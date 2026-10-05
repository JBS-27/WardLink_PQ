"""Gateway state for every enrolled tank: sessions, readings, alarms and the attack bench.

A new session stays pending until its first sealed reading opens; that reading
proves the board holds the enrolled keys. Every stored reading is answered with
a sealed receipt, and a reading already stored is recognised by its tank time
and ignored, so a board can resend safely after any outage. An authentic
capsule arriving on a session that a newer one replaced means two boards hold
the same keys, and raises a clone alarm.
"""

from __future__ import annotations

import bisect
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from wardlink.channel import (
    Session,
    chain_fingerprint,
    claimed_device_id,
    frame_sequence,
    gateway_accept,
    hello_mode,
    lean_accept,
    lean_derive,
    lean_hello,
    sensor_hello,
)
from wardlink.crypto import ChannelError, new_identity, new_static_keys, open_seal, ratchet_step
from wardlink.enroll import GatewayKeys, SensorKeys, SensorRecord, load_sensor, reenroll, set_status
from wardlink.record import RECEIPT, SEEN, Reading, decode_reading, encode_notice, encode_reading, json_bytes
from wardlink.rules import assess
from wardlink.store import Store
from wardlink.world import IST, TANK, World, speed_of_sound

MODE_LABEL = {"signed": "Signed (ML-DSA-65)", "lean": "Lean (KEM-authenticated)"}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def tank_clock(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, IST).strftime("%d %b %H:%M")


class SessionEnded(ChannelError):
    """The session may not carry readings any more; the connection should close."""


@dataclass
class Controls:
    """Demo switches the sensor thread reads between readings."""

    mode: str = "lean"
    rekey_every: int = 36
    rekey_requested: bool = False
    link_down: bool = False
    outbox: int = 0
    dropped: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def request_rekey(self, mode: str | None = None) -> None:
        with self.lock:
            if mode in ("signed", "lean"):
                self.mode = mode
            self.rekey_requested = True

    def take_rekey(self) -> bool:
        with self.lock:
            requested = self.rekey_requested
            self.rekey_requested = False
            return requested


@dataclass
class Delivery:
    """What the connection sends back for one capsule."""

    reading: dict | None
    receipt: bytes
    duplicate: bool = False


@dataclass
class Device:
    record: SensorRecord
    session: Session | None = None
    superseded: set[str] = field(default_factory=set)
    retired: set[str] = field(default_factory=set)
    latest: dict | None = None
    history: list[dict] = field(default_factory=list)
    trusted: list[Reading] = field(default_factory=list)
    previous: list[Reading] = field(default_factory=list)
    recent_frames: list[tuple[int, bytes]] = field(default_factory=list)
    pending_acks: list[int] = field(default_factory=list)
    handshake_times: deque = field(default_factory=lambda: deque(maxlen=64))
    connections: int = 0
    last_arrival: float = 0.0
    gaps: deque = field(default_factory=lambda: deque(maxlen=12))
    silent: bool = False
    silent_since: float = 0.0
    stored: int = 0
    buffered: int = 0
    backlog_run: int = 0
    duplicates: int = 0
    clone: dict | None = None
    stolen_keys: SensorKeys | None = None
    tamper_armed: bool = False
    refused_seq: int | None = None
    captured: dict | None = None

    @property
    def device_id(self) -> str:
        return self.record.device_id


class Office:
    def __init__(
        self,
        keys: GatewayKeys,
        roster: dict[str, SensorRecord],
        world: World | None = None,
        controls: Controls | None = None,
        store: Store | None = None,
        data_dir: Path | None = None,
        idle_timeout: float = 30.0,
        silent_after: float = 20.0,
        handshake_limit: int = 6,
        handshake_window: float = 60.0,
        body_timeout: float = 5.0,
    ):
        self.keys = keys
        self.devices = {device_id: Device(record) for device_id, record in roster.items()}
        self.primary = next(iter(self.devices))
        self.world = world
        self.controls = controls
        self.store = store or Store()
        self.data_dir = data_dir
        self.idle_timeout = idle_timeout
        self.silent_after = silent_after
        self.handshake_limit = handshake_limit
        self.handshake_window = handshake_window
        self.body_timeout = body_timeout
        self.lock = threading.RLock()
        self.last_hello: dict[str, int] = {}
        self.events: list[dict] = []
        self.handshakes: list[dict] = []
        self.attacks: dict[str, dict] = {}
        self.counters = {"accepted": 0, "refused": 0, "duplicates": 0, "buffered": 0, "internal": 0}
        self.bench: dict | None = None
        self.rigor: dict | None = None
        self.rigor_running = False
        self._restore()

    # Views used by the snapshot and tests --------------------------------------

    @property
    def roster(self) -> dict[str, SensorRecord]:
        return {device_id: device.record for device_id, device in self.devices.items()}

    @property
    def session(self) -> Session | None:
        return self.devices[self.primary].session

    @property
    def latest(self) -> dict | None:
        return self.devices[self.primary].latest

    @property
    def captured(self) -> dict | None:
        return self.devices[self.primary].captured

    def device(self, device_id: str | None = None) -> Device:
        return self.devices[device_id or self.primary]

    def _restore(self) -> None:
        for device in self.devices.values():
            rows = self.store.recent(device.device_id, 144)
            for reading, meta in rows:
                device.history.append(self._history_entry(reading, meta["seq"], meta["session_id"], meta["flag"], meta["plausible"]))
                if meta["plausible"]:
                    device.trusted.append(reading)
                device.previous.append(reading)
            device.trusted = device.trusted[-36:]
            device.previous = device.previous[-8:]
            device.stored = self.store.count(device.device_id)
            if rows:
                self._event(
                    "delivery",
                    f"Gateway started. Restored {len(rows)} readings for {device.device_id} from the database; "
                    "leak and physics checks keep their context.",
                )

    # Handshake -----------------------------------------------------------------

    def accept_hello(self, hello_wire: bytes, now_ms: int) -> tuple[bytes, Session]:
        mode = hello_mode(hello_wire)
        device_id = claimed_device_id(hello_wire)
        with self.lock:
            device = self.devices.get(device_id)
            if device is None:
                raise ChannelError(f"{device_id} is not on the ward roster")
            if device.record.status != "active":
                raise ChannelError(f"{device_id} is revoked; re-enroll it on site")
            if device.clone:
                raise ChannelError(f"clone alarm on {device_id}: two boards hold its keys; re-enroll it on site")
            now = time.monotonic()
            recent = [moment for moment in device.handshake_times if now - moment < self.handshake_window]
            if len(recent) >= self.handshake_limit:
                raise ChannelError(
                    f"too many handshakes for {device_id}: {len(recent)} in the last {self.handshake_window:.0f} s"
                )
            device.handshake_times.append(now)
            record = device.record
            started = time.perf_counter()
            if mode == "signed":
                welcome, session = gateway_accept(hello_wire, record.public_key, self.keys.identity, now_ms, self.last_hello)
            else:
                welcome, session = lean_accept(hello_wire, record.kem_public, record.x_public, self.keys.static)
            gateway_ms = (time.perf_counter() - started) * 1000
            self.handshakes.append(
                {
                    "session_id": session.session_id,
                    "device_id": device_id,
                    "mode": mode,
                    "hello_bytes": len(hello_wire),
                    "welcome_bytes": len(welcome),
                    "total_bytes": len(hello_wire) + len(welcome),
                    "gateway_ms": round(gateway_ms, 2),
                    "at": utc_now(),
                    "proven": False,
                }
            )
            self.handshakes = self.handshakes[-12:]
            self._event(
                "handshake",
                f"{MODE_LABEL[mode]} handshake from {device_id}: {len(hello_wire):,} bytes in, "
                f"{len(welcome):,} bytes out. The board still has to prove itself with its first sealed reading.",
            )
        return welcome, session

    def note_refusal(self, message: str) -> None:
        with self.lock:
            self.counters["refused"] += 1
            self._event("rejected", f"Refused: {message}. Nothing was shown.")

    def note_internal(self, message: str) -> None:
        with self.lock:
            self.counters["internal"] += 1
            self._event("rejected", f"Connection dropped after an unexpected error ({message}); the gateway kept running.")

    def note_idle(self, session: Session, seconds: float) -> None:
        with self.lock:
            self._event(
                "delivery",
                f"Closed a silent connection from {session.device_id} after {seconds:.0f} s without data "
                "(dead link or power cut). The board can reconnect at once.",
            )

    def connection_opened(self, device_id: str) -> None:
        with self.lock:
            self.devices[device_id].connections += 1

    def connection_closed(self, device_id: str) -> None:
        with self.lock:
            device = self.devices[device_id]
            device.connections = max(0, device.connections - 1)

    def session_live(self, session: Session) -> bool:
        with self.lock:
            device = self.devices.get(session.device_id)
            return (
                bool(device)
                and device.record.status == "active"
                and not device.clone
                and session.session_id not in device.superseded
                and session.session_id not in device.retired
            )

    # Readings ------------------------------------------------------------------

    def receive_reading(self, session: Session, frame: bytes) -> Delivery:
        with self.lock:
            device = self.devices[session.device_id]
            tampered = False
            if device.tamper_armed and session is device.session:
                device.tamper_armed = False
                damaged = bytearray(frame)
                damaged[len(damaged) // 2] ^= 0x01
                frame = bytes(damaged)
                tampered = True
            sequence = frame_sequence(frame)
            try:
                plaintext = session.open(frame)
                reading = decode_reading(plaintext)
            except ChannelError as exc:
                self.counters["refused"] += 1
                if tampered:
                    device.refused_seq = sequence
                    self._attack(
                        "tamper",
                        f"Capsule {sequence} had one bit flipped on the wire. Its Poly1305 tag no longer matched, "
                        "so the gateway refused it and showed no tank number.",
                    )
                self._event("rejected", f"Capsule {sequence} from {device.device_id} refused: {exc}.")
                raise
            if session.session_id in device.retired:
                raise SessionEnded("this session predates the board's re-enrollment")
            if session.session_id in device.superseded:
                self._clone_alarm(device, session)
                raise SessionEnded("an authentic capsule arrived on a replaced session; two boards hold these keys")
            if device.clone:
                raise SessionEnded(f"clone alarm on {device.device_id}; re-enroll it on site")
            if device.record.status != "active":
                raise SessionEnded(f"{device.device_id} is revoked")
            if session is not device.session:
                self._activate(device, session)
            receipt = session.seal(encode_notice(RECEIPT, reading.tank_time, sequence))
            self._arrived(device, reading.buffered)
            assessment = assess(reading, device.trusted, device.previous)
            plausible = assessment["physics"]["plausible"]
            stored = self.store.add_reading(
                device.device_id, reading, sequence, session.session_id, assessment["flag"], plausible, utc_now()
            )
            if not stored:
                device.duplicates += 1
                self.counters["duplicates"] += 1
                self._event(
                    "delivery",
                    f"The reading for tank time {tank_clock(reading.tank_time)} from {device.device_id} arrived again "
                    "after a lost receipt. It was already stored, so it was acknowledged again and ignored.",
                )
                return Delivery(None, receipt, duplicate=True)

            device.stored += 1
            self.counters["accepted"] += 1
            if plausible:
                device.trusted.append(reading)
                device.trusted = device.trusted[-36:]
            device.previous.append(reading)
            device.previous = device.previous[-8:]
            if reading.buffered:
                device.buffered += 1
                device.backlog_run += 1
                self.counters["buffered"] += 1
            elif device.backlog_run:
                self._event(
                    "delivery",
                    f"{device.backlog_run} readings buffered on {device.device_id} during the outage were delivered "
                    "in order with their original tank times. Nothing was lost.",
                )
                device.backlog_run = 0
            if device.refused_seq is not None and sequence > device.refused_seq:
                self._event(
                    "reading",
                    f"Capsule {sequence} opened normally. The ratchet stepped past the key of refused capsule "
                    f"{device.refused_seq}.",
                )
                device.refused_seq = None
            device.recent_frames.append((sequence, frame))
            device.recent_frames = device.recent_frames[-12:]
            self._thief_check(device, session, sequence, frame)

            entry = self._history_entry(reading, sequence, session.session_id, assessment["flag"], plausible)
            times = [item["tank_time"] for item in device.history]
            device.history.insert(bisect.bisect(times, reading.tank_time), entry)
            device.history = device.history[-144:]

            latest = self._latest_entry(device, session, reading, sequence, frame, assessment)
            if device.latest is None or reading.tank_time >= device.latest["tank_time"]:
                device.latest = latest
            if not reading.buffered or assessment["severity"] >= 2:
                prefix = "Buffered reading" if reading.buffered else "Reading"
                self._event(
                    "reading",
                    f"{prefix} {sequence} verified: tank {reading.level_pct:.0f}%, turbidity "
                    f"{reading.turbidity_ntu:.1f} NTU, pH {reading.ph:.2f}. {assessment['title']}.",
                )
            return Delivery(latest, receipt)

    def _latest_entry(self, device: Device, session: Session, reading: Reading, sequence: int, frame: bytes, assessment: dict) -> dict:
        sound = speed_of_sound(reading.air_c)
        return {
            "seq": sequence,
            "session_id": session.session_id,
            "mode": session.mode,
            "device_id": device.device_id,
            "label": device.record.label,
            "level_pct": reading.level_pct,
            "distance_m": reading.distance_m,
            "echo_ms": round(2 * reading.distance_m / sound * 1000, 2),
            "sound_mps": round(sound, 1),
            "uncompensated_pct": round(TANK.level_for(reading.distance_m * 343.0 / sound), 1),
            "turbidity_ntu": reading.turbidity_ntu,
            "tds_mgl": reading.tds_mgl,
            "ph": reading.ph,
            "water_c": reading.water_c,
            "air_c": reading.air_c,
            "tank_time": reading.tank_time,
            "tank_clock": tank_clock(reading.tank_time),
            "buffered": reading.buffered,
            "received_at": utc_now(),
            "seen_at": None,
            "capsule_bytes": len(frame),
            "json_bytes": json_bytes(reading) + 20,
            "capsule_hex": frame.hex(),
            "assessment": assessment,
        }

    @staticmethod
    def _history_entry(reading: Reading, sequence: int, session_id: str, flag: str, plausible: bool) -> dict:
        return {
            "seq": sequence,
            "session_id": session_id,
            "tank_time": reading.tank_time,
            "level_pct": reading.level_pct,
            "turbidity_ntu": reading.turbidity_ntu,
            "flag": flag,
            "plausible": plausible,
            "buffered": reading.buffered,
        }

    def _arrived(self, device: Device, buffered: bool) -> None:
        now = time.monotonic()
        if device.last_arrival and not buffered:
            device.gaps.append(now - device.last_arrival)
        if device.silent:
            device.silent = False
            self._event(
                "delivery",
                f"{device.device_id} is reporting again after {now - device.silent_since:.0f} s of silence.",
            )
        device.last_arrival = now

    def _activate(self, device: Device, session: Session) -> None:
        previous = device.session
        if previous is not None and previous.session_id != session.session_id:
            device.superseded.add(previous.session_id)
            if len(device.superseded) > 48:
                device.superseded = set(list(device.superseded)[-32:])
        device.session = session
        device.pending_acks.clear()
        device.recent_frames.clear()
        device.refused_seq = None
        for handshake in self.handshakes:
            if handshake["session_id"] == session.session_id:
                handshake["proven"] = True
        retired = f" Session {previous.session_id} retired." if previous else ""
        self._event(
            "handshake",
            f"{device.device_id} proven by its first sealed reading. Session {session.session_id} "
            f"({MODE_LABEL[session.mode]}) is live.{retired}",
        )
        captured = device.captured
        if captured and not captured["healed"] and captured["session_id"] != session.session_id:
            captured["healed"] = True
            self._attack(
                "capture",
                f"Re-keyed with a fresh ML-KEM handshake. The chain stolen after reading {captured['seq']} "
                "belongs to the old session and opens nothing from now on.",
            )

    def _clone_alarm(self, device: Device, session: Session) -> None:
        if device.clone:
            return
        live = device.session.session_id if device.session else None
        suspect = self.store.mark_suspect(device.device_id, live) if live else 0
        if live:
            for entry in device.history:
                if entry["session_id"] == live:
                    entry["flag"] = "SUSPECT"
            if device.latest and device.latest["session_id"] == live:
                device.latest["suspect"] = True
        device.clone = {"at": utc_now(), "replaced": session.session_id, "live": live, "suspect": suspect}
        if device.session is not None:
            device.superseded.add(device.session.session_id)
        device.session = None
        self._event(
            "rejected",
            f"Clone alarm: an authentic capsule arrived on {device.device_id}'s replaced session {session.session_id} "
            f"while session {live} was live. Two boards hold the same keys, so the office stops trusting "
            f"{device.device_id} until it is re-enrolled on site. {suspect} reading(s) received on the overlapping "
            "session are marked suspect in the database.",
        )
        self._attack(
            "clone",
            f"Clone alarm raised. Both boards proved the genuine keys, so cryptography alone could not tell them apart; "
            f"the overlap gave them away. {device.device_id} is quarantined until it is re-enrolled on site.",
        )

    # Silence watchdog ------------------------------------------------------------

    def check_silence(self) -> None:
        with self.lock:
            now = time.monotonic()
            for device in self.devices.values():
                if not device.last_arrival or device.silent:
                    continue
                expected = statistics.median(device.gaps) if len(device.gaps) >= 3 else None
                limit = max(self.silent_after, 3 * expected) if expected else self.silent_after
                quiet = now - device.last_arrival
                if quiet > limit:
                    device.silent = True
                    device.silent_since = device.last_arrival
                    cadence = f"; it normally reports every {expected:.1f} s" if expected else ""
                    self._event(
                        "rejected",
                        f"No reading from {device.device_id} for {quiet:.0f} s{cadence}. Check power and radio; "
                        "readings taken meanwhile stay buffered on the board.",
                    )

    # Acks ----------------------------------------------------------------------

    def request_ack(self, device_id: str | None = None) -> int | None:
        with self.lock:
            device = self.device(device_id)
            if device.latest is None:
                return None
            sequence = int(device.latest["seq"])
            if sequence not in device.pending_acks:
                device.pending_acks.append(sequence)
            return sequence

    def next_note_frame(self, session: Session) -> bytes | None:
        with self.lock:
            device = self.devices[session.device_id]
            if not device.pending_acks or session is not device.session:
                return None
            sequence = device.pending_acks.pop(0)
            frame = session.seal(encode_notice(SEEN, sequence, int(time.time())))
            if device.latest and device.latest["seq"] == sequence:
                device.latest["seen_at"] = utc_now()
            self._event(
                "ack",
                f"Engineer marked reading {sequence} seen. A {len(frame)}-byte sealed note went back to the board.",
            )
            return frame

    # Attack bench --------------------------------------------------------------

    def arm_tamper(self) -> dict:
        with self.lock:
            device = self.device()
            if device.session is None:
                raise ChannelError("no live session yet")
            device.tamper_armed = True
            return self._attack("tamper", "Armed. The next capsule from the board will have one bit flipped on the wire.", done=False)

    def replay_last(self) -> dict:
        with self.lock:
            device = self.device()
            if device.session is None or not device.recent_frames:
                raise ChannelError("no reading has arrived yet")
            sequence, frame = device.recent_frames[-1]
            try:
                device.session.try_open(frame)
            except ChannelError as exc:
                self.counters["refused"] += 1
                self._event("rejected", f"Copy of capsule {sequence} refused: {exc}.")
                return self._attack(
                    "replay",
                    f"A recorded copy of capsule {sequence} was sent again. Its key was used once and "
                    "thrown away, so the copy was refused and the office saw nothing new.",
                )
            raise ChannelError("the replayed capsule opened; the ratchet is broken")

    def impostor(self) -> dict:
        device = self.device()
        record = device.record
        mode = self.controls.mode if self.controls else "lean"
        fake = Reading(97.0, 0.40, 0.4, 280, 7.3, 27.0, 30.0, int(time.time()))
        with self.lock:
            if mode == "lean":
                rogue = new_static_keys()
                offer = lean_hello(rogue, record.device_id, self.keys.static.kem_public, self.keys.static.x_public)
                welcome, gateway_side = lean_accept(offer.wire, record.kem_public, record.x_public, self.keys.static)
                rogue_side, gateway_proven = lean_derive(offer, welcome)
                forged = rogue_side.seal(encode_reading(fake))
                try:
                    gateway_side.open(forged)
                except ChannelError:
                    self.counters["refused"] += 1
                    self._event("rejected", f"Impostor claiming {record.device_id}: first capsule refused. Live session untouched.")
                    note = "" if not gateway_proven else " (the confirm tag unexpectedly matched)"
                    return self._attack(
                        "impostor",
                        f"A board with its own keys claimed to be {record.device_id}. The gateway answered, because it "
                        "cannot tell yet, but the board could not open the capsule sealed to the enrolled sensor. "
                        f"Its forged reading “tank 97%, water clean” was refused and the live session was untouched{note}.",
                    )
                raise ChannelError("the impostor's capsule opened")
            offer = sensor_hello(new_identity(), record.device_id, time.time_ns() // 1_000_000)
            offer.discard()
            try:
                gateway_accept(offer.wire, record.public_key, self.keys.identity, time.time_ns() // 1_000_000, {})
            except ChannelError as exc:
                self.counters["refused"] += 1
                self._event("rejected", f"Impostor claiming {record.device_id}: {exc}.")
                return self._attack(
                    "impostor",
                    f"A board signed a hello as {record.device_id} with its own ML-DSA-65 key. The signature did not "
                    "match the enrolled public key, so the gateway never answered.",
                )
            raise ChannelError("the impostor's signature was accepted")

    def unknown_board(self) -> dict:
        offer = lean_hello(new_static_keys(), "tank-77", self.keys.static.kem_public, self.keys.static.x_public)
        offer.discard()
        try:
            self.accept_hello(offer.wire, time.time_ns() // 1_000_000)
        except ChannelError as exc:
            self.note_refusal(str(exc))
            return self._attack(
                "unknown",
                "A board calling itself tank-77 is not on the ward roster. It was refused before any key work.",
            )
        raise ChannelError("an unlisted board was accepted")

    def capture_board(self) -> dict:
        with self.lock:
            device = self.device()
            if device.session is None:
                raise ChannelError("no live session to steal from")
            session = device.session
            stolen = session.recv_chain
            sequence = session.recv_seq
            recorded = [(seq, frame) for seq, frame in device.recent_frames if seq <= sequence]
            opened = sum(1 for seq, frame in recorded if self._thief_opens(stolen, sequence, seq, frame, session))
            device.captured = {
                "session_id": session.session_id,
                "chain": stolen,
                "seq": sequence,
                "tried": [seq for seq, _frame in recorded],
                "opened_past": opened,
                "exposed": [],
                "healed": False,
            }
            if self.data_dir is not None:
                device.stolen_keys = load_sensor(self.data_dir, device.device_id)
            self._event(
                "rejected",
                f"Board stolen after reading {sequence}. Thief tried {len(recorded)} recorded capsules and opened {opened}.",
            )
            keys_note = " Its enrolled keys were in flash too, so re-enroll it on site." if device.stolen_keys else ""
            return self._attack(
                "capture",
                f"The board was stolen after reading {sequence} and its memory dumped. The thief tried the "
                f"{len(recorded)} capsules recorded earlier and opened {opened}: the key chain only turns forward. "
                f"Readings sent after the theft stay readable to the thief until the next re-key.{keys_note}",
            )

    def clone_board(self) -> dict:
        if self.data_dir is None:
            raise ChannelError("the clone demo needs the enrolled key files: python -m wardlink demo")
        device = self.device()
        with self.lock:
            if device.clone:
                raise ChannelError("the clone alarm is already raised; re-enroll the board")
            if device.session is None or device.latest is None:
                raise ChannelError("no live session yet")
            last = dict(device.latest)
        stolen = device.stolen_keys or load_sensor(self.data_dir, device.device_id)
        offer = lean_hello(stolen.static, stolen.device_id, stolen.gateway_kem_public, stolen.gateway_x_public)
        welcome, gateway_side = self.accept_hello(offer.wire, time.time_ns() // 1_000_000)
        clone_side = offer.finish(welcome)
        level = min(96.0, last["level_pct"] + 0.4)
        fake = Reading(level, TANK.distance_for(level), 0.4, 280, 7.3, last["water_c"], last["air_c"], last["tank_time"] + 300)
        self.receive_reading(gateway_side, clone_side.seal(encode_reading(fake)))
        return self._attack(
            "clone",
            f"A second board built from {device.device_id}'s dumped keys connected and proved itself; the gateway "
            "accepted its reading because the keys are genuine. Watch for the clone alarm when the real board sends "
            "its next capsule.",
            done=False,
        )

    def revoke(self) -> dict:
        with self.lock:
            device = self.device()
            device.record = replace(device.record, status="revoked")
            if self.data_dir is not None:
                set_status(self.data_dir, device.device_id, "revoked")
            self._event(
                "world",
                f"{device.device_id} revoked at the office. Its handshakes and capsules are refused until it is "
                "re-enrolled on site; the board keeps buffering readings meanwhile.",
            )
            return self._attack("revoke", f"{device.device_id} is revoked. Every handshake from it is refused.")

    def reenroll_device(self) -> dict:
        if self.data_dir is None:
            raise ChannelError("re-enrollment needs the key files: python -m wardlink demo")
        with self.lock:
            device = self.device()
            record = reenroll(self.data_dir, device.device_id)
            device.record = record
            device.retired |= device.superseded
            if device.session is not None:
                device.retired.add(device.session.session_id)
            device.superseded.clear()
            device.session = None
            device.clone = None
            device.stolen_keys = None
            device.handshake_times.clear()
            self._event(
                "world",
                f"{device.device_id} re-enrolled on site with new keys. Keys copied from the old board no longer work.",
            )
            return self._attack(
                "reenroll",
                f"{device.device_id} has new keys. The real board picks them up on its next connection; a clone holding "
                "the old keys is refused at its first capsule.",
            )

    def set_link(self, down: bool) -> str:
        if self.controls is None:
            raise ChannelError("the link switch works only in demo mode: python -m wardlink demo")
        self.controls.link_down = down
        text = (
            "Radio link cut. The board keeps measuring and buffers every reading until the link returns."
            if down
            else "Radio link restored. The board reconnects and sends its buffer in order."
        )
        with self.lock:
            self._event("world", text)
        return text

    def _thief_opens(self, chain: bytes, chain_seq: int, target_seq: int, frame: bytes, session: Session) -> bool:
        aad = session.device_id.encode() + frame[:4]
        if target_seq <= chain_seq:
            cursor = chain
            for _ in range(8):
                key, cursor = ratchet_step(cursor)
                try:
                    open_seal(key, target_seq, session.recv_direction, frame[4:], aad)
                    return True
                except ChannelError:
                    continue
            return False
        cursor = chain
        for _ in range(target_seq - chain_seq):
            key, cursor = ratchet_step(cursor)
        try:
            open_seal(key, target_seq, session.recv_direction, frame[4:], aad)
            return True
        except ChannelError:
            return False

    def _thief_check(self, device: Device, session: Session, sequence: int, frame: bytes) -> None:
        captured = device.captured
        if not captured or captured["healed"] or captured["session_id"] != session.session_id:
            return
        if self._thief_opens(captured["chain"], captured["seq"], sequence, frame, session):
            captured["exposed"].append(sequence)
            captured["exposed"] = captured["exposed"][-12:]
            self._event("rejected", f"The thief also reads capsule {sequence} with the stolen chain. Re-key to stop it.")

    def world_event(self, name: str) -> str:
        if self.world is None:
            raise ChannelError("tank controls work only in demo mode: python -m wardlink demo")
        text = self.world.set_event(name)
        with self.lock:
            self._event("world", f"In the tank: {text}")
        return text

    def request_rekey(self, mode: str | None) -> str:
        if self.controls is None:
            raise ChannelError("re-key control works only in demo mode: python -m wardlink demo")
        self.controls.request_rekey(mode)
        label = MODE_LABEL.get(self.controls.mode, self.controls.mode)
        with self.lock:
            self._event("world", f"Re-key requested. The board will open a new {label} session once its buffer is acknowledged.")
        return label

    # Snapshot ------------------------------------------------------------------

    def snapshot(self) -> dict:
        self.check_silence()
        with self.lock:
            device = self.device()
            session = device.session
            now = time.monotonic()
            body = {
                "connected": device.connections > 0,
                "waiting": device.latest is None,
                "demo": self.world is not None,
                "device": {"id": device.device_id, "label": device.record.label, "status": device.record.status},
                "reading": dict(device.latest) if device.latest else None,
                "history": list(device.history),
                "session": None,
                "handshakes": list(reversed(self.handshakes)),
                "events": list(reversed(self.events[-50:])),
                "attacks": dict(self.attacks),
                "world": self.world.events() if self.world else None,
                "controls": None,
                "captured": None,
                "counters": dict(self.counters),
                "tamper_armed": device.tamper_armed,
                "delivery": {
                    "stored": device.stored,
                    "buffered": device.buffered,
                    "duplicates": device.duplicates,
                    "silent": device.silent,
                    "quiet_s": round(now - device.last_arrival, 1) if device.last_arrival else None,
                },
                "clone": device.clone,
                "devices": [
                    {
                        "id": item.device_id,
                        "label": item.record.label,
                        "status": item.record.status,
                        "stored": item.stored,
                        "silent": item.silent,
                        "clone": bool(item.clone),
                        "mode": item.session.mode if item.session else None,
                    }
                    for item in self.devices.values()
                ],
                "rigor": None,
                "rigor_running": self.rigor_running,
            }
            if self.controls is not None:
                body["controls"] = {
                    "mode": self.controls.mode,
                    "rekey_every": self.controls.rekey_every,
                    "link_down": self.controls.link_down,
                    "outbox": self.controls.outbox,
                    "dropped": self.controls.dropped,
                }
            if session is not None:
                body["session"] = {
                    "session_id": session.session_id,
                    "mode": session.mode,
                    "mode_label": MODE_LABEL[session.mode],
                    "recv_seq": session.recv_seq,
                    "chain_fp": chain_fingerprint(session),
                }
            if device.captured:
                body["captured"] = {key: value for key, value in device.captured.items() if key != "chain"}
            if self.rigor:
                body["rigor"] = {key: self.rigor[key] for key in ("passed", "total", "finished_at", "seconds")}
            return body

    def _attack(self, name: str, text: str, done: bool = True) -> dict:
        self.attacks[name] = {"at": utc_now(), "text": text, "done": done}
        return self.attacks[name]

    def _event(self, kind: str, text: str) -> None:
        at = utc_now()
        self.events.append({"at": at, "kind": kind, "text": text})
        self.events = self.events[-120:]
        self.store.add_event(at, kind, text)

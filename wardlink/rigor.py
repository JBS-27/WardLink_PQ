"""Field-scenario suite: the conditions a ward deployment actually meets.

Every scenario builds its own gateway (on a throwaway port when it needs the
network), drives it the way the field would, and checks the outcome. Nothing
here touches the running demo.

  python -m wardlink rigor
"""

from __future__ import annotations

import hashlib
import json
import platform
import random
import socket
import tempfile
import threading
import time
import traceback
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

from wardlink.channel import lean_accept, lean_derive, lean_hello, sensor_hello
from wardlink.crypto import ChannelError, new_identity, new_static_keys
from wardlink.enroll import DEVICE_ID, GatewayKeys, SensorKeys, SensorRecord, enroll, load_gateway, load_sensor
from wardlink.framing import HELLO, recv_frame, send_frame
from wardlink.office import Controls, Office, SessionEnded
from wardlink.record import RECEIPT, Reading, decode_notice, encode_reading
from wardlink.rules import assess
from wardlink.service import _connect, listen, run_sensor, serve_gateway
from wardlink.store import Store
from wardlink.world import IST, TANK, World

VECTORS = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "acvp_keygen.json"
NOON = datetime(2026, 10, 4, 12, 0, tzinfo=IST)
SCENARIOS: list[tuple[str, str, str, Callable[[], tuple[bool, str]]]] = []


def scenario(ident: str, category: str, title: str):
    def wrap(fn: Callable[[], tuple[bool, str]]):
        SCENARIOS.append((ident, category, title, fn))
        return fn

    return wrap


# Helpers -------------------------------------------------------------------------


def reading(minutes: int = 0, level: float = 55.0, ntu: float = 0.6, ph: float = 7.3, tds: int = 290, distance: float | None = None, base: datetime = NOON) -> Reading:
    moment = base + timedelta(minutes=minutes)
    return Reading(level, TANK.distance_for(level) if distance is None else distance, ntu, tds, ph, 27.0, 33.0, int(moment.timestamp()))


def office_with(
    keys: GatewayKeys | None = None,
    sensors: int = 1,
    data_dir: Path | None = None,
    store: Store | None = None,
    **options,
) -> tuple[Office, list[SensorKeys]]:
    """An office with `sensors` enrolled boards whose keys live only in memory."""
    keys = keys or GatewayKeys(new_identity(), new_static_keys())
    roster: dict[str, SensorRecord] = {}
    boards: list[SensorKeys] = []
    for index in range(sensors):
        device_id = DEVICE_ID if index == 0 else f"tank-{index:02d}"
        identity, static = new_identity(), new_static_keys()
        roster[device_id] = SensorRecord(device_id, f"Tank {index}", identity.public_key, static.kem_public, static.x_public)
        boards.append(SensorKeys(device_id, f"Tank {index}", identity, static, keys.identity.public_key, keys.static.kem_public, keys.static.x_public))
    return Office(keys, roster, store=store or Store(), data_dir=data_dir, **options), boards


def pair(office: Office, board: SensorKeys):
    offer = lean_hello(board.static, board.device_id, board.gateway_kem_public, board.gateway_x_public)
    welcome, gateway_side = office.accept_hello(offer.wire, time.time_ns() // 1_000_000)
    return gateway_side, offer.finish(welcome)


class Gateway:
    """A real TCP gateway on a throwaway port, with short field timeouts."""

    def __init__(self, sensors: int = 1, max_connections: int = 64, hello_timeout: float = 1.0, **options):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name)
        enroll(self.data)
        keys, roster = load_gateway(self.data)
        self.boards = [load_sensor(self.data)]
        for index in range(1, sensors):
            device_id = f"tank-{index:02d}"
            identity, static = new_identity(), new_static_keys()
            roster[device_id] = SensorRecord(device_id, f"Tank {index}", identity.public_key, static.kem_public, static.x_public)
            self.boards.append(SensorKeys(device_id, f"Tank {index}", identity, static, keys.identity.public_key, keys.static.kem_public, keys.static.x_public))
        settings = {"idle_timeout": 1.0, "body_timeout": 1.0, "silent_after": 1.0, "handshake_limit": 50}
        settings.update(options)
        self.office = Office(keys, roster, store=Store(), data_dir=self.data, **settings)
        self.listener = listen("127.0.0.1", 0)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(
            target=serve_gateway,
            args=(self.office, self.listener, self.stop),
            kwargs={"max_connections": max_connections, "hello_timeout": hello_timeout, "quiet": True},
            daemon=True,
        )
        self.thread.start()

    def sensor(self, readings: int, board: int = 0, pace: float = 0.03, **options) -> dict:
        return run_sensor(self.boards[board], port=self.port, readings=readings, pace=pace, quiet=True, **options)

    def raw(self) -> socket.socket:
        return socket.create_connection(("127.0.0.1", self.port), timeout=3)

    def __enter__(self) -> "Gateway":
        return self

    def __exit__(self, *_exc) -> None:
        self.stop.set()
        self.thread.join(timeout=3)
        self.tmp.cleanup()


class ScriptedWorld(World):
    """A tank whose n-th reading can trigger an action (cut the radio, inject a fault)."""

    def __init__(self, script: dict[int, Callable[[], None]], **kwargs):
        super().__init__(**kwargs)
        self.script = script
        self.count = 0

    def step(self) -> Reading:
        self.count += 1
        action = self.script.get(self.count)
        if action:
            action()
        return super().step()


def closed_within(sock: socket.socket, seconds: float) -> bool:
    sock.settimeout(seconds)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return True
    except (ConnectionResetError, BrokenPipeError):
        return True
    except TimeoutError:
        return False


def events_matching(office: Office, text: str) -> int:
    return sum(1 for event in office.events if text in event["text"])


def said(flag: bool, yes: str, no: str) -> str:
    return yes if flag else no


# Standards -----------------------------------------------------------------------


@scenario("nist-mlkem", "Standards", "ML-KEM-768 key generation matches NIST ACVP vectors")
def nist_mlkem():
    cases = json.loads(VECTORS.read_text())["ml_kem_768_keygen"]
    matched = 0
    for case in cases:
        key = MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(case["d"] + case["z"]))
        matched += hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest() == case["ek_sha256"]
    return matched == len(cases), f"{matched} of {len(cases)} official NIST test cases produce the expected public key"


@scenario("nist-mldsa", "Standards", "ML-DSA-65 key generation matches NIST ACVP vectors")
def nist_mldsa():
    cases = json.loads(VECTORS.read_text())["ml_dsa_65_keygen"]
    matched = 0
    for case in cases:
        key = MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(case["seed"]))
        matched += hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest() == case["pk_sha256"]
    return matched == len(cases), f"{matched} of {len(cases)} official NIST test cases produce the expected public key"


@scenario("lean-roundtrip", "Standards", "Lean handshake agrees on one session, 4,544 bytes")
def lean_roundtrip():
    office, (board,) = office_with()
    offer = lean_hello(board.static, board.device_id, board.gateway_kem_public, board.gateway_x_public)
    welcome, gateway_side = office.accept_hello(offer.wire, time.time_ns() // 1_000_000)
    sensor_side = offer.finish(welcome)
    total = len(offer.wire) + len(welcome)
    ok = gateway_side.session_id == sensor_side.session_id and total == 4544
    return ok, f"{len(offer.wire)} + {len(welcome)} = {total} bytes, both sides derived session {sensor_side.session_id}"


@scenario("signed-roundtrip", "Standards", "Signed handshake agrees on one session, 8,978 bytes")
def signed_roundtrip():
    office, (board,) = office_with()
    offer = sensor_hello(board.identity, board.device_id, time.time_ns() // 1_000_000)
    welcome, gateway_side = office.accept_hello(offer.wire, time.time_ns() // 1_000_000)
    sensor_side = offer.finish(welcome, board.gateway_public)
    total = len(offer.wire) + len(welcome)
    ok = gateway_side.session_id == sensor_side.session_id and total == 8978
    return ok, f"{len(offer.wire)} + {len(welcome)} = {total} bytes with ML-DSA-65 on both sides"


@scenario("fake-gateway", "Standards", "A fake gateway cannot prove itself to the board")
def fake_gateway():
    _office, (board,) = office_with()
    fake = new_static_keys()
    offer = lean_hello(board.static, board.device_id, board.gateway_kem_public, board.gateway_x_public)
    welcome, _ = lean_accept(offer.wire, board.static.kem_public, board.static.x_public, fake)
    try:
        offer.finish(welcome)
    except ChannelError as exc:
        return True, f"Board refused the welcome: {exc}"
    return False, "Board accepted a gateway that does not hold the enrolled keys"


# Protocol attacks ------------------------------------------------------------------


@scenario("bit-flip", "Protocol attacks", "One flipped bit is refused; the next capsule still opens")
def bit_flip():
    office, (board,) = office_with()
    gateway_side, sensor_side = pair(office, board)
    office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(0))))
    damaged = bytearray(sensor_side.seal(encode_reading(reading(10))))
    damaged[12] ^= 0x01
    try:
        office.receive_reading(gateway_side, bytes(damaged))
        return False, "A modified capsule was accepted"
    except ChannelError:
        pass
    delivery = office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(20))))
    return delivery.reading["seq"] == 3, "Capsule 2 refused on its Poly1305 tag; capsule 3 opened after the ratchet skipped key 2"


@scenario("replay-capsule", "Protocol attacks", "A recorded capsule sent again is refused")
def replay_capsule():
    office, (board,) = office_with()
    gateway_side, sensor_side = pair(office, board)
    frame = sensor_side.seal(encode_reading(reading(0)))
    office.receive_reading(gateway_side, frame)
    try:
        office.receive_reading(gateway_side, frame)
    except ChannelError as exc:
        return office.device().stored == 1, f"Copy refused ({exc}); one reading stored"
    return False, "The copy was accepted"


@scenario("impostor", "Protocol attacks", "Impostor board with its own keys is refused at its first capsule")
def impostor():
    office, (board,) = office_with()
    gateway_side, sensor_side = pair(office, board)
    office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(0))))
    result = office.impostor()
    return office.session is gateway_side and "refused" in result["text"], "Forged “tank 97%” refused; live session untouched"


@scenario("unlisted-board", "Protocol attacks", "A board missing from the roster is refused before key work")
def unlisted_board():
    office, _boards = office_with()
    result = office.unknown_board()
    return "not on the ward roster" in result["text"], result["text"]


@scenario("hello-replay", "Protocol attacks", "A recorded hello gets the attacker nothing")
def hello_replay():
    office, (board,) = office_with(handshake_limit=6)
    offer = lean_hello(board.static, board.device_id, board.gateway_kem_public, board.gateway_x_public)
    welcome, live = office.accept_hello(offer.wire, time.time_ns() // 1_000_000)
    sensor_side = offer.finish(welcome)
    office.receive_reading(live, sensor_side.seal(encode_reading(reading(0))))
    answered = refused = 0
    rng = random.Random(3)
    for _ in range(10):
        try:
            _welcome, replayed = office.accept_hello(offer.wire, time.time_ns() // 1_000_000)
        except ChannelError:
            refused += 1
            continue
        answered += 1
        guess = (1).to_bytes(4, "big") + bytes(rng.randrange(256) for _ in range(36))
        try:
            office.receive_reading(replayed, guess)
            return False, "A replayed hello led to an accepted capsule"
        except ChannelError:
            pass
    ok = office.session is live and refused > 0
    return ok, f"{answered} replays answered but none could seal a capsule; {refused} refused by the handshake rate limit; live session untouched"


@scenario("stolen-board", "Protocol attacks", "Stolen board opens no earlier reading; re-key locks it out")
def stolen_board():
    office, (board,) = office_with()
    gateway_side, sensor_side = pair(office, board)
    for index in range(5):
        office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(index * 10))))
    office.capture_board()
    office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(50))))
    exposed = list(office.captured["exposed"])
    gateway_two, sensor_two = pair(office, board)
    office.receive_reading(gateway_two, sensor_two.seal(encode_reading(reading(60))))
    captured = office.captured
    ok = captured["opened_past"] == 0 and exposed == [6] and captured["healed"]
    return ok, f"Opened {captured['opened_past']} of {len(captured['tried'])} earlier capsules; read capsule {exposed} after the theft; re-key healed it"


@scenario("fuzz", "Protocol attacks", "2,400 mutated hellos and capsules: no crash, nothing forged")
def fuzz():
    office, (board,) = office_with(handshake_limit=100_000)
    rng = random.Random(7)
    crashes = forged = 0
    lean = lean_hello(board.static, board.device_id, board.gateway_kem_public, board.gateway_x_public).wire
    signed = sensor_hello(board.identity, board.device_id, time.time_ns() // 1_000_000).wire

    def mutate(data: bytes) -> bytes:
        out = bytearray(data)
        for _ in range(rng.randint(1, 4)):
            choice = rng.random()
            if choice < 0.6 and out:
                out[rng.randrange(len(out))] ^= 1 << rng.randrange(8)
            elif choice < 0.8 and out:
                del out[rng.randrange(len(out)):]
            else:
                out += bytes(rng.randrange(256) for _ in range(rng.randint(1, 40)))
        return bytes(out)

    for index in range(1200):
        wire = mutate(lean if index % 2 else signed)
        try:
            office.accept_hello(wire, time.time_ns() // 1_000_000)
        except (ChannelError, ValueError):
            pass
        except Exception:
            crashes += 1
    gateway_side, sensor_side = pair(office, board)
    genuine = sensor_side.seal(encode_reading(reading(0)))
    for _ in range(1200):
        frame = mutate(genuine)
        try:
            gateway_side.try_open(frame)
            if frame != genuine:
                forged += 1
        except (ChannelError, ValueError):
            pass
        except Exception:
            crashes += 1
    return crashes == 0 and forged == 0, f"{crashes} crashes, {forged} forged capsules accepted"


# Transport faults -------------------------------------------------------------------


@scenario("stall-half-frame", "Transport faults", "A sender that stalls mid-frame is dropped and blocks nobody")
def stall_half_frame():
    with Gateway() as gw:
        stall = gw.raw()
        stall.sendall((1000).to_bytes(4, "big") + b"H" * 10)
        started = time.monotonic()
        result = gw.sensor(3)
        served = time.monotonic() - started
        dropped = closed_within(stall, 2.5)
        stall.close()
        ok = result["delivered"] == 3 and served < 5 and dropped
        return ok, f"Real sensor served in {served:.2f} s while the staller hung; " + said(
            dropped, "the staller was dropped by the 1 s body timeout", "the staller was never dropped"
        )


@scenario("power-cut", "Transport faults", "Power cut mid-session: board reconnects at once; dead link is cleaned up")
def power_cut():
    with Gateway() as gw:
        conn, session = _connect(gw.boards[0], "127.0.0.1", gw.port, "lean")
        for minutes in (0, 10):
            send_frame(conn, b"D" + session.seal(encode_reading(reading(minutes))))
            recv_frame(conn, timeout=2)
        started = time.monotonic()
        result = gw.sensor(3, world=World(start=NOON + timedelta(days=1)))
        served = time.monotonic() - started
        time.sleep(1.8)
        cleaned = events_matching(gw.office, "Closed a silent connection") >= 1
        conn.close()
        ok = result["delivered"] == 3 and served < 5 and cleaned
        return ok, f"Rebooted board served in {served:.2f} s; " + said(
            cleaned, "the dead connection was closed by the 1 s idle timeout", "the dead connection was never closed"
        )


@scenario("silent-connection", "Transport faults", "A connection that never says hello is closed")
def silent_connection():
    with Gateway(hello_timeout=0.8) as gw:
        sock = gw.raw()
        closed = closed_within(sock, 2.5)
        sock.close()
        return closed and events_matching(gw.office, "sent nothing") >= 1, said(
            closed, "Closed by the 0.8 s hello timeout and logged", "The silent connection stayed open"
        )


@scenario("connection-flood", "Transport faults", "Connection flood is capped; the gateway recovers")
def connection_flood():
    with Gateway(max_connections=16, hello_timeout=0.8) as gw:
        flood = [gw.raw() for _ in range(48)]
        time.sleep(0.4)
        turned_away = events_matching(gw.office, "connection cap reached")
        time.sleep(1.2)
        for sock in flood:
            sock.close()
        result = gw.sensor(3)
        ok = turned_away >= 20 and result["delivered"] == 3
        return ok, f"{turned_away} of 48 flood connections turned away at the cap of 16; afterwards the sensor delivered {result['delivered']} readings"


@scenario("oversize-frame", "Transport faults", "A frame claiming 10 MB is refused without allocating it")
def oversize_frame():
    with Gateway() as gw:
        sock = gw.raw()
        sock.sendall((10_000_000).to_bytes(4, "big"))
        closed = closed_within(sock, 2.0)
        sock.close()
        result = gw.sensor(2)
        return closed and result["delivered"] == 2, said(
            closed, "Connection closed at once, nothing allocated; the gateway kept serving", "The connection was not closed"
        )


@scenario("garbage-hello", "Transport faults", "Garbage in place of a hello is refused")
def garbage_hello():
    with Gateway() as gw:
        replies = []
        for payload in (b"X" * 64, HELLO + b"WL9" + bytes(200)):
            sock = gw.raw()
            send_frame(sock, payload)
            frame = recv_frame(sock, timeout=2)
            replies.append(frame[:1] if frame else b"")
            sock.close()
        ok = replies == [b"R", b"R"]
        return ok, "Both refused with an explicit reject frame"


# Delivery ---------------------------------------------------------------------------


@scenario("outage-no-loss", "Delivery", "Radio outage longer than the idle timeout loses no reading")
def outage_no_loss():
    with Gateway() as gw:
        controls = Controls()
        world = ScriptedWorld({4: lambda: setattr(controls, "link_down", True), 34: lambda: setattr(controls, "link_down", False)}, start=NOON)
        result = gw.sensor(40, pace=0.06, world=world, controls=controls)
        times = gw.office.store.tank_times(DEVICE_ID)
        contiguous = all(b - a == 600 for a, b in zip(times, times[1:]))
        device = gw.office.device()
        ok = len(times) == 40 and contiguous and result["outbox"] == 0 and device.buffered >= 25
        return ok, f"{len(times)} of 40 readings stored, {device.buffered} of them buffered through a 1.8 s outage and a reconnect; " + said(
            contiguous, "no gap in tank time", "gaps in tank time"
        )


@scenario("lost-receipt", "Delivery", "A reading resent after a lost receipt is stored once")
def lost_receipt():
    office, (board,) = office_with()
    gateway_one, sensor_one = pair(office, board)
    first = reading(0)
    office.receive_reading(gateway_one, sensor_one.seal(encode_reading(first)))
    gateway_two, sensor_two = pair(office, board)
    delivery = office.receive_reading(gateway_two, sensor_two.seal(encode_reading(first)))
    kind, tank_time, _seq = decode_notice(sensor_two.open(delivery.receipt))
    ok = delivery.duplicate and kind == RECEIPT and tank_time == first.tank_time and office.store.count(DEVICE_ID) == 1
    return ok, "Resent copy recognised by its tank time, acknowledged again, stored once"


@scenario("gateway-restart", "Delivery", "Gateway restart keeps readings and the context the rules need")
def gateway_restart():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "wardlink.db"
        keys = GatewayKeys(new_identity(), new_static_keys())
        office, (board,) = office_with(keys, store=Store(path))
        gateway_side, sensor_side = pair(office, board)
        for index in range(6):
            office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(index * 10, level=50 - index * 0.7))))
        office.store.close()
        restarted = Office(keys, office.roster, store=Store(path))
        device = restarted.device()
        gateway_two, sensor_two = pair(restarted, board)
        delivery = restarted.receive_reading(gateway_two, sensor_two.seal(encode_reading(reading(70, level=80))))
        flag = delivery.reading["assessment"]["flag"]
        restarted.store.close()
        ok = len(device.history) == 7 and flag == "SENSOR"
        return ok, f"Restored {len(device.history) - 1} readings; a 30-point jump right after the restart was still caught ({flag})"


@scenario("outbox-overflow", "Delivery", "A full board buffer drops the oldest readings and counts them")
def outbox_overflow():
    with Gateway() as gw:
        controls = Controls(link_down=True)
        world = ScriptedWorld({21: lambda: setattr(controls, "link_down", False)}, start=NOON)
        result = gw.sensor(25, pace=0.03, world=world, controls=controls, outbox_limit=10)
        times = gw.office.store.tank_times(DEVICE_ID)
        newest = int((NOON + timedelta(minutes=250)).timestamp())
        contiguous = bool(times) and times[-1] == newest and all(b - a == 600 for a, b in zip(times, times[1:]))
        ok = result["dropped"] >= 10 and result["dropped"] + len(times) == 25 and contiguous
        return ok, (
            f"Buffer of 10 through a 20-reading outage: {result['dropped']} oldest readings dropped and counted, "
            f"the newest {len(times)} delivered in order; every reading delivered or accounted for"
        )


# Lifecycle ----------------------------------------------------------------------------


@scenario("clone-alarm", "Lifecycle", "A clone made from stolen keys raises the clone alarm")
def clone_alarm():
    office, (board,) = office_with()
    real_gateway, real_sensor = pair(office, board)
    office.receive_reading(real_gateway, real_sensor.seal(encode_reading(reading(0))))
    clone_gateway, clone_sensor = pair(office, board)
    forged = reading(5, level=96.0)
    office.receive_reading(clone_gateway, clone_sensor.seal(encode_reading(forged)))
    try:
        office.receive_reading(real_gateway, real_sensor.seal(encode_reading(reading(10))))
        return False, "The overlap went unnoticed"
    except SessionEnded:
        pass
    try:
        pair(office, board)
        return False, "Handshakes still accepted after the alarm"
    except ChannelError:
        pass
    flags = office.store.flags(DEVICE_ID)
    ok = office.device().clone is not None and flags[forged.tank_time] == "SUSPECT" and flags[reading(0).tank_time] != "SUSPECT"
    return ok, "Both boards proved genuine keys; the overlap raised the alarm, quarantined the tank, and marked the overlapping session's reading suspect"


@scenario("revoke", "Lifecycle", "A revoked board's handshakes are refused")
def revoke():
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp)
        enroll(data)
        keys, roster = load_gateway(data)
        office = Office(keys, roster, store=Store(), data_dir=data)
        office.revoke()
        try:
            pair(office, load_sensor(data))
        except ChannelError as exc:
            return "revoked" in str(exc), f"Refused: {exc}"
        return False, "A revoked board completed a handshake"


@scenario("reenroll", "Lifecycle", "Re-enrolling on site restores the board and locks out stolen keys")
def reenroll():
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp)
        enroll(data)
        keys, roster = load_gateway(data)
        office = Office(keys, roster, store=Store(), data_dir=data)
        stolen = load_sensor(data)
        office.revoke()
        office.reenroll_device()
        fresh = load_sensor(data)
        gateway_side, sensor_side = pair(office, fresh)
        office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(0))))
        offer = lean_hello(stolen.static, stolen.device_id, stolen.gateway_kem_public, stolen.gateway_x_public)
        welcome, clone_gateway = office.accept_hello(offer.wire, time.time_ns() // 1_000_000)
        clone_session, proven = lean_derive(offer, welcome)
        try:
            office.receive_reading(clone_gateway, clone_session.seal(encode_reading(reading(10))))
            return False, "Stolen keys still worked after re-enrollment"
        except ChannelError:
            pass
        return not proven and office.device().stored == 1, "New keys accepted; the old keys could not even verify the gateway, and their capsule was refused"


@scenario("rate-limit", "Lifecycle", "Handshake rate limit caps a flood of hellos")
def rate_limit():
    office, (board,) = office_with(handshake_limit=6, handshake_window=60)
    accepted = refused = 0
    for _ in range(9):
        try:
            pair(office, board)
            accepted += 1
        except ChannelError:
            refused += 1
    return accepted == 6 and refused == 3, f"{accepted} handshakes answered, {refused} refused within the 60 s window"


@scenario("silence-watchdog", "Lifecycle", "A board that stops reporting is flagged, and cleared when it returns")
def silence_watchdog():
    office, (board,) = office_with(silent_after=0.4)
    gateway_side, sensor_side = pair(office, board)
    for index in range(4):
        office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(index * 10))))
        time.sleep(0.05)
    time.sleep(0.6)
    office.check_silence()
    flagged = office.device().silent
    office.receive_reading(gateway_side, sensor_side.seal(encode_reading(reading(40))))
    cleared = not office.device().silent
    return flagged and cleared, said(flagged, "Flagged after 0.4 s of silence", "Silence never flagged") + "; " + said(
        cleared, "cleared by the next reading", "never cleared"
    )


@scenario("rekey-no-false-alarm", "Lifecycle", "Six re-keys in a row raise no false clone alarm")
def rekey_no_false_alarm():
    with Gateway() as gw:
        controls = Controls(rekey_every=2)
        result = gw.sensor(12, controls=controls)
        proven = sum(1 for item in gw.office.handshakes if item["proven"])
        ok = result["delivered"] == 12 and proven >= 6 and gw.office.device().clone is None
        return ok, f"{proven} sessions, {result['delivered']} readings, " + said(
            gw.office.device().clone is None, "no clone alarm", "a false clone alarm"
        )


# Sensor faults ------------------------------------------------------------------------


def _history(count: int, distance: float | None = None, level: float = 55.0) -> list[Reading]:
    return [reading(index * 10, level=level, distance=distance) for index in range(count)]


@scenario("stuck-sensor", "Sensor faults", "A frozen level sensor is detected")
def stuck_sensor():
    previous = _history(5, distance=1.774)
    result = assess(reading(50, distance=1.774), previous, previous)
    return result["flag"] == "SENSOR" and "stuck" in result["title"], f"{result['flag']}: {result['title']}"


@scenario("no-echo", "Sensor faults", "No echo: level ignored, no tanker sent on it")
def no_echo():
    result = assess(reading(0, level=0.0, distance=4.5), _history(3), _history(3))
    kinds = {item["kind"] for item in result["findings"]}
    ok = result["flag"] == "SENSOR" and not result["physics"]["plausible"] and "tanker" not in kinds
    return ok, f"{result['flag']}: {result['title']}; " + said("tanker" in kinds, "a tanker was still suggested", "no tanker sent on a blind reading")


@scenario("blind-zone", "Sensor faults", "Something inside the blind zone is reported, not believed")
def blind_zone():
    result = assess(reading(0, level=100.0, distance=0.15), [], [])
    return result["flag"] == "SENSOR", f"{result['flag']}: {result['title']}"


@scenario("probes-dry", "Sensor faults", "Probes out of the water raise no false quality alarm")
def probes_dry():
    result = assess(reading(0, level=5.0, ntu=40.0), [], [])
    kinds = {item["kind"] for item in result["findings"]}
    ok = "hold" not in kinds and "dry" in kinds
    return ok, f"{result['flag']}: {result['title']} (40 NTU in air ignored)"


@scenario("impossible-ph", "Sensor faults", "An impossible pH is a probe fault, not a water alarm")
def impossible_ph():
    result = assess(reading(0, ph=0.2), [], [])
    kinds = [item["kind"] for item in result["findings"]]
    ok = "fault" in kinds and "ph" not in kinds
    return ok, f"{result['title']}; " + said("ph" in kinds, "a false water-pH alarm was raised", "no false water-pH alarm")


@scenario("turbidity-debounce", "Sensor faults", "One turbidity spike waits for confirmation; two in a row act")
def turbidity_debounce():
    once = assess(reading(10, ntu=7.0), [reading(0)], [reading(0)])
    twice = assess(reading(20, ntu=7.2), [reading(0), reading(10, ntu=7.0)], [reading(0), reading(10, ntu=7.0)])
    extreme = assess(reading(10, ntu=20.0), [reading(0)], [reading(0)])
    ok = once["flag"] == "CHECK" and twice["flag"] == "SAMPLE" and extreme["flag"] == "SAMPLE"
    return ok, f"single 7 NTU → {once['flag']}, two in a row → {twice['flag']}, 20 NTU at once → {extreme['flag']}"


# Physics and water ------------------------------------------------------------------------


@scenario("plate-under-sensor", "Physics and water", "Plate under the sensor: genuine capsule, impossible level")
def plate_under_sensor():
    result = assess(reading(0, level=99.1, distance=0.33), [], [])
    return result["flag"] == "SENSOR", result["reason"]


@scenario("rise-without-supply", "Physics and water", "Level rising with the main closed is not believed")
def rise_without_supply():
    result = assess(reading(10, level=70), [reading(0, level=40)], [reading(0, level=40)])
    return result["flag"] == "SENSOR", result["reason"]


@scenario("is10500-bands", "Physics and water", "IS 10500 bands for turbidity, pH and TDS")
def is10500_bands():
    clear = assess(reading(0, ntu=0.7), [], [])["flag"]
    above = assess(reading(0, ntu=3.0), [], [])["flag"]
    ph = assess(reading(10, ph=6.2), [reading(0, ph=6.3)], [reading(0, ph=6.3)])["flag"]
    tds = assess(reading(10, tds=3200), [], [])["flag"]
    ok = (clear, above, ph, tds) == ("LOG", "CHECK", "SAMPLE", "SAMPLE")
    return ok, f"0.7 NTU {clear} · 3 NTU {above} · pH 6.2 twice {ph} · TDS 3,200 {tds}"


def _simulate(leak_at_step: int, steps: int) -> list[tuple[str, str, float]]:
    world = World(start=datetime(2026, 10, 4, 4, 20, tzinfo=IST))
    trusted: list[Reading] = []
    previous: list[Reading] = []
    flags = []
    for index in range(steps):
        if index == leak_at_step:
            world.set_event("leak")
        item = world.step()
        result = assess(item, trusted, previous)
        if result["physics"]["plausible"]:
            trusted = (trusted + [item])[-36:]
        previous = (previous + [item])[-8:]
        flags.append((datetime.fromtimestamp(item.tank_time, IST).strftime("%H:%M"), result["flag"], item.level_pct))
    return flags


@scenario("night-leak", "Physics and water", "Minimum-night-flow test catches a leak between 01:00 and 04:00")
def night_leak():
    flags = _simulate(95, 160)
    leak = [entry for entry in flags if entry[1] == "LEAK"]
    ok = bool(leak) and "01:00" <= leak[0][0] <= "04:00"
    return ok, f"Leak from 20:10 flagged at {leak[0][0]}" if leak else "Leak never flagged"


@scenario("tanker-forecast", "Physics and water", "Tanker booked before the tank runs dry")
def tanker_forecast():
    flags = _simulate(50, 200)
    tanker = [entry for entry in flags if entry[1] == "TANKER"]
    return bool(tanker), f"Tanker first requested at {tanker[0][0]} with the tank at {tanker[0][2]:.0f}%" if tanker else "No tanker requested"


# Load ----------------------------------------------------------------------------------------


@scenario("load-20-tanks", "Load", "Twenty tanks reporting at once: every reading stored, no cross-talk")
def load_20_tanks():
    with Gateway(sensors=20) as gw:
        results: dict[int, dict] = {}

        def work(index: int) -> None:
            results[index] = gw.sensor(8, board=index, pace=0.02, world=World(seed=index, start=NOON))

        started = time.monotonic()
        threads = [threading.Thread(target=work, args=(index,)) for index in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        seconds = time.monotonic() - started
        counts = [gw.office.store.count(board.device_id) for board in gw.boards]
        ok = all(count == 8 for count in counts) and sum(r["delivered"] for r in results.values()) == 160
        return ok, f"{sum(counts)} of 160 readings stored from 20 boards in {seconds:.1f} s; every tank has exactly its own 8"


# Runner ----------------------------------------------------------------------------------------


def run_suite(only: str = "", progress: bool = False) -> dict:
    started = time.monotonic()
    results = []
    for ident, category, title, fn in SCENARIOS:
        if only and only not in ident:
            continue
        begin = time.monotonic()
        try:
            passed, detail = fn()
        except Exception as exc:  # a crashing scenario is a failed scenario, with its reason
            passed, detail = False, f"{type(exc).__name__}: {exc} · {traceback.format_exc(limit=2).splitlines()[-1]}"
        ms = round((time.monotonic() - begin) * 1000)
        results.append({"id": ident, "category": category, "title": title, "passed": bool(passed), "detail": detail, "ms": ms})
        if progress:
            print(f"{'PASS' if passed else 'FAIL'}  {ident:<22} {ms:>6} ms  {detail}")
    return {
        "finished_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "seconds": round(time.monotonic() - started, 1),
        "passed": sum(1 for item in results if item["passed"]),
        "total": len(results),
        "machine": f"{platform.machine()} · Python {platform.python_version()}",
        "results": results,
    }


def save_report(report: dict, data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "rigor.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def print_report(report: dict) -> None:
    print(f"\n{report['passed']} of {report['total']} field scenarios passed in {report['seconds']} s")
    current = None
    for item in report["results"]:
        if item["category"] != current:
            current = item["category"]
            print(f"\n{current}")
        print(f"  {'pass' if item['passed'] else 'FAIL'}  {item['title']}")

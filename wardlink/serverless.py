"""WardLink on a serverless host such as Vercel.

A serverless function only runs while it answers a request, so there is no
sensor thread, no TCP gateway and no background watchdog. Instead every request
first catches the tank up to the wall clock: the readings that fell due since
the last request are taken, sealed by the board and opened by the gateway
in-process, using the same handshake, per-reading key ratchet, receipts, rules
and attack bench as the TCP demo. State lives in the warm instance and starts
afresh, with new keys, after a cold start.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
from collections import deque
from dataclasses import replace
from pathlib import Path

from wardlink.api import parse_body, respond
from wardlink.channel import lean_hello, sensor_hello
from wardlink.crypto import ChannelError
from wardlink.enroll import enroll, load_gateway, load_sensor
from wardlink.office import Controls, Office, SessionEnded
from wardlink.record import BUFFERED, RECEIPT, Reading, decode_notice, encode_reading
from wardlink.store import Store
from wardlink.world import World

REPORTS = Path(__file__).resolve().parent / "reports"
PACE = 6.5
MAX_CATCH_UP = 6
OUTBOX_LIMIT = 144
RETRY_AFTER = 5.0
REASONS = {200: "OK", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict", 500: "Internal Server Error"}


def _report(name: str) -> dict | None:
    try:
        return json.loads((REPORTS / name).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


class ServerlessDemo:
    def __init__(self, data_dir: Path | None = None, pace: float = PACE, rekey_every: int = 36):
        self.data_dir = data_dir or Path(tempfile.mkdtemp(prefix="wardlink-"))
        enroll(self.data_dir)
        keys, roster = load_gateway(self.data_dir)
        self.pace = pace
        self.controls = Controls(rekey_every=rekey_every)
        self.world = World()
        self.office = Office(keys, roster, world=self.world, controls=self.controls, store=Store(), data_dir=self.data_dir)
        self.office.bench = _report("bench.json")
        self.office.rigor = _report("rigor.json")
        self.board = load_sensor(self.data_dir)
        self.session = None
        self.gateway_side = None
        self.sent: set[int] = set()
        self.in_session = 0
        self.outbox: deque[Reading] = deque()
        self.dropped = 0
        self.next_due = time.monotonic()
        self.down_since: float | None = None
        self.offline_since: float | None = None
        self.retry_at = 0.0
        self.lock = threading.Lock()

    def tick(self) -> None:
        """Bring the simulation up to now. Never raises: one bad step must not fail the request."""
        with self.lock:
            now = time.monotonic()
            due = 0
            while self.next_due <= now and due < MAX_CATCH_UP:
                self.next_due += self.pace
                due += 1
            if self.next_due <= now:
                self.next_due = now + self.pace
            try:
                for _ in range(due):
                    self._sample(now)
                self._deliver(now)
            except Exception as exc:  # report it in the office log instead of a 500
                self.office.note_internal(f"{type(exc).__name__}: {exc}")
                self._drop()

    def _sample(self, now: float) -> None:
        reading = self.world.step()
        offline = self.offline_since is not None and now - self.offline_since > min(self.pace, 2.0)
        if self.controls.link_down or offline:
            reading = replace(reading, flags=reading.flags | BUFFERED)
        self.outbox.append(reading)
        while len(self.outbox) > OUTBOX_LIMIT:
            self.outbox.popleft()
            self.dropped += 1
        self.controls.outbox, self.controls.dropped = len(self.outbox), self.dropped

    def _deliver(self, now: float) -> None:
        if self.controls.link_down:
            if self.down_since is None:
                self.down_since = now
                self.offline_since = self.offline_since or now
            if self.session is not None and now - self.down_since > self.office.idle_timeout:
                self.office.note_idle(self.gateway_side, now - self.down_since)
                self._drop()
            return
        self.down_since = None
        if self.session is None and not self._connect(now):
            return
        for reading in list(self.outbox):
            if reading.tank_time in self.sent:
                continue
            frame = self.session.seal(encode_reading(reading))
            self.sent.add(reading.tank_time)
            self.in_session += 1
            try:
                delivery = self.office.receive_reading(self.gateway_side, frame)
            except SessionEnded:
                self._drop()
                return
            except ChannelError:
                continue
            kind, tank_time, _seq = decode_notice(self.session.open(delivery.receipt))
            if kind == RECEIPT:
                self.outbox = deque(item for item in self.outbox if item.tank_time != tank_time)
                self.sent.discard(tank_time)
        note = self.office.next_note_frame(self.gateway_side)
        if note is not None:
            self.session.open(note)
        self.controls.outbox = len(self.outbox)
        if not self.outbox and (self.in_session >= self.controls.rekey_every or self.controls.take_rekey()):
            self._drop()

    def _connect(self, now: float) -> bool:
        if now < self.retry_at:
            return False
        try:
            fresh = load_sensor(self.data_dir, self.board.device_id)
        except (OSError, ValueError, KeyError):
            fresh = self.board
        self.board = fresh
        if self.controls.mode == "signed":
            offer = sensor_hello(fresh.identity, fresh.device_id, time.time_ns() // 1_000_000)
        else:
            offer = lean_hello(fresh.static, fresh.device_id, fresh.gateway_kem_public, fresh.gateway_x_public)
        try:
            welcome, gateway_side = self.office.accept_hello(offer.wire, time.time_ns() // 1_000_000)
            self.session = offer.finish(welcome, fresh.gateway_public)
        except ChannelError as exc:
            offer.discard()
            self.office.note_refusal(str(exc))
            self.offline_since = self.offline_since or now
            self.retry_at = now + RETRY_AFTER
            return False
        self.gateway_side = gateway_side
        self.sent.clear()
        self.in_session = 0
        self.offline_since = None
        self.office.connection_opened(fresh.device_id)
        return True

    def _drop(self) -> None:
        if self.session is not None:
            self.office.connection_closed(self.board.device_id)
        self.session = None
        self.gateway_side = None
        self.sent.clear()


_demo: ServerlessDemo | None = None
_demo_lock = threading.Lock()


def demo() -> ServerlessDemo:
    global _demo
    with _demo_lock:
        if _demo is None:
            _demo = ServerlessDemo()
        return _demo


def app(environ, start_response):
    """WSGI entry point. Vercel loads this as `app` from the project's app.py."""
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/") or "/"
    body = {}
    if method == "POST":
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length:
            body = parse_body(environ["wsgi.input"].read(min(length, 4096)))
    current = demo()
    if path.startswith("/api/"):
        current.tick()
    try:
        status, content_type, payload = respond(current.office, method, path, body, run_rigor=None, serverless=True)
    except Exception as exc:  # never leak a traceback page
        status, content_type, payload = 500, "application/json", json.dumps({"error": str(exc)}).encode()
    headers = [("Content-Type", content_type), ("Content-Length", str(len(payload))), ("Cache-Control", "no-store")]
    start_response(f"{status} {REASONS.get(status, 'OK')}", headers)
    return [b""] if method == "HEAD" else [payload]

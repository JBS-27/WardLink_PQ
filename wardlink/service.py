"""TCP gateway, the sensor loop, and the one-command demo.

Gateway: every connection gets its own thread, so a stalled or dead link
never blocks another tank. A hello must arrive within the hello timeout, a
started frame must finish within the body timeout, and a connection that
carries nothing for the idle timeout is closed. Connections beyond the cap
are turned away.

Sensor: every reading goes into an outbox first and leaves it only when the
gateway's sealed receipt for it arrives. Across an outage, a gateway restart
or a re-key, nothing is lost; readings taken while offline are marked as
buffered and keep their original tank time.
"""

from __future__ import annotations

import socket
import threading
import time
from collections import deque
from dataclasses import replace
from pathlib import Path

from wardlink.channel import lean_hello, sensor_hello
from wardlink.crypto import ChannelError
from wardlink.enroll import SensorKeys, load_sensor
from wardlink.framing import DATA, HELLO, NOTE, REJECT, WELCOME, recv_frame, send_frame
from wardlink.office import Controls, Office, SessionEnded
from wardlink.record import BUFFERED, RECEIPT, SEEN, Reading, decode_notice, encode_reading
from wardlink.world import World

SENSOR_HOST = "127.0.0.1"
SENSOR_PORT = 9701
PAGE_HOST = "127.0.0.1"
PAGE_PORT = 8765
MAX_CONNECTIONS = 64
HELLO_TIMEOUT = 10.0
OUTBOX_LIMIT = 144


def listen(host: str = SENSOR_HOST, port: int = SENSOR_PORT) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    return listener


def serve_gateway(
    office: Office,
    listener: socket.socket,
    stop: threading.Event | None = None,
    max_connections: int = MAX_CONNECTIONS,
    hello_timeout: float = HELLO_TIMEOUT,
    quiet: bool = False,
) -> None:
    slots = threading.BoundedSemaphore(max_connections)
    listener.settimeout(0.5)
    if not quiet:
        bound = listener.getsockname()
        print(f"Sensor port {bound[0]}:{bound[1]}")
    try:
        while stop is None or not stop.is_set():
            try:
                conn, _addr = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if stop is not None and stop.is_set():
                    break
                raise
            if not slots.acquire(blocking=False):
                try:
                    conn.settimeout(1.0)
                    send_frame(conn, REJECT + b"gateway busy")
                except OSError:
                    pass
                conn.close()
                office.note_refusal("connection cap reached, so a new connection was turned away")
                continue
            threading.Thread(
                target=_serve_one, args=(office, conn, slots, hello_timeout, quiet), daemon=True
            ).start()
    except KeyboardInterrupt:
        print("Gateway stopped")
    finally:
        listener.close()


def handle_sensor(office: Office, listener: socket.socket) -> None:
    """Serve exactly one connection, then close the listener. Used by tests."""
    conn, _addr = listener.accept()
    slots = threading.BoundedSemaphore(1)
    slots.acquire()
    try:
        _serve_one(office, conn, slots, HELLO_TIMEOUT, True)
    finally:
        listener.close()


def _keepalive(conn: socket.socket) -> None:
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for name, value in (("TCP_KEEPIDLE", 10), ("TCP_KEEPINTVL", 5), ("TCP_KEEPCNT", 3)):
        if hasattr(socket, name):
            conn.setsockopt(socket.IPPROTO_TCP, getattr(socket, name), value)


def _serve_one(office: Office, conn: socket.socket, slots: threading.BoundedSemaphore, hello_timeout: float, quiet: bool) -> None:
    try:
        _keepalive(conn)
        _talk_to_sensor(office, conn, hello_timeout, quiet)
    except ChannelError as exc:
        office.note_refusal(str(exc))
    except (ConnectionError, OSError):
        pass
    except Exception as exc:  # one bad connection must never take the gateway down
        office.note_internal(f"{type(exc).__name__}: {exc}")
    finally:
        conn.close()
        slots.release()


def _talk_to_sensor(office: Office, conn: socket.socket, hello_timeout: float, quiet: bool) -> None:
    hello = recv_frame(conn, timeout=hello_timeout, body_timeout=office.body_timeout)
    if hello is None:
        office.note_refusal(f"a connection sent nothing for {hello_timeout:.0f} s")
        return
    if not hello.startswith(HELLO):
        send_frame(conn, REJECT + b"expected a hello")
        raise ChannelError("first message was not a hello")
    try:
        welcome, session = office.accept_hello(hello[1:], time.time_ns() // 1_000_000)
    except ChannelError as exc:
        office.note_refusal(str(exc))
        send_frame(conn, REJECT + str(exc).encode())
        return
    send_frame(conn, WELCOME + welcome)
    office.connection_opened(session.device_id)
    if not quiet:
        print(f"Handshake {session.mode} from {session.device_id}: {len(hello) - 1} bytes in, {len(welcome)} bytes out")
    try:
        last_data = time.monotonic()
        while True:
            frame = recv_frame(conn, timeout=0.5, body_timeout=office.body_timeout)
            if frame is None:
                quiet_for = time.monotonic() - last_data
                if quiet_for > office.idle_timeout:
                    office.note_idle(session, quiet_for)
                    return
            else:
                last_data = time.monotonic()
                if not frame.startswith(DATA):
                    raise ChannelError("expected a reading")
                try:
                    delivery = office.receive_reading(session, frame[1:])
                except SessionEnded:
                    return
                except ChannelError:
                    continue
                send_frame(conn, NOTE + delivery.receipt)
                if not quiet and delivery.reading:
                    reading = delivery.reading
                    print(f"Verified reading {reading['seq']}: tank {reading['level_pct']:.0f}% · {reading['assessment']['flag']}")
            note = office.next_note_frame(session)
            if note is not None:
                send_frame(conn, NOTE + note)
    finally:
        office.connection_closed(session.device_id)


# Sensor ------------------------------------------------------------------------


def _connect(keys: SensorKeys, host: str, port: int, mode: str):
    conn = socket.create_connection((host, port), timeout=5)
    if mode == "signed":
        offer = sensor_hello(keys.identity, keys.device_id, time.time_ns() // 1_000_000)
    else:
        offer = lean_hello(keys.static, keys.device_id, keys.gateway_kem_public, keys.gateway_x_public)
    try:
        send_frame(conn, HELLO + offer.wire)
        welcome = recv_frame(conn, timeout=10)
        if welcome is None:
            raise ChannelError("gateway did not answer")
        if welcome.startswith(REJECT):
            raise ChannelError(welcome[1:].decode(errors="replace"))
        if not welcome.startswith(WELCOME):
            raise ChannelError("gateway answer was not a welcome")
        return conn, offer.finish(welcome[1:], keys.gateway_public)
    except BaseException:
        offer.discard()
        conn.close()
        raise


def _close(conn: socket.socket | None) -> None:
    if conn is not None:
        try:
            conn.close()
        except OSError:
            pass


def _reload(keys: SensorKeys, data_dir: Path) -> SensorKeys:
    try:
        fresh = load_sensor(data_dir, keys.device_id)
    except (OSError, ValueError, KeyError):
        return keys
    if fresh.static.kem_public != keys.static.kem_public:
        print(f"{keys.device_id} was re-enrolled; using its new keys")
    return fresh


def run_sensor(
    keys: SensorKeys,
    host: str = SENSOR_HOST,
    port: int = SENSOR_PORT,
    world: World | None = None,
    controls: Controls | None = None,
    readings: int | None = None,
    pace: float = 6.5,
    data_dir: Path | None = None,
    outbox_limit: int = OUTBOX_LIMIT,
    stop: threading.Event | None = None,
    quiet: bool = False,
) -> dict:
    """Sample on schedule; deliver through an outbox that only receipts can empty."""
    world = world or World()
    controls = controls or Controls()
    outbox: deque[Reading] = deque()
    sent: set[int] = set()
    taken = delivered = dropped = 0
    conn: socket.socket | None = None
    session = None
    in_session = 0
    backoff = 0.5
    retry_at = 0.0
    offline_since: float | None = None
    next_sample = time.monotonic()
    try:
        while stop is None or not stop.is_set():
            now = time.monotonic()
            if controls.link_down and offline_since is None:
                offline_since = now
            if (readings is None or taken < readings) and now >= next_sample:
                reading = world.step()
                taken += 1
                next_sample = now + pace
                if controls.link_down or (session is None and offline_since is not None and now - offline_since > min(pace, 2.0)):
                    reading = replace(reading, flags=reading.flags | BUFFERED)
                outbox.append(reading)
                while len(outbox) > outbox_limit:
                    outbox.popleft()
                    dropped += 1
                controls.outbox, controls.dropped = len(outbox), dropped
            if readings is not None and taken >= readings and not outbox:
                break
            if controls.link_down:
                time.sleep(0.05)
                continue
            if session is not None and offline_since is not None:
                offline_since = None
            if session is None:
                if now < retry_at:
                    time.sleep(0.05)
                    continue
                try:
                    if data_dir is not None:
                        keys = _reload(keys, data_dir)
                    conn, session = _connect(keys, host, port, controls.mode)
                    sent.clear()
                    in_session = 0
                    backoff = 0.5
                    offline_since = None
                    if not quiet:
                        print(f"{session.mode} session {session.session_id}; {len(outbox)} readings in the outbox")
                except (ConnectionError, OSError, ChannelError) as exc:
                    conn, session = None, None
                    if offline_since is None:
                        offline_since = now
                    if not quiet:
                        print(f"Waiting for gateway ({exc})")
                    retry_at = time.monotonic() + backoff
                    backoff = min(backoff * 2, 8.0)
                    continue
            try:
                burst = 0
                for item in list(outbox):
                    if item.tank_time in sent:
                        continue
                    send_frame(conn, DATA + session.seal(encode_reading(item)))
                    sent.add(item.tank_time)
                    in_session += 1
                    burst += 1
                    if burst >= 8:
                        break
                frame = recv_frame(conn, timeout=0.1)
                while frame is not None:
                    if not frame.startswith(NOTE):
                        raise ChannelError("unexpected gateway message")
                    kind, first, second = decode_notice(session.open(frame[1:]))
                    if kind == RECEIPT:
                        before = len(outbox)
                        outbox = deque(item for item in outbox if item.tank_time != first)
                        delivered += before - len(outbox)
                        sent.discard(first)
                    elif kind == SEEN and not quiet:
                        print(f"Engineer saw reading {first}")
                    frame = recv_frame(conn, timeout=0.001)
                controls.outbox = len(outbox)
                if not outbox and (in_session >= controls.rekey_every or controls.take_rekey()):
                    _close(conn)
                    conn, session = None, None
            except (ConnectionError, OSError, ChannelError) as exc:
                if not quiet:
                    print(f"Link lost ({exc}); {len(outbox)} readings kept for resend")
                _close(conn)
                conn, session = None, None
                offline_since = offline_since or time.monotonic()
                retry_at = time.monotonic() + backoff
                backoff = min(backoff * 2, 8.0)
            if not outbox:
                time.sleep(0.02)
    finally:
        _close(conn)
    return {"taken": taken, "delivered": delivered, "dropped": dropped, "outbox": len(outbox)}


# Background helpers ------------------------------------------------------------


def start_page(office: Office, host: str = PAGE_HOST, port: int = PAGE_PORT) -> None:
    from wardlink.web import serve_page

    threading.Thread(target=serve_page, args=(office, host, port), daemon=True).start()
    print(f"Section office dashboard http://{host}:{port}")


def start_bench(office: Office, data_dir=None) -> None:
    from wardlink.bench import run_bench

    def work() -> None:
        try:
            office.bench = run_bench(data_dir)
        except Exception as exc:  # the dashboard shows the reason instead of crashing the gateway
            office.bench = {"error": str(exc)}

    threading.Thread(target=work, daemon=True).start()


def start_watchdog(office: Office, every: float = 1.0) -> None:
    def work() -> None:
        while True:
            time.sleep(every)
            office.check_silence()

    threading.Thread(target=work, daemon=True).start()


def start_rigor(office: Office, data_dir: Path | None = None) -> bool:
    """Run the scenario suite in the background. False if a run is already going."""
    from wardlink.rigor import run_suite, save_report

    with office.lock:
        if office.rigor_running:
            return False
        office.rigor_running = True

    def work() -> None:
        try:
            report = run_suite()
            office.rigor = report
            if data_dir is not None:
                save_report(report, data_dir)
        except Exception as exc:  # report the failure on the dashboard
            office.rigor = {"error": str(exc), "passed": 0, "total": 0, "finished_at": "", "seconds": 0, "results": []}
        finally:
            office.rigor_running = False

    threading.Thread(target=work, daemon=True).start()
    return True


def run_demo(
    office: Office,
    sensor_keys: SensorKeys,
    pace: float,
    host: str = SENSOR_HOST,
    port: int = SENSOR_PORT,
    page_port: int = PAGE_PORT,
    data_dir: Path | None = None,
) -> None:
    listener = listen(host, port)
    start_page(office, PAGE_HOST, page_port)
    start_bench(office, data_dir)
    start_watchdog(office)
    threading.Thread(
        target=run_sensor,
        args=(sensor_keys, host, port, office.world, office.controls),
        kwargs={"pace": pace, "data_dir": data_dir},
        daemon=True,
    ).start()
    serve_gateway(office, listener)

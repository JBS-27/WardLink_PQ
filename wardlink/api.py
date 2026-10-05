"""Dashboard routes, shared by the local web server and the serverless (WSGI) app."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from wardlink.crypto import ChannelError
from wardlink.office import Office

STATIC = (Path(__file__).resolve().parent / "static").resolve()
TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}
ATTACKS = {
    "tamper": Office.arm_tamper,
    "replay": Office.replay_last,
    "impostor": Office.impostor,
    "unknown": Office.unknown_board,
    "capture": Office.capture_board,
    "clone": Office.clone_board,
}
DEVICE_ACTIONS = {"revoke": Office.revoke, "reenroll": Office.reenroll_device}
WORLD = {"leak", "contaminate", "spoof", "stuck", "noecho", "spike", "normal"}
SERVERLESS_RIGOR = (
    "Live scenario runs need a long-running server, which this serverless deployment is not. "
    "This page shows the last full run; reproduce it with: python -m wardlink rigor"
)

Response = tuple[int, str, bytes]


def _json(status: int, payload: dict) -> Response:
    return status, "application/json", json.dumps(payload).encode()


def static_file(path: str) -> Path | None:
    name = "index.html" if path in ("", "/") else path.lstrip("/")
    candidate = (STATIC / name).resolve()
    if STATIC not in candidate.parents or candidate.suffix not in TYPES or not candidate.is_file():
        return None
    return candidate


def parse_body(raw: bytes) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def respond(
    office: Office,
    method: str,
    path: str,
    body: dict,
    run_rigor: Callable[[], bool] | None = None,
    serverless: bool = False,
) -> Response:
    """Answer one dashboard request. `run_rigor` is None where background runs are impossible."""
    path = path.split("?", 1)[0]
    if method in ("GET", "HEAD"):
        if path == "/api/state":
            snapshot = office.snapshot()
            snapshot["serverless"] = serverless
            return _json(200, snapshot)
        if path == "/api/bench":
            return _json(200, office.bench or {"pending": True})
        if path == "/api/rigor":
            note = None if run_rigor else SERVERLESS_RIGOR
            return _json(200, {"running": office.rigor_running, "report": office.rigor, "live_runs": run_rigor is not None, "note": note})
        file = static_file(path)
        if file is None:
            return 404, "text/plain; charset=utf-8", b"not found"
        return 200, TYPES[file.suffix], file.read_bytes()
    if method != "POST":
        return 405, "text/plain; charset=utf-8", b"method not allowed"
    parts = [part for part in path.split("/") if part]
    try:
        if path == "/api/ack":
            sequence = office.request_ack()
            return _json(409, {"error": "no reading yet"}) if sequence is None else _json(200, {"acked": sequence})
        if len(parts) == 3 and parts[:2] == ["api", "attack"] and parts[2] in ATTACKS:
            return _json(200, ATTACKS[parts[2]](office))
        if len(parts) == 3 and parts[:2] == ["api", "device"] and parts[2] in DEVICE_ACTIONS:
            return _json(200, DEVICE_ACTIONS[parts[2]](office))
        if len(parts) == 3 and parts[:2] == ["api", "world"] and parts[2] in WORLD:
            return _json(200, {"text": office.world_event(parts[2])})
        if len(parts) == 3 and parts[:2] == ["api", "link"] and parts[2] in ("down", "up"):
            return _json(200, {"text": office.set_link(parts[2] == "down")})
        if path == "/api/rekey":
            return _json(200, {"mode": office.request_rekey(body.get("mode"))})
        if path == "/api/rigor/run":
            if run_rigor is None:
                return _json(409, {"started": False, "error": SERVERLESS_RIGOR})
            started = run_rigor()
            return _json(200 if started else 409, {"started": started})
    except ChannelError as exc:
        return _json(409, {"error": str(exc)})
    return 404, "text/plain; charset=utf-8", b"not found"

"""Section-office website. Readings reach the page only after the gateway verified them."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


def serve_page(office: Office, host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), _handler(office))
    server.daemon_threads = True
    server.serve_forever()


def _static_file(path: str) -> Path | None:
    name = "index.html" if path in ("", "/") else path.lstrip("/")
    candidate = (STATIC / name).resolve()
    if STATIC not in candidate.parents or candidate.suffix not in TYPES or not candidate.is_file():
        return None
    return candidate


def _handler(office: Office):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/api/state":
                self._json(200, office.snapshot())
                return
            if path == "/api/bench":
                self._json(200, office.bench or {"pending": True})
                return
            if path == "/api/rigor":
                self._json(200, {"running": office.rigor_running, "report": office.rigor})
                return
            file = _static_file(path)
            if file is None:
                self._send(404, "text/plain; charset=utf-8", b"not found")
                return
            self._send(200, TYPES[file.suffix], file.read_bytes())

        def do_POST(self) -> None:
            body = self._body()
            path = self.path.split("?", 1)[0]
            parts = [part for part in path.split("/") if part]
            try:
                if path == "/api/ack":
                    sequence = office.request_ack()
                    if sequence is None:
                        self._json(409, {"error": "no reading yet"})
                    else:
                        self._json(200, {"acked": sequence})
                    return
                if len(parts) == 3 and parts[:2] == ["api", "attack"] and parts[2] in ATTACKS:
                    self._json(200, ATTACKS[parts[2]](office))
                    return
                if len(parts) == 3 and parts[:2] == ["api", "device"] and parts[2] in DEVICE_ACTIONS:
                    self._json(200, DEVICE_ACTIONS[parts[2]](office))
                    return
                if len(parts) == 3 and parts[:2] == ["api", "world"] and parts[2] in WORLD:
                    self._json(200, {"text": office.world_event(parts[2])})
                    return
                if len(parts) == 3 and parts[:2] == ["api", "link"] and parts[2] in ("down", "up"):
                    self._json(200, {"text": office.set_link(parts[2] == "down")})
                    return
                if path == "/api/rekey":
                    self._json(200, {"mode": office.request_rekey(body.get("mode"))})
                    return
                if path == "/api/rigor/run":
                    from wardlink.service import start_rigor

                    started = start_rigor(office, office.data_dir)
                    self._json(200 if started else 409, {"started": started})
                    return
            except ChannelError as exc:
                self._json(409, {"error": str(exc)})
                return
            self._send(404, "text/plain; charset=utf-8", b"not found")

        def log_message(self, fmt: str, *args) -> None:
            return

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if not length:
                return {}
            raw = self.rfile.read(min(length, 4096))
            try:
                parsed = json.loads(raw.decode())
            except (UnicodeDecodeError, json.JSONDecodeError):
                return {}
            return parsed if isinstance(parsed, dict) else {}

        def _json(self, status: int, payload: dict) -> None:
            self._send(status, "application/json", json.dumps(payload).encode())

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler

"""Section-office website on the local, long-running server."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from wardlink.api import parse_body, respond
from wardlink.office import Office


def serve_page(office: Office, host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), _handler(office))
    server.daemon_threads = True
    server.serve_forever()


def _handler(office: Office):
    def run_rigor() -> bool:
        from wardlink.service import start_rigor

        return start_rigor(office, office.data_dir)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._answer("GET", {})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(min(length, 4096)) if length else b""
            self._answer("POST", parse_body(raw))

        def _answer(self, method: str, body: dict) -> None:
            status, content_type, payload = respond(office, method, self.path, body, run_rigor=run_rigor)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args) -> None:
            return

    return Handler

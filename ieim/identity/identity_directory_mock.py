from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlparse


@dataclass
class IdentityDirectoryMockState:
    token: str = "MOCK_JWT"
    mode: str = "OK"  # OK, 429, 503
    last_search_request: Optional[dict] = None
    candidates: list[dict] = field(default_factory=list)


class IdentityDirectoryMockServer:
    def __init__(self, *, state: Optional[IdentityDirectoryMockState] = None) -> None:
        self.state = state or IdentityDirectoryMockState()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.base_url: Optional[str] = None

    def __enter__(self) -> "IdentityDirectoryMockServer":
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            server_version = "IEIMIdentityDirectoryMock/1.0"

            def log_message(self, fmt: str, *args) -> None:  # pragma: no cover
                return

            def _send_json(self, status: int, obj: dict) -> None:
                data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _read_body(self) -> bytes:
                n = int(self.headers.get("Content-Length") or "0")
                return self.rfile.read(n) if n > 0 else b""

            def _require_bearer(self) -> bool:
                auth = self.headers.get("Authorization") or ""
                if auth.strip() != f"Bearer {state.token}":
                    self._send_json(401, {"error": "unauthorized"})
                    return False
                return True

            def do_POST(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path != "/v1/identity/search":
                    self._send_json(404, {"error": "not_found"})
                    return
                if not self._require_bearer():
                    return
                if state.mode == "429":
                    self._send_json(429, {"error": "rate_limited"})
                    return
                if state.mode == "503":
                    self._send_json(503, {"error": "unavailable"})
                    return
                req = json.loads(self._read_body().decode("utf-8"))
                state.last_search_request = req if isinstance(req, dict) else None
                request_id = ""
                if isinstance(req, dict):
                    rid = req.get("request_id")
                    if isinstance(rid, str):
                        request_id = rid
                self._send_json(
                    200,
                    {
                        "request_id": request_id,
                        "candidates": list(state.candidates),
                        "warnings": [],
                        "trace_id": "id_dir_trace_mock",
                    },
                )

            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path.startswith("/v1/"):
                    if not self._require_bearer():
                        return
                self._send_json(404, {"error": "not_found"})

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd = httpd
        host, port = httpd.server_address
        self.base_url = f"http://{host}:{port}"

        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self._thread = thread
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


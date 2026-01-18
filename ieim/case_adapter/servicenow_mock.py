from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse


@dataclass
class ServiceNowMockState:
    token: str = "MOCK_TOKEN"
    incidents: dict[str, dict] = field(default_factory=dict)
    correlation_index: dict[str, str] = field(default_factory=dict)
    attachments_by_incident: dict[str, dict[str, bytes]] = field(default_factory=dict)
    sys_users_by_email: dict[str, str] = field(default_factory=dict)
    next_incident_number: int = 1

    def incident_count(self) -> int:
        return len(self.incidents)

    def attachment_count(self) -> int:
        total = 0
        for _sys_id, files in self.attachments_by_incident.items():
            total += len(files)
        return total


class ServiceNowMockServer:
    def __init__(self, *, state: Optional[ServiceNowMockState] = None) -> None:
        self.state = state or ServiceNowMockState()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.base_url: Optional[str] = None

    def __enter__(self) -> "ServiceNowMockServer":
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            server_version = "IEIMServiceNowMock/1.0"

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
                if parsed.path == "/oauth_token.do":
                    body = self._read_body().decode("utf-8", errors="replace")
                    form = parse_qs(body)
                    if form.get("grant_type", [""])[0] != "client_credentials":
                        self._send_json(400, {"error": "unsupported_grant_type"})
                        return
                    self._send_json(
                        200,
                        {
                            "access_token": state.token,
                            "token_type": "Bearer",
                            "expires_in": 3600,
                        },
                    )
                    return

                if parsed.path == "/api/now/table/incident":
                    if not self._require_bearer():
                        return
                    payload = json.loads(self._read_body().decode("utf-8"))
                    correlation_id = str(payload.get("correlation_id") or "")
                    if not correlation_id:
                        self._send_json(400, {"error": "missing correlation_id"})
                        return

                    existing_sys_id = state.correlation_index.get(correlation_id)
                    if existing_sys_id is not None:
                        self._send_json(200, {"result": state.incidents[existing_sys_id]})
                        return

                    sys_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"sn_incident:{correlation_id}"))
                    number = f"INC{state.next_incident_number:07d}"
                    state.next_incident_number += 1
                    record = {
                        "sys_id": sys_id,
                        "number": number,
                        "correlation_id": correlation_id,
                        **payload,
                    }
                    state.incidents[sys_id] = record
                    state.correlation_index[correlation_id] = sys_id
                    state.attachments_by_incident.setdefault(sys_id, {})
                    self._send_json(201, {"result": record})
                    return

                if parsed.path == "/api/now/attachment/file":
                    if not self._require_bearer():
                        return
                    qs = parse_qs(parsed.query)
                    table_name = qs.get("table_name", [""])[0]
                    table_sys_id = qs.get("table_sys_id", [""])[0]
                    file_name = qs.get("file_name", [""])[0]
                    if table_name != "incident" or not table_sys_id or not file_name:
                        self._send_json(400, {"error": "invalid attachment upload"})
                        return
                    body = self._read_body()
                    files = state.attachments_by_incident.setdefault(table_sys_id, {})
                    files.setdefault(file_name, body)
                    self._send_json(
                        201,
                        {
                            "result": {
                                "sys_id": str(uuid.uuid4()),
                                "table_name": "incident",
                                "table_sys_id": table_sys_id,
                                "file_name": file_name,
                            }
                        },
                    )
                    return

                self._send_json(404, {"error": "not_found"})

            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path.startswith("/api/now/"):
                    if not self._require_bearer():
                        return

                if parsed.path == "/api/now/table/incident":
                    qs = parse_qs(parsed.query)
                    q = qs.get("sysparm_query", [""])[0]
                    fields = qs.get("sysparm_fields", [""])[0].split(",") if qs.get("sysparm_fields") else []
                    correlation_id = ""
                    if q.startswith("correlation_id="):
                        correlation_id = q.split("=", 1)[1]
                    sys_id = state.correlation_index.get(correlation_id or "")
                    if sys_id is None:
                        self._send_json(200, {"result": []})
                        return
                    record = state.incidents.get(sys_id) or {}
                    if fields:
                        filtered = {k: record.get(k) for k in fields}
                    else:
                        filtered = record
                    self._send_json(200, {"result": [filtered]})
                    return

                if parsed.path == "/api/now/table/sys_user":
                    qs = parse_qs(parsed.query)
                    q = qs.get("sysparm_query", [""])[0]
                    email = ""
                    if q.startswith("email="):
                        email = q.split("=", 1)[1]
                    sys_id = state.sys_users_by_email.get(email)
                    if sys_id is None:
                        self._send_json(200, {"result": []})
                        return
                    self._send_json(200, {"result": [{"sys_id": sys_id}]})
                    return

                if parsed.path == "/api/now/attachment":
                    qs = parse_qs(parsed.query)
                    q = qs.get("sysparm_query", [""])[0]
                    table_sys_id = ""
                    for part in q.split("^"):
                        if part.startswith("table_sys_id="):
                            table_sys_id = part.split("=", 1)[1]
                    files = state.attachments_by_incident.get(table_sys_id) or {}
                    out = [{"sys_id": str(uuid.uuid4()), "file_name": fn} for fn in sorted(files.keys())]
                    self._send_json(200, {"result": out})
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


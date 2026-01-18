from __future__ import annotations

import base64
import json
import time
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Callable, Iterable, Optional
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ieim.ingest.adapter import AttachmentRef, MailIngestAdapter, MessageRef


def _parse_graph_datetime(value: str) -> datetime:
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        dt = parsedate_to_datetime(v)
        if dt is None:
            raise
        return dt


RequestBytesFn = Callable[[str, dict[str, str]], bytes]


def _default_request_bytes(url: str, headers: dict[str, str]) -> bytes:
    max_attempts = 4
    base_backoff_s = 0.5

    for attempt in range(1, max_attempts + 1):
        try:
            req = Request(url, headers=headers, method="GET")
            with urlopen(req, timeout=30) as resp:
                return resp.read()
        except HTTPError as e:
            status = int(getattr(e, "code", 0) or 0)
            retryable = status in (429, 500, 502, 503, 504)
            if not retryable or attempt >= max_attempts:
                raise

            retry_after = None
            try:
                retry_after = e.headers.get("Retry-After")
            except Exception:
                retry_after = None

            sleep_s = base_backoff_s * (2 ** (attempt - 1))
            if isinstance(retry_after, str) and retry_after.isdigit():
                sleep_s = max(sleep_s, float(int(retry_after)))

            time.sleep(min(sleep_s, 10.0))
        except URLError:
            if attempt >= max_attempts:
                raise
            sleep_s = base_backoff_s * (2 ** (attempt - 1))
            time.sleep(min(sleep_s, 10.0))


class M365GraphMailIngestAdapter(MailIngestAdapter):
    """Mail ingestion adapter backed by Microsoft Graph."""

    def __init__(
        self,
        *,
        user_id: str,
        access_token_provider: Callable[[], str],
        folder_id: str = "Inbox",
        base_url: str = "https://graph.microsoft.com/v1.0",
        request_bytes: RequestBytesFn = _default_request_bytes,
    ) -> None:
        self._user_id = user_id
        self._folder_id = folder_id
        self._base_url = base_url.rstrip("/")
        self._access_token_provider = access_token_provider
        self._request_bytes = request_bytes
        self._received_at_cache: dict[str, datetime] = {}

    def _headers(self) -> dict[str, str]:
        token = self._access_token_provider()
        if not token:
            raise ValueError("access token provider returned empty token")
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def _get_json(self, url: str) -> dict:
        raw = self._request_bytes(url, self._headers())
        return json.loads(raw.decode("utf-8"))

    def list_message_refs(
        self, *, cursor: Optional[str], limit: int
    ) -> tuple[list[MessageRef], Optional[str]]:
        if limit <= 0:
            raise ValueError("limit must be positive")

        if cursor:
            url = cursor
        else:
            qs = urlencode({"$select": "id,receivedDateTime", "$top": str(limit)})
            url = (
                f"{self._base_url}/users/{self._user_id}"
                f"/mailFolders/{self._folder_id}/messages/delta?{qs}"
            )

        data = self._get_json(url)
        values = data.get("value", [])
        if not isinstance(values, list):
            raise ValueError("unexpected Graph delta response: value is not a list")

        refs: list[MessageRef] = []
        for item in values:
            if not isinstance(item, dict):
                continue
            if "@removed" in item:
                continue
            msg_id = item.get("id")
            if not isinstance(msg_id, str) or not msg_id:
                continue
            refs.append(MessageRef(source_message_id=msg_id))
            received = item.get("receivedDateTime")
            if isinstance(received, str) and received:
                self._received_at_cache[msg_id] = _parse_graph_datetime(received)

        next_link = data.get("@odata.nextLink")
        delta_link = data.get("@odata.deltaLink")

        if len(refs) >= limit and isinstance(next_link, str) and next_link:
            return refs[:limit], next_link
        if isinstance(next_link, str) and next_link:
            return refs, next_link
        if isinstance(delta_link, str) and delta_link:
            return refs, delta_link
        return refs, cursor

    def fetch_raw_mime(self, ref: MessageRef) -> bytes:
        url = f"{self._base_url}/users/{self._user_id}/messages/{ref.source_message_id}/$value"
        headers = self._headers()
        headers["Accept"] = "message/rfc822"
        return self._request_bytes(url, headers)

    def get_received_at(self, ref: MessageRef) -> datetime:
        cached = self._received_at_cache.get(ref.source_message_id)
        if cached is not None:
            return cached
        url = (
            f"{self._base_url}/users/{self._user_id}/messages/{ref.source_message_id}"
            "?$select=receivedDateTime"
        )
        data = self._get_json(url)
        received = data.get("receivedDateTime")
        if not isinstance(received, str) or not received:
            raise ValueError("missing receivedDateTime")
        dt = _parse_graph_datetime(received)
        self._received_at_cache[ref.source_message_id] = dt
        return dt

    def list_attachments(self, ref: MessageRef) -> Iterable[AttachmentRef]:
        url = (
            f"{self._base_url}/users/{self._user_id}/messages/{ref.source_message_id}"
            "/attachments?$select=id,name,contentType,size,@odata.type"
        )
        data = self._get_json(url)
        values = data.get("value", [])
        if not isinstance(values, list):
            raise ValueError("unexpected Graph attachments response: value is not a list")

        out: list[AttachmentRef] = []
        for item in values:
            if not isinstance(item, dict):
                continue
            odata_type = item.get("@odata.type")
            if odata_type and odata_type != "#microsoft.graph.fileAttachment":
                continue
            att_id = item.get("id")
            name = item.get("name")
            content_type = item.get("contentType")
            size = item.get("size")
            if not isinstance(att_id, str) or not att_id:
                continue
            if not isinstance(name, str) or not name:
                continue
            if not isinstance(content_type, str) or not content_type:
                continue
            if not isinstance(size, int) or size < 0:
                continue
            out.append(
                AttachmentRef(
                    attachment_id=f"{ref.source_message_id}:{att_id}",
                    filename=name,
                    mime_type=content_type,
                    size_bytes=size,
                )
            )
        return out

    def fetch_attachment_bytes(self, ref: AttachmentRef) -> bytes:
        if ":" not in ref.attachment_id:
            raise ValueError("invalid attachment reference: missing message prefix")
        message_id, attachment_id = ref.attachment_id.split(":", 1)
        url = (
            f"{self._base_url}/users/{self._user_id}/messages/{message_id}"
            f"/attachments/{attachment_id}"
        )
        data = self._get_json(url)
        odata_type = data.get("@odata.type")
        if odata_type and odata_type != "#microsoft.graph.fileAttachment":
            raise ValueError("unsupported attachment type")
        content = data.get("contentBytes")
        if not isinstance(content, str) or not content:
            raise ValueError("missing contentBytes")
        return base64.b64decode(content)

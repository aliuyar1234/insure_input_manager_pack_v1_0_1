from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class IdentityDirectoryError(RuntimeError):
    pass


class IdentityDirectoryDependencyError(IdentityDirectoryError):
    def __init__(self, *, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = int(status_code)


class IdentityDirectoryAuthError(IdentityDirectoryError):
    def __init__(self, *, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = int(status_code)


@dataclass(frozen=True)
class IdentityDirectoryClientConfig:
    base_url: str
    token_provider: Callable[[], str]
    http_timeout_seconds: int = 10


class IdentityDirectoryClient:
    def __init__(self, *, config: IdentityDirectoryClientConfig) -> None:
        self._cfg = config

    def _url(self, path: str, *, query: Optional[dict[str, str]] = None) -> str:
        base = self._cfg.base_url.rstrip("/")
        url = base + path
        if query:
            url += "?" + urlencode(query)
        return url

    def _request_json(self, *, method: str, url: str, body: Optional[bytes] = None) -> dict:
        token = self._cfg.token_provider()
        if not token:
            raise IdentityDirectoryAuthError(status_code=401, message="token provider returned empty token")

        headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"

        req = Request(url, headers=headers, data=body, method=method)
        try:
            with urlopen(req, timeout=self._cfg.http_timeout_seconds) as resp:
                raw = resp.read()
        except HTTPError as e:
            status = int(getattr(e, "code", 0) or 0)
            if status in (401, 403):
                raise IdentityDirectoryAuthError(status_code=status, message=f"identity directory auth failed: {status}") from e
            if status in (429, 503):
                raise IdentityDirectoryDependencyError(
                    status_code=status,
                    message=f"identity directory unavailable: {status}",
                ) from e
            raise IdentityDirectoryError(f"identity directory request failed: {status}") from e

        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise IdentityDirectoryError("identity directory response must be an object")
        return obj

    def search(self, *, request: dict) -> dict:
        url = self._url("/v1/identity/search")
        body = json.dumps(request, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return self._request_json(method="POST", url=url, body=body)

    def get_entity(self, *, entity_type: str, entity_id: str) -> dict:
        url = self._url(f"/v1/entities/{entity_type}/{entity_id}")
        return self._request_json(method="GET", url=url)


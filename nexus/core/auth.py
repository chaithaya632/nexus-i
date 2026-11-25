"""Stateful HTTP authentication and session refresh manager for authenticated scans."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from nexus.core.scope import ScopeEnforcer
from nexus.scanner._http import make_http_client, parse_url_target

log = logging.getLogger("nexus.core.auth")


def _extract_json_path(data: Any, path: str) -> str:
    """Resolve a dot-separated field like 'access_token' or 'data.token' from parsed JSON."""
    if not path:
        return ""
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return ""
    return str(cur).strip() if cur is not None else ""


class StatefulAuthSession:
    """Manages initial login, token extraction, cookie capture, and 401 session refresh."""

    def __init__(
        self,
        login_url: str | None = None,
        *,
        login_body: dict[str, Any] | None = None,
        token_field: str = "access_token",
        base_headers: dict[str, str] | None = None,
        refresh_callback: Callable[[], Awaitable[dict[str, str]] | dict[str, str]] | None = None,
        use_json: bool = True,
        timeout: float = 15.0,
    ) -> None:
        self.login_url = (login_url or "").strip() or None
        self.login_body = dict(login_body or {})
        self.token_field = token_field or "access_token"
        self.headers: dict[str, str] = dict(base_headers or {})
        self._refresh_callback = refresh_callback
        self.use_json = use_json
        self.timeout = timeout
        self.refresh_count = 0

    async def authenticate(self, scope: ScopeEnforcer | None = None) -> dict[str, str]:
        """Perform stateful login or refresh callback and return merged auth headers."""
        if self._refresh_callback is not None:
            res = self._refresh_callback()
            if hasattr(res, "__await__"):
                res = await res  # type: ignore[misc]
            if isinstance(res, dict):
                self.headers.update({str(k): str(v) for k, v in res.items() if k and v})
                self.refresh_count += 1
            return dict(self.headers)

        if not self.login_url:
            return dict(self.headers)

        host, port, _ = parse_url_target(self.login_url)
        if scope is not None:
            scope.enforce(host, port)

        async with make_http_client(
            headers=self.headers or None, timeout=self.timeout, follow_redirects=False
        ) as client:
            if self.use_json:
                resp = await client.post(self.login_url, json=self.login_body)
            else:
                resp = await client.post(self.login_url, data=self.login_body)

        if resp.status_code >= 400:
            log.warning("Stateful login POST %s returned HTTP %d", self.login_url, resp.status_code)
            return dict(self.headers)

        # 1. Extract session cookies if issued
        if resp.cookies:
            cookie_pairs = [f"{k}={v}" for k, v in resp.cookies.items()]
            if cookie_pairs:
                existing = self.headers.get("Cookie", "").strip()
                combined = (
                    f"{existing}; {'; '.join(cookie_pairs)}"
                    if existing
                    else "; ".join(cookie_pairs)
                )
                self.headers["Cookie"] = combined.strip("; ")

        # 2. Extract bearer/JWT token from JSON response body
        try:
            body_json = resp.json()
        except ValueError:
            body_json = None
        if isinstance(body_json, dict):
            token = ""
            for candidate in (self.token_field, "access_token", "token", "jwt", "id_token"):
                token = _extract_json_path(body_json, candidate)
                if token:
                    break
            if token:
                self.headers["Authorization"] = f"Bearer {token}"

        self.refresh_count += 1
        return dict(self.headers)

    async def refresh(self, scope: ScopeEnforcer | None = None) -> dict[str, str]:
        """Alias for refreshing expired credentials/cookies mid-engagement."""
        return await self.authenticate(scope=scope)

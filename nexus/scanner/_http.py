"""Shared HTTP parsing and header-redaction helpers for Wave 2 web/API scanners."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from nexus.recon.runner import validate_headers

_SENSITIVE_HEADER_KEYS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "api-key",
    }
)


def parse_url_target(url: str) -> tuple[str, int | None, str]:
    """Return (host, port, protocol) parsed from an HTTP/HTTPS URL."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    proto = parsed.scheme.lower() or "http"
    host = (parsed.hostname or "").strip().lower()
    port = parsed.port
    if port is None:
        port = 443 if proto == "https" else 80
    return host, port, proto


def redact_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Return a copy of headers with credential/token values redacted for safe logging."""
    if not headers:
        return {}
    out: dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower().strip()
        if kl in _SENSITIVE_HEADER_KEYS or any(
            tok in kl for tok in ("token", "secret", "auth", "key", "pass", "cookie")
        ):
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out


def _resolve_stealth_controller(stealth: Any | None = None) -> Any | None:
    """Resolve an explicit StealthController, level name, or active global controller."""
    if stealth is not None:
        if isinstance(stealth, str):
            try:
                from nexus.stealth.controller import StealthController

                return StealthController(stealth)
            except Exception:
                return None
        return stealth
    try:
        import nexus.stealth.controller as sc_mod

        getter = getattr(sc_mod, "get_active_stealth", None)
        if callable(getter):
            return getter()
    except Exception:
        pass
    return None


def make_http_client(
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    follow_redirects: bool = False,
    stealth: Any | None = None,
    verify: bool = False,
) -> httpx.AsyncClient:
    """Create a configured AsyncClient for non-destructive security probes.

    Note: ``verify=False`` is the default because authorized assessment targets
    frequently present self-signed or internal certificates; TLS trust and
    certificate hygiene are audited separately by ``nexus.scanner.tls``.
    Redirect following defaults to ``False`` to prevent credential leakage
    across cross-origin redirects.
    """
    clean_headers = validate_headers(headers)
    ctrl = _resolve_stealth_controller(stealth)

    merged: dict[str, str] = {}
    has_explicit_ua = any(k.lower() == "user-agent" for k in clean_headers)
    if not has_explicit_ua:
        ua = "NEXUS-Security-Scanner/1.0"
        if ctrl is not None:
            get_ua = getattr(ctrl, "get_user_agent", None)
            if callable(get_ua):
                ua = str(get_ua() or ua)
        merged["User-Agent"] = ua
    merged.update(clean_headers)

    event_hooks: dict[str, list[Any]] | None = None
    if ctrl is not None:
        throttle_fn = getattr(ctrl, "throttle", None)
        if callable(throttle_fn):

            async def _throttle_request(_request: httpx.Request) -> None:
                await throttle_fn()

            event_hooks = {"request": [_throttle_request]}

    return httpx.AsyncClient(
        headers=merged,
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        event_hooks=event_hooks,
    )

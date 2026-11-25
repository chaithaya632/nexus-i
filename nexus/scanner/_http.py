"""Shared HTTP parsing and header-redaction helpers for Wave 2 web/API scanners."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

_SENSITIVE_HEADER_KEYS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "api-key",
})


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
        if kl in _SENSITIVE_HEADER_KEYS or any(tok in kl for tok in ("token", "secret", "auth", "key", "pass", "cookie")):
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out


def make_http_client(
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    follow_redirects: bool = False,
) -> httpx.AsyncClient:
    """Create a configured AsyncClient for non-destructive security probes."""
    merged = {"User-Agent": "NEXUS-Security-Scanner/1.0"}
    if headers:
        merged.update(headers)
    return httpx.AsyncClient(
        headers=merged,
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=False,  # Assessment targets frequently use self-signed/internal certs
    )

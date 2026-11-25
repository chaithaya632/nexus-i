"""Verified HTTP security header, CORS, CSP, and cookie flag auditor."""

from __future__ import annotations

import logging
from typing import Mapping

from nexus.db.models import Finding, Severity
from nexus.scanner._http import make_http_client, parse_url_target

log = logging.getLogger("nexus.scanner.headers")

_TEST_CORS_ORIGIN = "https://untrusted.nexus.invalid"
_SENSITIVE_COOKIE_HINTS = ("session", "sess", "sid", "token", "jwt", "auth", "csrf")


def _hdr_get(headers: Mapping[str, str], name: str) -> str:
    """Case-insensitive header getter."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return ""


def analyze_security_headers(
    url: str,
    resp_headers: Mapping[str, str],
    *,
    cors_headers: Mapping[str, str] | None = None,
    tested_origin: str = _TEST_CORS_ORIGIN,
    set_cookies: list[str] | None = None,
) -> list[Finding]:
    """Analyze HTTP response headers for CORS, CSP, HSTS, framing, and cookie weaknesses."""
    host, port, proto = parse_url_target(url)
    findings: list[Finding] = []

    # 1. CORS reflection & wildcard+credentials checks
    cors_src = cors_headers if cors_headers is not None else resp_headers
    acao = _hdr_get(cors_src, "access-control-allow-origin").strip()
    acac = _hdr_get(cors_src, "access-control-allow-credentials").strip().lower()
    if acao == "*" and acac == "true":
        findings.append(Finding(
            host=host, port=port, protocol=proto,
            title="CORS: Wildcard Origin With Credentials Enabled",
            description=f"{url} returns Access-Control-Allow-Origin: * alongside Allow-Credentials: true.",
            severity=Severity.HIGH, cwe_id="CWE-942",
            tool_source="http_headers", confirmed=True,
            evidence=f"URL: {url}\nACAO: {acao}\nACAC: {acac}",
        ))
    elif acao == tested_origin:
        findings.append(Finding(
            host=host, port=port, protocol=proto,
            title=(
                "CORS: Arbitrary Origin Reflected With Credentials"
                if acac == "true" else
                "CORS: Arbitrary Untrusted Origin Reflected"
            ),
            description=f"{url} reflects untrusted Origin '{tested_origin}' in Access-Control-Allow-Origin.",
            severity=Severity.HIGH if acac == "true" else Severity.MEDIUM,
            cwe_id="CWE-942",
            tool_source="http_headers", confirmed=True,
            evidence=f"URL: {url}\nOrigin: {tested_origin}\nACAO: {acao}\nACAC: {acac or 'false'}",
        ))

    ctype = _hdr_get(resp_headers, "content-type").lower()
    is_html = "text/html" in ctype

    # 2. HSTS on HTTPS
    if proto == "https" and not _hdr_get(resp_headers, "strict-transport-security"):
        findings.append(Finding(
            host=host, port=port, protocol=proto,
            title="HTTP: Missing Strict-Transport-Security (HSTS) Header",
            description=f"HTTPS endpoint {url} does not enforce HSTS.",
            severity=Severity.LOW, cwe_id="CWE-523",
            tool_source="http_headers", confirmed=True,
            evidence=f"URL: {url} (Strict-Transport-Security absent)",
        ))

    # 3. Content-Security-Policy (missing or weak directives on HTML)
    csp = _hdr_get(resp_headers, "content-security-policy")
    if is_html and not csp:
        findings.append(Finding(
            host=host, port=port, protocol=proto,
            title="HTTP: Missing Content-Security-Policy (CSP) Header",
            description=f"HTML response from {url} lacks a Content-Security-Policy header.",
            severity=Severity.LOW, cwe_id="CWE-693",
            tool_source="http_headers", confirmed=True,
            evidence=f"URL: {url} (Content-Security-Policy absent)",
        ))
    elif csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp):
        findings.append(Finding(
            host=host, port=port, protocol=proto,
            title="HTTP: Permissive Content-Security-Policy (unsafe-inline / unsafe-eval)",
            description=f"{url} allows unsafe inline or eval execution in its Content-Security-Policy.",
            severity=Severity.LOW, cwe_id="CWE-693",
            tool_source="http_headers", confirmed=True,
            evidence=f"URL: {url}\nCSP: {csp[:300]}",
        ))

    # 4. Clickjacking protection
    xfo = _hdr_get(resp_headers, "x-frame-options")
    has_frame_ancestors = "frame-ancestors" in csp.lower() if csp else False
    if is_html and not xfo and not has_frame_ancestors:
        findings.append(Finding(
            host=host, port=port, protocol=proto,
            title="HTTP: Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
            description=f"HTML response from {url} sets neither X-Frame-Options nor CSP frame-ancestors.",
            severity=Severity.LOW, cwe_id="CWE-1021",
            tool_source="http_headers", confirmed=True,
            evidence=f"URL: {url}",
        ))

    # 5. MIME sniffing protection
    if _hdr_get(resp_headers, "x-content-type-options").lower() != "nosniff":
        findings.append(Finding(
            host=host, port=port, protocol=proto,
            title="HTTP: Missing X-Content-Type-Options: nosniff",
            description=f"Response from {url} lacks X-Content-Type-Options: nosniff.",
            severity=Severity.INFO, cwe_id="CWE-693",
            tool_source="http_headers", confirmed=True,
            evidence=f"URL: {url}",
        ))

    # 6. Cookie security flags (parse semicolon-delimited attribute tokens)
    cookie_lines = list(set_cookies or [])
    single_sc = _hdr_get(resp_headers, "set-cookie")
    if single_sc and not cookie_lines:
        cookie_lines.append(single_sc)
    for sc in cookie_lines:
        parts = [p.strip() for p in sc.split(";") if p.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip().lower()
        attrs: dict[str, str] = {}
        for attr in parts[1:]:
            if "=" in attr:
                ak, av = attr.split("=", 1)
                attrs[ak.strip().lower()] = av.strip().lower()
            else:
                attrs[attr.strip().lower()] = ""

        if any(h in name for h in _SENSITIVE_COOKIE_HINTS):
            missing_flags = []
            if "httponly" not in attrs:
                missing_flags.append("HttpOnly")
            if proto == "https" and "secure" not in attrs:
                missing_flags.append("Secure")
            samesite = attrs.get("samesite", "")
            if samesite not in ("strict", "lax", "none"):
                missing_flags.append("SameSite")
            elif samesite == "none" and "secure" not in attrs and "Secure" not in missing_flags:
                missing_flags.append("Secure")
            if missing_flags:
                findings.append(Finding(
                    host=host, port=port, protocol=proto,
                    title=f"HTTP: Session Cookie Missing Security Flag(s) ({', '.join(missing_flags)})",
                    description=f"Sensitive cookie '{name}' from {url} is missing {', '.join(missing_flags)}.",
                    severity=Severity.MEDIUM, cwe_id="CWE-1004",
                    tool_source="http_headers", confirmed=True,
                    evidence=f"URL: {url}\nCookie name: {name}\nMissing: {', '.join(missing_flags)}",
                ))

    return findings


async def audit_http_security(
    urls: list[str],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> list[Finding]:
    """Perform live non-destructive CORS, CSP, HSTS, header, and cookie checks on URLs."""
    if not urls:
        return []

    findings: list[Finding] = []
    seen_keys: set[tuple[str, int | None, str, str]] = set()

    async with make_http_client(headers=headers, timeout=timeout) as client:
        for url in urls[:8]:
            try:
                resp = await client.get(url, follow_redirects=False)
            except Exception as exc:
                log.debug("HTTP security probe failed for %s: %s", url, exc)
                continue

            cors_hdrs: Mapping[str, str] | None = None
            try:
                cors_resp = await client.get(url, headers={"Origin": _TEST_CORS_ORIGIN}, follow_redirects=False)
                cors_hdrs = cors_resp.headers
            except Exception:
                pass

            resp_url = str(resp.url)
            set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else None
            url_findings = analyze_security_headers(
                resp_url,
                resp.headers,
                cors_headers=cors_hdrs,
                tested_origin=_TEST_CORS_ORIGIN,
                set_cookies=set_cookies,
            )
            for f in url_findings:
                dedup_key = (f.host, f.port, resp_url, f.title)
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    findings.append(f)

    log.info("HTTP security header audit: %d verified findings across %d URL(s)", len(findings), min(len(urls), 8))
    return findings

"""SPA/JS endpoint discovery and passive exposed-secret scanner (`katana` + Python fallback)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner
from nexus.scanner._http import make_http_client, parse_url_target

log = logging.getLogger("nexus.scanner.crawler")

_STEALTH_CRAWL: dict[str, tuple[int, int, float]] = {
    "loud": (25, 150, 0.0),
    "normal": (10, 60, 0.05),
    "quiet": (4, 20, 0.25),
    "ghost": (1, 5, 1.0),
}

# Patterns to extract API/endpoint strings from JS bundles and HTML
_JS_ENDPOINT_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|open)\(\s*['"`]((?:/|https?://)[^'"`\s]{2,140})['"`]"""
    r"""|['"`](/(?:api|v[1-9]|graphql|auth|admin|oauth|rest)[A-Za-z0-9_\-/{}.?=&]{0,120})['"`]""",
    re.IGNORECASE,
)

# Passive detection patterns for accidentally exposed secrets in client-side JS/HTML
_SECRET_RULES: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("AWS Access Key ID", Severity.HIGH, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API Key", Severity.MEDIUM, re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Stripe Live Secret Key", Severity.CRITICAL, re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("Slack API Token", Severity.HIGH, re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b")),
    ("PEM Private Key Material", Severity.CRITICAL, re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Hardcoded JWT Token", Severity.MEDIUM, re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")),
    (
        "Hardcoded Secret/API Credential",
        Severity.MEDIUM,
        re.compile(
            r"""(?i)\b[a-z0-9_]*(?:api_?key|client_?secret|auth_?token|secret_?key)\b\s*[:=]\s*['"]([A-Za-z0-9_\-\.+/=]{16,80})['"]"""
        ),
    ),
]

_PLACEHOLDER_HINTS = ("example", "placeholder", "changeme", "your_", "xxxxxx", "dummy")


def _mask_secret(raw: str) -> str:
    if len(raw) <= 10:
        return "*" * len(raw)
    return f"{raw[:6]}...{raw[-4:]}"


class _HtmlLinkExtractor(HTMLParser):
    """Lightweight HTML link/script/form extractor using Python stdlib."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        if tag in ("a", "link") and attr_map.get("href"):
            self.links.append(attr_map["href"] or "")
        elif tag == "form" and attr_map.get("action"):
            self.links.append(attr_map["action"] or "")
        elif tag == "script" and attr_map.get("src"):
            src = attr_map["src"] or ""
            self.scripts.append(src)
            self.links.append(src)


def extract_js_endpoints_and_secrets(
    content: str,
    source_url: str,
    *,
    allowed_host: str = "",
) -> tuple[list[str], list[Finding]]:
    """Extract same-host endpoints and detect accidentally exposed client-side secrets."""
    host, port, proto = parse_url_target(source_url)
    scope_host = (allowed_host or host).lower()

    endpoints: list[str] = []
    seen_ep: set[str] = set()
    for m in _JS_ENDPOINT_RE.finditer(content):
        raw_ep = m.group(1) or m.group(2)
        if not raw_ep:
            continue
        resolved = urljoin(source_url, raw_ep)
        parsed = urlparse(resolved)
        if parsed.scheme in ("http", "https") and (parsed.hostname or "").lower() == scope_host:
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean += f"?{parsed.query}"
            if clean not in seen_ep:
                seen_ep.add(clean)
                endpoints.append(clean)

    findings: list[Finding] = []
    seen_secrets: set[tuple[str, str]] = set()
    for label, sev, pattern in _SECRET_RULES:
        for match in pattern.finditer(content):
            val = match.group(1) if match.lastindex else match.group(0)
            if not val or any(ph in val.lower() for ph in _PLACEHOLDER_HINTS):
                continue
            masked = _mask_secret(val)
            key = (label, masked)
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            findings.append(Finding(
                host=host,
                port=port,
                protocol=proto,
                title=f"Client-Side Secret Exposed: {label}",
                description=(
                    f"Passive analysis detected a potential {label} embedded in response from {source_url}."
                ),
                severity=sev,
                cwe_id="CWE-798",
                tool_source="crawler",
                evidence=f"Source: {source_url}\nMatch (masked): {masked}",
                confirmed=True,
            ))

    return endpoints, findings


async def _katana_crawl(
    target_url: str,
    *,
    max_depth: int,
    stealth: str,
    headers: dict[str, str] | None,
    timeout: int,
) -> list[str]:
    """Run ProjectDiscovery katana and return discovered URLs."""
    conc, rate, _ = _STEALTH_CRAWL.get(stealth, _STEALTH_CRAWL["normal"])
    args = [
        "-u", target_url,
        "-d", str(max_depth),
        "-jc",
        "-kf", "all",
        "-jsonl",
        "-silent",
        "-c", str(conc),
        "-rl", str(rate),
    ]
    if headers:
        for k, v in headers.items():
            args.extend(["-H", f"{k}: {v}"])

    out = await ToolRunner.run("katana", args, timeout=timeout)
    urls: list[str] = []
    seen: set[str] = set()
    for line in out.lines:
        ep = ""
        try:
            rec = json.loads(line)
            ep = (rec.get("request") or {}).get("endpoint") or rec.get("endpoint") or ""
        except json.JSONDecodeError:
            if line.strip().startswith(("http://", "https://")):
                ep = line.strip()
        if ep and ep not in seen:
            seen.add(ep)
            urls.append(ep)
    return urls


async def crawl_web(
    target_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 35,
    stealth: str = "normal",
    headers: dict[str, str] | None = None,
    timeout: int = 120,
) -> tuple[list[str], list[Finding]]:
    """Crawl a web/SPA target via `katana` (if available) + Python HTML/JS asset inspection.

    Returns (discovered_urls, secret_exposure_findings).
    """
    base_host, _, _ = parse_url_target(target_url)
    discovered: list[str] = []
    seen_urls: set[str] = set()
    findings: list[Finding] = []
    _, _, delay_s = _STEALTH_CRAWL.get(stealth, _STEALTH_CRAWL["normal"])

    def _add_url(u: str) -> bool:
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https") or (parsed.hostname or "").lower() != base_host:
            return False
        norm = u.split("#", 1)[0]
        if norm not in seen_urls:
            seen_urls.add(norm)
            discovered.append(norm)
            return True
        return False

    _add_url(target_url)

    js_to_scan: list[str] = []
    if ToolRunner.is_available("katana"):
        kat_urls = await _katana_crawl(
            target_url, max_depth=max_depth, stealth=stealth, headers=headers, timeout=timeout
        )
        for ku in kat_urls:
            _add_url(ku)
            if ku.lower().split("?", 1)[0].endswith(".js") and len(js_to_scan) < 15:
                js_to_scan.append(ku)

    # Pure-Python HTTP crawl + JS/HTML inspection (runs as fallback when katana absent, or scans JS assets)
    try:
        async with make_http_client(headers=headers, timeout=10.0) as client:
            if ToolRunner.is_available("katana") and discovered:
                queue: deque[tuple[str, int]] = deque((u, max_depth) for u in js_to_scan)
            else:
                queue = deque([(target_url, 0)])

            visited: set[str] = set()
            while queue and len(visited) < max_pages:
                cur_url, depth = queue.popleft()
                if cur_url in visited:
                    continue
                visited.add(cur_url)

                if delay_s > 0 and len(visited) > 1:
                    await asyncio.sleep(delay_s)

                try:
                    resp = await client.get(cur_url)
                except Exception as exc:
                    log.debug("Crawler request failed for %s: %s", cur_url, exc)
                    continue

                ctype = (resp.headers.get("content-type") or "").lower()
                text = resp.text or ""
                if not text:
                    continue

                if "javascript" in ctype or cur_url.lower().split("?", 1)[0].endswith(".js") or "html" in ctype:
                    js_eps, sec_findings = extract_js_endpoints_and_secrets(
                        text, cur_url, allowed_host=base_host
                    )
                    findings.extend(sec_findings)
                    for ep in js_eps:
                        _add_url(ep)

                if "html" in ctype and depth < max_depth:
                    extractor = _HtmlLinkExtractor()
                    try:
                        extractor.feed(text)
                    except Exception:
                        continue
                    for rel in extractor.links:
                        resolved = urljoin(cur_url, rel)
                        if _add_url(resolved):
                            next_depth = depth if rel in extractor.scripts else depth + 1
                            if next_depth <= max_depth and resolved not in visited:
                                queue.append((resolved, next_depth))
    except Exception as exc:
        log.warning("Crawler fallback error on %s: %s", target_url, exc)

    log.info(
        "Web crawl for %s: %d endpoint(s), %d JS secret finding(s)",
        target_url, len(discovered), len(findings),
    )
    return discovered, findings

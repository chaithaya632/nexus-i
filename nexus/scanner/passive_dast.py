"""Passive Web/API DAST checks: HTML/form/DOM-sink rules, GraphQL introspection, and Auth-Diff."""

from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from nexus.db.models import Finding, Severity
from nexus.scanner._http import make_http_client, parse_url_target

log = logging.getLogger("nexus.scanner.passive_dast")

_CSRF_TOKEN_HINTS = (
    "csrf",
    "xsrf",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "nonce",
)
_DOM_SINK_RE = re.compile(
    r"(?:\.(?:innerHTML|outerHTML)\s*=|dangerouslySetInnerHTML\b|\bdocument\.write\s*\(|\beval\s*\()"
)
_PUBLIC_PATH_HINTS = (
    "/login",
    "/logout",
    "/signin",
    "/signup",
    "/register",
    "/health",
    "/status",
    "/metrics",
    "/swagger",
    "/openapi",
    "/api-docs",
    "/redoc",
    "/robots.txt",
    "/favicon.ico",
    "/.well-known",
)
_STATIC_EXTS = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".map",
)


class _PassiveHtmlInspector(HTMLParser):
    """Extract forms, external scripts, iframes, and target=_blank links for passive security analysis."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._cur_form: dict | None = None
        self.scripts: list[dict[str, str]] = []
        self.iframes: list[str] = []
        self.blank_links: list[dict[str, str]] = []
        self._in_script = False
        self.inline_scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        amap = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "form":
            self._cur_form = {
                "action": amap.get("action", ""),
                "method": (amap.get("method", "get") or "get").lower().strip(),
                "has_password": False,
                "input_names": [],
            }
        elif t == "input" and self._cur_form is not None:
            itype = (amap.get("type", "text") or "text").lower().strip()
            iname = (amap.get("name", "") or "").lower().strip()
            if itype == "password":
                self._cur_form["has_password"] = True
            if iname:
                self._cur_form["input_names"].append(iname)
        elif t == "script":
            src = amap.get("src", "")
            if src:
                self.scripts.append({"src": src, "integrity": amap.get("integrity", "")})
            else:
                self._in_script = True
        elif t == "iframe" and amap.get("src"):
            self.iframes.append(amap["src"])
        elif t == "a" and amap.get("target", "").lower() == "_blank":
            self.blank_links.append(
                {"href": amap.get("href", ""), "rel": amap.get("rel", "").lower()}
            )

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None
        elif t == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.inline_scripts.append(data)


def analyze_html_passive(
    url: str,
    body: str,
    content_type: str = "text/html",
) -> list[Finding]:
    """Run non-destructive OWASP ZAP-style passive checks on already-fetched HTML or JS content."""
    if not body:
        return []
    host, port, proto = parse_url_target(url)
    ct = (content_type or "").lower()
    is_js = "javascript" in ct or url.lower().split("?", 1)[0].endswith(".js")
    is_html = "html" in ct or body.lstrip()[:200].lower().startswith(("<!doctype", "<html"))

    findings: list[Finding] = []
    seen_titles: set[str] = set()

    def _emit(
        title: str,
        desc: str,
        sev: Severity,
        cwe: str,
        evidence: str,
        *,
        confirmed: bool = True,
    ) -> None:
        if title in seen_titles:
            return
        seen_titles.add(title)
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol=proto,
                title=title,
                description=desc,
                severity=sev,
                cwe_id=cwe,
                tool_source="passive_dast",
                evidence=evidence,
                confirmed=confirmed,
            )
        )

    if is_html:
        parser = _PassiveHtmlInspector()
        try:
            parser.feed(body)
        except Exception:
            parser = _PassiveHtmlInspector()

        for form in parser.forms:
            resolved_action = urljoin(url, form["action"]) if form["action"] else url
            if form["has_password"] and (
                proto == "http" or resolved_action.lower().startswith("http://")
            ):
                _emit(
                    "Cleartext Password Submission Over HTTP",
                    f"Password input on {url} submits over unencrypted HTTP ({resolved_action}).",
                    Severity.HIGH,
                    "CWE-319",
                    f"URL: {url}\nForm action: {resolved_action}",
                )
            if form["method"] == "post":
                has_csrf = any(
                    any(h in name for h in _CSRF_TOKEN_HINTS) for name in form["input_names"]
                )
                if not has_csrf:
                    _emit(
                        "POST Form Missing Anti-CSRF Token Field",
                        f"POST form at {url} (action={resolved_action}) has no recognizable CSRF token input.",
                        Severity.LOW,
                        "CWE-352",
                        f"URL: {url}\nAction: {resolved_action}",
                    )

        for sc in parser.scripts:
            resolved_src = urljoin(url, sc["src"])
            parsed_src = urlparse(resolved_src)
            src_host = (parsed_src.hostname or "").lower()
            if proto == "https" and parsed_src.scheme == "http":
                _emit(
                    "Mixed Active Content: HTTP Script on HTTPS Page",
                    f"HTTPS page {url} loads script over plaintext HTTP ({resolved_src}).",
                    Severity.MEDIUM,
                    "CWE-319",
                    f"URL: {url}\nScript: {resolved_src}",
                )
            elif (
                parsed_src.scheme == "https"
                and src_host
                and src_host != host
                and not sc["integrity"].strip()
            ):
                _emit(
                    "External Script Missing Subresource Integrity (SRI)",
                    f"Third-party script {resolved_src} loaded by {url} lacks an 'integrity' attribute.",
                    Severity.LOW,
                    "CWE-353",
                    f"URL: {url}\nExternal script: {resolved_src}",
                )

        if proto == "https":
            for iframe_src in parser.iframes:
                resolved_if = urljoin(url, iframe_src)
                if resolved_if.lower().startswith("http://"):
                    _emit(
                        "Mixed Content: HTTP Iframe on HTTPS Page",
                        f"HTTPS page {url} embeds insecure iframe ({resolved_if}).",
                        Severity.MEDIUM,
                        "CWE-319",
                        f"URL: {url}\nIframe: {resolved_if}",
                    )

        for lnk in parser.blank_links:
            if "noopener" not in lnk["rel"] and "noreferrer" not in lnk["rel"]:
                _emit(
                    "Reverse Tabnabbing Risk (target=_blank Without rel=noopener)",
                    f"Link on {url} opens a new tab without rel='noopener' or rel='noreferrer'.",
                    Severity.INFO,
                    "CWE-1022",
                    f"URL: {url}\nHref: {lnk['href']}",
                )

        for snippet in parser.inline_scripts:
            m = _DOM_SINK_RE.search(snippet)
            if m:
                _emit(
                    "Client-Side DOM Sink Audit Candidate",
                    f"Inline script on {url} uses risky DOM sink '{m.group(0).strip()}'.",
                    Severity.INFO,
                    "CWE-79",
                    f"URL: {url}\nSink: {m.group(0).strip()}",
                    confirmed=False,
                )

    if is_js:
        m = _DOM_SINK_RE.search(body)
        if m:
            _emit(
                "Client-Side DOM Sink Audit Candidate",
                f"JavaScript asset {url} references DOM sink '{m.group(0).strip()}'.",
                Severity.INFO,
                "CWE-79",
                f"URL: {url}\nSink: {m.group(0).strip()}",
                confirmed=False,
            )

    return findings


async def audit_graphql_introspection(
    urls: list[str],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 6.0,
) -> list[Finding]:
    """Read-only check for enabled GraphQL `__schema` introspection on discovered or default routes."""
    if not urls:
        return []

    candidates: list[str] = []
    seen_candidates: set[str] = set()
    for u in urls:
        clean = u.split("#", 1)[0].rstrip("/")
        if "graphql" in clean.lower():
            if clean not in seen_candidates:
                seen_candidates.add(clean)
                candidates.append(clean)
    # Also probe root /graphql and /api/graphql derived from base origins
    for u in urls[:3]:
        p = urlparse(u)
        if p.scheme in ("http", "https") and p.netloc:
            root = f"{p.scheme}://{p.netloc}"
            for suffix in ("/graphql", "/api/graphql"):
                ep = f"{root}{suffix}"
                if ep not in seen_candidates:
                    seen_candidates.add(ep)
                    candidates.append(ep)

    query = {"query": "{ __schema { queryType { name } } }"}
    findings: list[Finding] = []
    seen_hosts: set[tuple[str, int | None, str]] = set()
    async with make_http_client(headers=headers, timeout=timeout) as client:
        for ep in candidates[:6]:
            try:
                resp = await client.post(ep, json=query, follow_redirects=False)
            except Exception:
                continue
            ctype = (resp.headers.get("content-type") or "").lower()
            if resp.status_code != 200 or "text/html" in ctype:
                continue
            txt = resp.text or ""
            if '"__schema"' in txt and '"queryType"' in txt:
                host, port, proto = parse_url_target(ep)
                key = (host, port, ep)
                if key in seen_hosts:
                    continue
                seen_hosts.add(key)
                findings.append(
                    Finding(
                        host=host,
                        port=port,
                        protocol=proto,
                        title="GraphQL Schema Introspection Enabled",
                        description=f"GraphQL endpoint {ep} permits unauthenticated/full __schema introspection.",
                        severity=Severity.LOW,
                        cwe_id="CWE-200",
                        tool_source="graphql_probe",
                        confirmed=True,
                        evidence=f"POST {ep} -> {txt[:250]}",
                    )
                )
    return findings


async def audit_auth_enforcement(
    urls: list[str],
    auth_headers: dict[str, str] | None,
    *,
    timeout: float = 6.0,
) -> list[Finding]:
    """Compare authenticated vs unauthenticated GET responses on API routes (OWASP API1/API5 posture)."""
    if not auth_headers or not urls:
        return []

    candidates: list[str] = []
    for u in urls:
        parsed = urlparse(u)
        path_l = (parsed.path or "/").lower()
        if path_l in ("", "/"):
            continue
        if any(path_l.endswith(ext) for ext in _STATIC_EXTS):
            continue
        if any(hint in path_l for hint in _PUBLIC_PATH_HINTS):
            continue
        if u not in candidates:
            candidates.append(u)

    findings: list[Finding] = []
    seen_urls: set[str] = set()
    async with (
        make_http_client(headers=auth_headers, timeout=timeout) as auth_cli,
        make_http_client(headers=None, timeout=timeout) as unauth_cli,
    ):
        for url in candidates[:8]:
            try:
                r_auth = await auth_cli.get(url, follow_redirects=False)
            except Exception:
                continue
            ct_auth = (r_auth.headers.get("content-type") or "").lower()
            body_auth = (r_auth.text or "").strip()
            if r_auth.status_code != 200 or len(body_auth) < 10:
                continue
            is_api_payload = "json" in ct_auth or body_auth.startswith(("{", "["))
            if not is_api_payload and "text/html" in ct_auth:
                continue

            try:
                r_unauth = await unauth_cli.get(url, follow_redirects=False)
            except Exception:
                continue
            if r_unauth.status_code != 200:
                continue
            body_unauth = (r_unauth.text or "").strip()
            if not body_unauth:
                continue

            ratio = SequenceMatcher(None, body_auth[:1000], body_unauth[:1000]).ratio()
            if ratio >= 0.85 and url not in seen_urls:
                seen_urls.add(url)
                host, port, proto = parse_url_target(url)
                findings.append(
                    Finding(
                        host=host,
                        port=port,
                        protocol=proto,
                        title="API Endpoint Accessible Without Authentication",
                        description=(
                            f"GET {url} returned HTTP 200 with matching payload content when auth_headers were stripped."
                        ),
                        severity=Severity.HIGH,
                        cwe_id="CWE-306",
                        tool_source="auth_diff",
                        confirmed=True,
                        evidence=f"URL: {url}\nAuthenticated vs unauthenticated similarity: {ratio:.2f}",
                    )
                )
    return findings

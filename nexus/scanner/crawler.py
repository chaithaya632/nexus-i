"""SPA/JS endpoint discovery and passive exposed-secret scanner (`katana` + Python fallback)."""

from __future__ import annotations

import asyncio
import contextlib
import glob
import importlib.util
import json
import logging
import os
import re
import shutil
import tempfile
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner, validate_cli_target, validate_headers
from nexus.scanner._http import make_http_client, parse_url_target
from nexus.scanner.passive_dast import analyze_html_passive

log = logging.getLogger("nexus.scanner.crawler")

_MAX_CRAWL_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB per response cap

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
    (
        "PEM Private Key Material",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "Hardcoded JWT Token",
        Severity.MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"),
    ),
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
    allowed_scheme: str = "",
    allowed_port: int | None = None,
) -> tuple[list[str], list[Finding]]:
    """Extract same-origin endpoints and detect accidentally exposed client-side secrets."""
    host, port, proto = parse_url_target(source_url)
    scope_host = (allowed_host or host).lower()
    scope_scheme = (allowed_scheme or proto).lower()
    scope_port = int(
        allowed_port
        if allowed_port is not None
        else (port or (443 if scope_scheme == "https" else 80))
    )
    bounded = (content or "")[:_MAX_CRAWL_BODY_BYTES]

    endpoints: list[str] = []
    seen_ep: set[str] = set()
    for m in _JS_ENDPOINT_RE.finditer(bounded):
        raw_ep = m.group(1) or m.group(2)
        if not raw_ep:
            continue
        resolved = urljoin(source_url, raw_ep)
        parsed = urlparse(resolved)
        if _is_same_target_origin(
            resolved, base_scheme=scope_scheme, base_host=scope_host, base_port=scope_port
        ):
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean += f"?{parsed.query}"
            if clean not in seen_ep:
                seen_ep.add(clean)
                endpoints.append(clean)

    findings: list[Finding] = []
    seen_secrets: set[tuple[str, str]] = set()
    for label, sev, pattern in _SECRET_RULES:
        for match in pattern.finditer(bounded):
            val = match.group(1) if match.lastindex else match.group(0)
            if not val or any(ph in val.lower() for ph in _PLACEHOLDER_HINTS):
                continue
            masked = _mask_secret(val)
            key = (label, masked)
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            findings.append(
                Finding(
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
                )
            )

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
    clean_target = validate_cli_target(target_url, label="target_url")
    clean_headers = validate_headers(headers)
    conc, rate, _ = _STEALTH_CRAWL.get(stealth, _STEALTH_CRAWL["normal"])
    args = [
        "-u",
        clean_target,
        "-d",
        str(max_depth),
        "-jc",
        "-kf",
        "all",
        "-fs",
        "fqdn",
        "-jsonl",
        "-silent",
        "-c",
        str(conc),
        "-rl",
        str(rate),
    ]
    if clean_headers:
        for k, v in clean_headers.items():
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


_DEFAULT_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "api-key",
    }
)


def _protected_header_names(headers: dict[str, str] | None) -> set[str]:
    return set(_DEFAULT_SENSITIVE_HEADERS) | {k.lower() for k in (headers or {})}


def _normalized_origin(parsed) -> tuple[str, str, int]:
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    return scheme, host, port


def _is_same_target_origin(url: str, *, base_scheme: str, base_host: str, base_port: int) -> bool:
    p = urlparse(url)
    if (p.scheme or "").lower() not in ("http", "https"):
        return False
    try:
        origin = _normalized_origin(p)
    except ValueError:
        return False
    return origin == (base_scheme.lower(), base_host.lower(), int(base_port))


def _make_url_keeper(base_host: str, base_scheme: str = "http", base_port: int = 80):
    discovered: list[str] = []
    seen: set[str] = set()
    eff_scheme = (base_scheme or "http").lower()
    eff_port = int(base_port or (443 if eff_scheme == "https" else 80))

    def _keep(u: str) -> bool:
        if not _is_same_target_origin(
            u, base_scheme=eff_scheme, base_host=base_host, base_port=eff_port
        ):
            return False
        p = urlparse(u)
        if p.path == "/favicon.ico":
            return False
        norm = u.split("#", 1)[0]
        if norm not in seen:
            seen.add(norm)
            discovered.append(norm)
            return True
        return False

    return discovered, _keep


def _process_dom_snapshot(
    cur: str,
    html: str,
    dom_links: list[str] | None,
    *,
    base_host: str,
    base_scheme: str = "",
    base_port: int | None = None,
    findings: list[Finding],
    keep_fn,
    visited: set[str],
    queue: deque[str],
) -> None:
    if html:
        js_eps, sec_f = extract_js_endpoints_and_secrets(
            html,
            cur,
            allowed_host=base_host,
            allowed_scheme=base_scheme,
            allowed_port=base_port,
        )
        findings.extend(sec_f)
        findings.extend(analyze_html_passive(cur, html, content_type="text/html"))
        for ep in js_eps:
            if keep_fn(ep) and ep not in visited:
                queue.append(ep)
    for rel in dom_links or []:
        if rel:
            resolved = urljoin(cur, str(rel))
            if keep_fn(resolved) and resolved not in visited:
                queue.append(resolved)


def _find_chromium_binary() -> str | None:
    """Locate an installed Chromium, Chrome, or Edge binary for optional CDP SPA crawling."""
    for name in ("chromium", "chromium-browser", "google-chrome", "chrome", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    if os.name == "nt":
        win_candidates = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        ]
        for path in win_candidates:
            if path and Path(path).is_file():
                return path
    else:
        for pat in (
            str(Path.home() / ".cache/ms-playwright/chromium-*/chrome-linux*/chrome"),
            str(
                Path.home()
                / ".cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell*/chrome-headless-shell"
            ),
        ):
            for match in sorted(glob.glob(pat)):
                p = Path(match)
                if p.is_file() and os.access(p, os.X_OK):
                    return str(p)
    return None


def _playwright_driver_ready() -> bool:
    """Return True unless Playwright's bundled/distro JS driver path is visibly missing."""
    try:
        from playwright._impl._driver import compute_driver_executable
    except Exception:
        return True  # Mocked or custom playwright package without _impl._driver
    try:
        node_bin, cli_js = compute_driver_executable()
        return Path(str(node_bin)).exists() and Path(str(cli_js)).exists()
    except Exception:
        return False


async def _playwright_browser_crawl(
    target_url: str,
    *,
    max_pages: int = 8,
    headers: dict[str, str] | None = None,
    timeout: int = 25,
) -> tuple[list[str], list[Finding]]:
    """Playwright Chromium SPA crawl with strict same-host auth & redirect isolation."""
    if importlib.util.find_spec("playwright") is None or not _playwright_driver_ready():
        return [], []

    try:
        from playwright.async_api import async_playwright
    except Exception as exc:
        log.debug("CDP pre-connect probe skipped for %s: %s", target_url, exc)
        return [], []

    base_host, base_port, base_proto = parse_url_target(target_url)
    discovered, _keep = _make_url_keeper(base_host, base_proto, base_port)
    findings: list[Finding] = []
    protected_hdr_names = _protected_header_names(headers)

    _keep(target_url)
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                ctx_kwargs: dict[str, object] = {"ignore_https_errors": True}
                if headers:
                    ctx_kwargs["extra_http_headers"] = dict(headers)
                context = await browser.new_context(**ctx_kwargs)

                queue: deque[str] = deque([target_url])
                visited: set[str] = set()

                async def _route_guard(route) -> None:
                    req = route.request
                    parsed_req = urlparse(req.url)
                    scheme = parsed_req.scheme.lower()
                    if scheme not in ("http", "https"):
                        await route.abort()
                        return
                    if not _is_same_target_origin(
                        req.url, base_scheme=base_proto, base_host=base_host, base_port=base_port
                    ):
                        if req.resource_type == "document":
                            await route.abort()
                            return
                        safe_hdrs = {
                            k: v
                            for k, v in req.headers.items()
                            if k.lower() not in protected_hdr_names
                        }
                        await route.continue_(headers=safe_hdrs)
                        return
                    if (req.resource_type == "document" or headers) and hasattr(route, "fetch"):
                        try:
                            resp = await route.fetch(max_redirects=0)
                        except Exception:
                            await route.abort()
                            return
                        if 300 <= resp.status < 400:
                            loc = next(
                                (
                                    hv.strip()
                                    for hk, hv in (resp.headers or {}).items()
                                    if hk.lower() == "location"
                                ),
                                "",
                            )
                            if loc:
                                resolved = urljoin(req.url, loc)
                                if not _is_same_target_origin(
                                    resolved,
                                    base_scheme=base_proto,
                                    base_host=base_host,
                                    base_port=base_port,
                                ):
                                    await route.abort()
                                    return
                                if (
                                    req.resource_type == "document"
                                    and _keep(resolved)
                                    and resolved not in visited
                                ):
                                    queue.append(resolved)
                        await route.fulfill(response=resp)
                        return
                    await route.continue_()

                await context.route("**/*", _route_guard)
                page = await context.new_page()
                page.on("request", lambda req: _keep(req.url))

                limit = min(max_pages, 8)
                while queue and len(visited) < limit:
                    cur = queue.popleft()
                    if cur in visited:
                        continue
                    visited.add(cur)
                    try:
                        await page.goto(cur, wait_until="domcontentloaded", timeout=timeout * 1000)
                        await page.wait_for_timeout(350)
                        html = await page.content()
                    except Exception:
                        continue

                    try:
                        dom_links = await page.evaluate(
                            "() => Array.from(document.querySelectorAll('a[href],form[action]')).map(el => el.getAttribute('href') || el.getAttribute('action') || '')"
                        )
                    except Exception:
                        dom_links = []
                    _process_dom_snapshot(
                        cur,
                        html,
                        dom_links,
                        base_host=base_host,
                        base_scheme=base_proto,
                        base_port=base_port,
                        findings=findings,
                        keep_fn=_keep,
                        visited=visited,
                        queue=queue,
                    )
            finally:
                await browser.close()
    except Exception as exc:
        log.debug("Playwright browser crawl skipped/fallback on %s: %s", target_url, exc)
        return [], []

    return discovered, findings


async def _cdp_browser_crawl(
    target_url: str,
    *,
    max_pages: int = 8,
    headers: dict[str, str] | None = None,
    timeout: int = 25,
) -> tuple[list[str], list[Finding]]:
    """Zero-dependency Chromium/Chrome/Edge headless CDP crawl with Fetch isolation."""
    exe = _find_chromium_binary()
    if not exe:
        return [], []
    try:
        import websockets
    except ImportError:
        return [], []

    base_host, base_port, base_proto = parse_url_target(target_url)
    if not base_host or not base_port:
        return [], []
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(base_host, base_port, happy_eyeballs_delay=0.25), timeout=2.0
        )
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    except Exception as exc:
        log.debug("CDP pre-connect probe skipped for %s: %s", target_url, exc)
        return [], []

    discovered, _keep = _make_url_keeper(base_host, base_proto, base_port)
    findings: list[Finding] = []
    protected_hdr_names = _protected_header_names(headers)
    profile_dir = ""
    proc = None
    _keep(target_url)

    try:
        profile_dir = tempfile.mkdtemp(prefix="nexus_cdp_")
        cmd = [
            exe,
            "--headless=new",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile_dir}",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--mute-audio",
            "--ignore-certificate-errors",
        ]
        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
            if os.environ.get("NEXUS_ALLOW_NO_SANDBOX") == "1":
                log.warning(
                    "Running headless Chromium with --no-sandbox as root (NEXUS_ALLOW_NO_SANDBOX=1)"
                )
                cmd.append("--no-sandbox")
            else:
                log.warning(
                    "Running as root without NEXUS_ALLOW_NO_SANDBOX=1; keeping Chromium sandbox enabled"
                )
        cmd.append("about:blank")

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )

        port_file = Path(profile_dir) / "DevToolsActivePort"
        cdp_port = ""
        for _ in range(60):
            if proc.returncode is not None:
                return [], []
            if port_file.is_file():
                lines = port_file.read_text(encoding="utf-8", errors="replace").splitlines()
                if lines and lines[0].strip().isdigit():
                    cdp_port = lines[0].strip()
                    break
            await asyncio.sleep(0.1)
        if not cdp_port:
            return [], []

        page_ws = ""
        async with httpx.AsyncClient(timeout=3.0, trust_env=False) as client:
            for _ in range(15):
                try:
                    resp = await client.get(f"http://127.0.0.1:{cdp_port}/json/list")
                    if resp.status_code == 200:
                        for target in resp.json():
                            if target.get("type") == "page" and target.get("webSocketDebuggerUrl"):
                                page_ws = target["webSocketDebuggerUrl"]
                                break
                        if page_ws:
                            break
                except Exception as exc:
                    log.debug("CDP /json/list poll retry for %s: %s", target_url, exc)
                await asyncio.sleep(0.1)
        if not page_ws:
            return [], []

        queue: deque[str] = deque([target_url])
        visited: set[str] = set()

        async with websockets.connect(page_ws, open_timeout=5.0, max_size=8 * 1024 * 1024) as ws:
            msg_seq = 0
            pending: dict[int, asyncio.Future] = {}
            send_lock = asyncio.Lock()
            settled = asyncio.Event()
            main_frame_id = ""
            bg_tasks: set[asyncio.Task] = set()

            async def _send_cdp(
                method: str, params: dict | None = None, *, wait: bool = True
            ) -> dict:
                nonlocal msg_seq
                async with send_lock:
                    msg_seq += 1
                    cid = msg_seq
                    fut = asyncio.get_running_loop().create_future() if wait else None
                    if fut is not None:
                        pending[cid] = fut
                    await ws.send(json.dumps({"id": cid, "method": method, "params": params or {}}))
                if not wait:
                    return {}
                try:
                    return await asyncio.wait_for(fut, timeout=min(float(timeout), 10.0))
                finally:
                    pending.pop(cid, None)

            async def _handle_paused(params: dict) -> None:
                req_id = params.get("requestId")
                if not req_id:
                    return
                req = params.get("request") or {}
                req_url = req.get("url") or ""
                req_headers = req.get("headers") or {}
                rtype = params.get("resourceType") or ""
                resp_status = params.get("responseStatusCode")
                err_reason = params.get("responseErrorReason")
                responded = False
                try:
                    if err_reason is not None:
                        await _send_cdp(
                            "Fetch.failRequest",
                            {"requestId": req_id, "errorReason": str(err_reason)},
                            wait=False,
                        )
                        responded = True
                        return
                    if resp_status is not None:
                        if 300 <= int(resp_status) < 400:
                            loc = next(
                                (
                                    str(h.get("value", "")).strip()
                                    for h in (params.get("responseHeaders") or [])
                                    if str(h.get("name", "")).lower() == "location"
                                ),
                                "",
                            )
                            if loc:
                                resolved = urljoin(req_url, loc)
                                if not _is_same_target_origin(
                                    resolved,
                                    base_scheme=base_proto,
                                    base_host=base_host,
                                    base_port=base_port,
                                ):
                                    await _send_cdp(
                                        "Fetch.failRequest",
                                        {"requestId": req_id, "errorReason": "Aborted"},
                                        wait=False,
                                    )
                                    responded = True
                                    return
                                if (
                                    rtype == "Document"
                                    and _keep(resolved)
                                    and resolved not in visited
                                ):
                                    queue.append(resolved)
                        await _send_cdp("Fetch.continueResponse", {"requestId": req_id}, wait=False)
                        responded = True
                        return

                    parsed = urlparse(req_url)
                    scheme = parsed.scheme.lower()
                    if scheme not in ("http", "https"):
                        await _send_cdp(
                            "Fetch.failRequest",
                            {"requestId": req_id, "errorReason": "Aborted"},
                            wait=False,
                        )
                        responded = True
                        return

                    if _is_same_target_origin(
                        req_url, base_scheme=base_proto, base_host=base_host, base_port=base_port
                    ):
                        _keep(req_url)
                        if headers:
                            merged = dict(req_headers)
                            lower_keys = {k.lower(): k for k in merged}
                            for k, v in headers.items():
                                old_key = lower_keys.get(k.lower())
                                if old_key:
                                    merged.pop(old_key, None)
                                merged[k] = v
                            await _send_cdp(
                                "Fetch.continueRequest",
                                {
                                    "requestId": req_id,
                                    "headers": [
                                        {"name": str(k), "value": str(v)} for k, v in merged.items()
                                    ],
                                },
                                wait=False,
                            )
                        else:
                            await _send_cdp(
                                "Fetch.continueRequest", {"requestId": req_id}, wait=False
                            )
                        responded = True
                        return

                    if rtype == "Document":
                        await _send_cdp(
                            "Fetch.failRequest",
                            {"requestId": req_id, "errorReason": "Aborted"},
                            wait=False,
                        )
                        responded = True
                        return

                    safe_hdrs = [
                        {"name": str(k), "value": str(v)}
                        for k, v in req_headers.items()
                        if str(k).lower() not in protected_hdr_names
                    ]
                    await _send_cdp(
                        "Fetch.continueRequest",
                        {"requestId": req_id, "headers": safe_hdrs},
                        wait=False,
                    )
                    responded = True
                except Exception as exc:
                    log.debug("CDP Fetch handler error for %s: %s", req_url, exc)
                finally:
                    if not responded:
                        with contextlib.suppress(Exception):
                            await _send_cdp(
                                "Fetch.failRequest",
                                {"requestId": req_id, "errorReason": "Failed"},
                                wait=False,
                            )

            async def _reader() -> None:
                try:
                    async for raw in ws:
                        msg = json.loads(raw)
                        if "id" in msg:
                            fut = pending.pop(msg["id"], None)
                            if fut and not fut.done():
                                fut.set_result(msg.get("result") or {})
                        else:
                            method = msg.get("method")
                            ev_params = msg.get("params") or {}
                            if method == "Page.loadEventFired":
                                settled.set()
                            elif method == "Page.frameStoppedLoading":
                                fid = ev_params.get("frameId") or ""
                                if not main_frame_id or fid == main_frame_id:
                                    settled.set()
                            elif method == "Network.loadingFailed":
                                # Only settle on main Document failure, never third-party subresources
                                if ev_params.get("type") == "Document":
                                    fid = ev_params.get("frameId") or ""
                                    if not main_frame_id or fid == main_frame_id:
                                        settled.set()
                            elif method == "Fetch.requestPaused":
                                task = asyncio.create_task(_handle_paused(ev_params))
                                bg_tasks.add(task)
                                task.add_done_callback(bg_tasks.discard)
                except Exception as exc:
                    log.debug("CDP websocket reader ended for %s: %s", target_url, exc)
                finally:
                    settled.set()
                    for fut in list(pending.values()):
                        if not fut.done():
                            fut.set_result({})

            reader_task = asyncio.create_task(_reader())
            try:
                await _send_cdp("Page.enable")
                await _send_cdp("Network.enable")
                await _send_cdp("Runtime.enable")
                await _send_cdp(
                    "Fetch.enable",
                    {
                        "patterns": [
                            {"urlPattern": "http://*", "requestStage": "Request"},
                            {"urlPattern": "https://*", "requestStage": "Request"},
                            {"urlPattern": "ws://*", "requestStage": "Request"},
                            {"urlPattern": "wss://*", "requestStage": "Request"},
                            {"urlPattern": "file://*", "requestStage": "Request"},
                            {"urlPattern": "ftp://*", "requestStage": "Request"},
                            {"urlPattern": "blob:*", "requestStage": "Request"},
                            {"urlPattern": "data:*", "requestStage": "Request"},
                            {"urlPattern": "http://*", "requestStage": "Response"},
                            {"urlPattern": "https://*", "requestStage": "Response"},
                        ]
                    },
                )

                limit = min(max_pages, 8)
                while queue and len(visited) < limit:
                    cur = queue.popleft()
                    if cur in visited:
                        continue
                    visited.add(cur)
                    settled.clear()
                    main_frame_id = ""
                    try:
                        nav_res = await _send_cdp("Page.navigate", {"url": cur})
                        if nav_res.get("errorText"):
                            continue
                        main_frame_id = str(nav_res.get("frameId") or "")
                        with contextlib.suppress(asyncio.TimeoutError):
                            await asyncio.wait_for(settled.wait(), timeout=min(float(timeout), 8.0))
                        await asyncio.sleep(0.35)
                        snap_res = await _send_cdp(
                            "Runtime.evaluate",
                            {
                                "expression": (
                                    "(() => ({href: location.href, "
                                    "html: document.documentElement ? document.documentElement.outerHTML : '', "
                                    "links: Array.from(document.querySelectorAll('a[href],form[action]'))"
                                    ".map(el => el.getAttribute('href') || el.getAttribute('action') || '')}))()"
                                ),
                                "returnByValue": True,
                            },
                        )
                    except Exception:
                        continue

                    snap = (snap_res.get("result") or {}).get("value")
                    if not isinstance(snap, dict):
                        continue
                    actual_href = str(snap.get("href") or "")
                    if actual_href.startswith("chrome-error://") or not _is_same_target_origin(
                        actual_href,
                        base_scheme=base_proto,
                        base_host=base_host,
                        base_port=base_port,
                    ):
                        continue
                    html = str(snap.get("html") or "")
                    raw_links = snap.get("links")
                    dom_links = list(raw_links) if isinstance(raw_links, list) else []
                    _process_dom_snapshot(
                        cur,
                        html,
                        dom_links,
                        base_host=base_host,
                        base_scheme=base_proto,
                        base_port=base_port,
                        findings=findings,
                        keep_fn=_keep,
                        visited=visited,
                        queue=queue,
                    )
            finally:
                for t in list(bg_tasks):
                    t.cancel()
                with contextlib.suppress(Exception):
                    await _send_cdp("Browser.close")
                reader_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await reader_task
    except Exception as exc:
        log.debug("CDP browser crawl skipped/fallback on %s: %s", target_url, exc)
        return [], []
    finally:
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), timeout=0.4)
            if proc.returncode is None:
                with contextlib.suppress(Exception):
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=0.6)
            if proc.returncode is None:
                with contextlib.suppress(Exception):
                    proc.kill()
                    await proc.wait()
        if profile_dir:
            shutil.rmtree(profile_dir, ignore_errors=True)

    return discovered, findings


async def _browser_crawl(
    target_url: str,
    *,
    max_pages: int = 8,
    headers: dict[str, str] | None = None,
    timeout: int = 25,
) -> tuple[list[str], list[Finding]]:
    """Headless browser SPA crawl via Playwright or native Chromium/Edge CDP fallback."""
    urls, findings = await _playwright_browser_crawl(
        target_url, max_pages=max_pages, headers=headers, timeout=timeout
    )
    if urls:
        return urls, findings
    return await _cdp_browser_crawl(
        target_url, max_pages=max_pages, headers=headers, timeout=timeout
    )


async def crawl_web(
    target_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 35,
    stealth: str = "normal",
    headers: dict[str, str] | None = None,
    use_browser: bool = True,
    timeout: int = 120,
) -> tuple[list[str], list[Finding]]:
    """Crawl a web/SPA target via optional Playwright headless browser, `katana`, and Python HTML/JS inspection.

    Returns (discovered_urls, passive_dast_and_secret_findings).
    """
    clean_url = validate_cli_target(target_url, label="target_url")
    clean_headers = validate_headers(headers)
    base_host, base_port, base_proto = parse_url_target(clean_url)
    discovered: list[str] = []
    seen_urls: set[str] = set()
    findings: list[Finding] = []
    _, _, delay_s = _STEALTH_CRAWL.get(stealth, _STEALTH_CRAWL["normal"])

    def _url_allowed(u: str) -> bool:
        return _is_same_target_origin(
            u, base_scheme=base_proto, base_host=base_host, base_port=base_port
        )

    def _add_url(u: str) -> bool:
        if not _url_allowed(u):
            return False
        norm = u.split("#", 1)[0]
        if norm not in seen_urls:
            seen_urls.add(norm)
            discovered.append(norm)
            return True
        return False

    _add_url(clean_url)

    js_to_scan: list[str] = []
    seen_js: set[str] = set()

    def _track_js(u: str) -> None:
        if not _url_allowed(u):
            return
        norm = u.split("#", 1)[0]
        if (
            norm.lower().split("?", 1)[0].endswith(".js")
            and norm not in seen_js
            and len(js_to_scan) < 20
        ):
            seen_js.add(norm)
            js_to_scan.append(norm)

    if use_browser:
        bw_urls, bw_findings = await _browser_crawl(
            clean_url,
            max_pages=min(max_pages, 8),
            headers=clean_headers or None,
            timeout=min(timeout, 30),
        )
        for bu in bw_urls:
            _add_url(bu)
            _track_js(bu)
        findings.extend(bw_findings)

    kat_added: list[str] = []
    if ToolRunner.is_available("katana"):
        kat_urls = await _katana_crawl(
            clean_url,
            max_depth=max_depth,
            stealth=stealth,
            headers=clean_headers or None,
            timeout=timeout,
        )
        for ku in kat_urls:
            if _add_url(ku):
                kat_added.append(ku.split("#", 1)[0])
                _track_js(ku)

    # Pure-Python HTTP crawl + JS/HTML inspection (runs as fallback when katana absent/empty, or inspects discovered assets)
    req_timeout = max(1.0, min(float(timeout), 15.0))
    try:
        async with make_http_client(
            headers=clean_headers or None, timeout=req_timeout, stealth=stealth
        ) as client:
            if kat_added:
                seed = list(js_to_scan) + [u for u in kat_added if u not in seen_js]
                queue: deque[tuple[str, int]] = deque((u, max_depth) for u in seed[:max_pages])
            else:
                seed = (
                    [clean_url]
                    + [u for u in discovered if u != clean_url]
                    + [u for u in js_to_scan if u != clean_url and u not in discovered]
                )
                queue = deque((u, 0) for u in seed[:max_pages])

            visited: set[str] = set()
            while queue and len(visited) < max_pages:
                cur_url, depth = queue.popleft()
                if cur_url in visited:
                    continue
                visited.add(cur_url)

                if delay_s > 0 and len(visited) > 1:
                    await asyncio.sleep(delay_s)

                try:
                    resp = await client.get(cur_url, follow_redirects=False)
                except Exception as exc:
                    log.debug("Crawler request failed for %s: %s", cur_url, exc)
                    continue

                if resp.is_redirect:
                    loc = resp.headers.get("location", "").strip()
                    if loc:
                        redir_url = urljoin(cur_url, loc)
                        if _url_allowed(redir_url):
                            norm_red = redir_url.split("#", 1)[0]
                            _add_url(norm_red)
                            if depth + 1 <= max_depth and norm_red not in visited:
                                queue.append((norm_red, depth + 1))
                    continue

                ctype = (resp.headers.get("content-type") or "").lower()
                text = (resp.text or "")[:_MAX_CRAWL_BODY_BYTES]
                if not text:
                    continue

                if (
                    "javascript" in ctype
                    or cur_url.lower().split("?", 1)[0].endswith(".js")
                    or "html" in ctype
                ):
                    js_eps, sec_findings = extract_js_endpoints_and_secrets(
                        text,
                        cur_url,
                        allowed_host=base_host,
                        allowed_scheme=base_proto,
                        allowed_port=base_port,
                    )
                    findings.extend(sec_findings)
                    findings.extend(analyze_html_passive(cur_url, text, content_type=ctype))
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
                        if not _url_allowed(resolved):
                            continue
                        norm_res = resolved.split("#", 1)[0]
                        _add_url(norm_res)
                        next_depth = depth if rel in extractor.scripts else depth + 1
                        if next_depth <= max_depth and norm_res not in visited:
                            queue.append((norm_res, next_depth))
    except Exception as exc:
        log.warning("Crawler fallback error on %s: %s", target_url, exc)

    deduped_findings: list[Finding] = []
    seen_f: set[tuple[str, int | None, str, str]] = set()
    for f in findings:
        fk = (f.host, f.port, f.title, f.evidence)
        if fk not in seen_f:
            seen_f.add(fk)
            deduped_findings.append(f)

    log.info(
        "Web crawl for %s: %d endpoint(s), %d JS secret finding(s)",
        target_url,
        len(discovered),
        len(deduped_findings),
    )
    return discovered, deduped_findings

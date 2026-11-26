"""Scoped MITM passive inspection & HTTP history recorder (mitmproxy-compatible)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from nexus.core.scope import ScopeEnforcer
from nexus.db.models import Finding, ProxyEntry
from nexus.scanner._http import parse_url_target, redact_headers
from nexus.scanner.headers import analyze_security_headers
from nexus.scanner.passive_dast import analyze_html_passive
from nexus.scanner.yaml_rules import YamlPassiveRuleEngine

log = logging.getLogger("nexus.scanner.proxy")


def _extract_header_items(raw_headers: Any) -> list[tuple[str, str]]:
    """Extract ordered (name, value) header pairs preserving repeated headers like Set-Cookie."""
    if not raw_headers:
        return []
    if hasattr(raw_headers, "multi_items"):
        return [(str(k), str(v)) for k, v in raw_headers.multi_items()]
    if hasattr(raw_headers, "items"):
        # mitmproxy Headers.items(multi=True) vs standard Mapping.items()
        try:
            return [(str(k), str(v)) for k, v in raw_headers.items(multi=True)]
        except TypeError:
            return [(str(k), str(v)) for k, v in raw_headers.items()]
    if isinstance(raw_headers, (list, tuple)):
        return [(str(k), str(v)) for k, v in raw_headers]
    return []


class NexusProxyRecorder:
    """Processes HTTP request/response pairs through ScopeEnforcer + passive DAST analyzers.

    Works standalone (unit tests / programmatic feeds) and as the core backend for
    ``NexusMitmAddon`` inside ``mitmdump`` / ``mitmproxy``.
    """

    def __init__(
        self,
        *,
        engagement_id: str = "",
        scope: ScopeEnforcer | None = None,
        store: Any = None,
        rules_dir: str | Path | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self.scope = scope
        self.store = store
        self.history: list[ProxyEntry] = []
        self.findings: list[Finding] = []
        self.discovered_urls: list[str] = []
        self._seen_urls: set[str] = set()
        self.yaml_engine = YamlPassiveRuleEngine()
        if rules_dir:
            self.yaml_engine.load_directory(rules_dir)

    def inspect_exchange(
        self,
        *,
        method: str,
        url: str,
        request_headers: dict[str, str] | None = None,
        request_body: str = "",
        status_code: int = 200,
        response_headers: dict[str, str] | list[tuple[str, str]] | Any = None,
        response_body: str = "",
    ) -> tuple[ProxyEntry | None, list[Finding]]:
        """Enforce scope on one HTTP transaction and run passive analyzers."""
        host, port, _proto = parse_url_target(url)
        if not host:
            return None, []
        if self.scope is not None:
            if not self.scope.is_in_scope(host) or (
                port is not None and not self.scope.is_port_allowed(port)
            ):
                log.debug("[PROXY] Skipping out-of-scope exchange: %s", url)
                return None, []

        req_hdrs = dict(_extract_header_items(request_headers))
        resp_items = _extract_header_items(response_headers)
        resp_hdrs = dict(resp_items)
        set_cookies = [v for k, v in resp_items if k.lower() == "set-cookie"]
        lower_resp_hdrs = {k.lower(): v for k, v in resp_items}
        ctype = lower_resp_hdrs.get("content-type", "")

        found: list[Finding] = []
        found.extend(analyze_security_headers(url, lower_resp_hdrs, set_cookies=set_cookies))
        if "html" in ctype.lower() or "<form" in response_body[:4000].lower():
            found.extend(analyze_html_passive(url, response_body, content_type=ctype))
        if self.yaml_engine.rule_count > 0:
            found.extend(
                self.yaml_engine.inspect_response(
                    url,
                    status_code=status_code,
                    headers=resp_items or resp_hdrs,
                    body=response_body,
                )
            )

        for f in found:
            f.engagement_id = self.engagement_id
            if self.store is not None and self.engagement_id:
                self.store.add_finding(f)
        self.findings.extend(found)

        entry = ProxyEntry(
            engagement_id=self.engagement_id,
            method=method.upper(),
            url=url,
            host=host,
            port=port or 80,
            request_headers=redact_headers(req_hdrs),
            request_body=request_body[:16000],
            status_code=status_code,
            response_headers=resp_hdrs,
            response_body=response_body[:32000],
            findings_count=len(found),
        )
        self.history.append(entry)
        if len(self.history) > 1000:
            self.history = self.history[-1000:]

        norm_url = url.split("#", 1)[0]
        if norm_url not in self._seen_urls:
            self._seen_urls.add(norm_url)
            self.discovered_urls.append(norm_url)

        if self.store is not None:
            try:
                self.store.add_proxy_entry(entry)
            except Exception as exc:
                log.debug("[PROXY] Failed persisting proxy history entry: %s", exc)

        return entry, found


class NexusMitmAddon:
    """mitmproxy addon wrapper forwarding live HTTP flows to NexusProxyRecorder."""

    def __init__(self, recorder: NexusProxyRecorder) -> None:
        self.recorder = recorder

    def response(self, flow: Any) -> None:
        """Called by mitmproxy whenever an HTTP response arrives."""
        req = getattr(flow, "request", None)
        resp = getattr(flow, "response", None)
        if req is None or resp is None:
            return
        url = str(getattr(req, "pretty_url", "") or getattr(req, "url", ""))
        req_headers = _extract_header_items(getattr(req, "headers", None))
        resp_headers = _extract_header_items(getattr(resp, "headers", None))
        req_body = req.get_text(strict=False) if hasattr(req, "get_text") else ""
        resp_body = resp.get_text(strict=False) if hasattr(resp, "get_text") else ""
        self.recorder.inspect_exchange(
            method=str(getattr(req, "method", "GET")),
            url=url,
            request_headers=dict(req_headers),
            request_body=req_body or "",
            status_code=int(getattr(resp, "status_code", 0) or 0),
            response_headers=resp_headers,
            response_body=resp_body or "",
        )


def build_mitmproxy_master(
    listen_host: str = "127.0.0.1",
    listen_port: int = 8080,
    recorder: NexusProxyRecorder | None = None,
) -> tuple[Any, NexusProxyRecorder]:
    """Create a headless mitmproxy DumpMaster with NexusMitmAddon loaded."""
    try:
        from mitmproxy import options as mitm_options  # type: ignore[import-untyped]
        from mitmproxy.tools.dump import DumpMaster  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "nexus proxy requires mitmproxy. Install with: pip install 'nexus-pt[proxy]'"
        ) from exc

    rec = recorder or NexusProxyRecorder()
    opts = mitm_options.Options(listen_host=listen_host, listen_port=listen_port)
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(NexusMitmAddon(rec))
    return master, rec

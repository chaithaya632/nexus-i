"""Wave 2 tests: OpenAPI parser, SPA/JS crawler & secret scanner, CORS/CSP/header audit, auth forwarding."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from nexus.db.models import Severity
from nexus.recon.runner import ToolOutput
from nexus.scanner._http import parse_url_target, redact_headers
from nexus.scanner.crawler import _katana_crawl, crawl_web, extract_js_endpoints_and_secrets
from nexus.scanner.headers import analyze_security_headers, audit_http_security
from nexus.scanner.nikto import nikto_scan
from nexus.scanner.nuclei import nuclei_scan
from nexus.scanner.openapi import audit_openapi_spec, parse_openapi_spec
from nexus.scanner.web import ffuf_scan


class TestHttpHelpersAndHeaderForwarding:
    """URL target parsing, sensitive header redaction, and scanner -H propagation."""

    def test_parse_url_target_and_redact_headers(self) -> None:
        assert parse_url_target("https://api.example.com/v1") == ("api.example.com", 443, "https")
        assert parse_url_target("http://127.0.0.1:8080/login") == ("127.0.0.1", 8080, "http")

        redacted = redact_headers({
            "Authorization": "Bearer live_token_abc123",
            "Cookie": "sessionid=xyz",
            "X-API-Key": "k_secret",
            "X-Org-Id": "team-1",
        })
        assert redacted["Authorization"] == "***REDACTED***"
        assert redacted["Cookie"] == "***REDACTED***"
        assert redacted["X-API-Key"] == "***REDACTED***"
        assert redacted["X-Org-Id"] == "team-1"

    @pytest.mark.asyncio
    async def test_scanners_forward_custom_headers(self) -> None:
        captured: list[tuple[str, list[str]]] = []

        async def _fake_run(tool: str, args: list[str], **_kwargs):
            captured.append((tool, list(args)))
            return ToolOutput(tool=tool, args=args, returncode=0, stdout="", stderr="")

        hdrs = {"Authorization": "Bearer t123", "Cookie": "sid=1"}
        with patch("nexus.scanner.nuclei.ToolRunner.run", AsyncMock(side_effect=_fake_run)), \
             patch("nexus.scanner.web.ToolRunner.run", AsyncMock(side_effect=_fake_run)), \
             patch("nexus.scanner.nikto.ToolRunner.run", AsyncMock(side_effect=_fake_run)):
            await nuclei_scan(["https://app.local"], headers=hdrs)
            await ffuf_scan("https://app.local", wordlist="dummy.txt", headers=hdrs)
            await nikto_scan("https://app.local", headers=hdrs)

        nuclei_args = dict(captured)["nuclei"]
        ffuf_args = dict(captured)["ffuf"]
        nikto_args = dict(captured)["nikto"]
        assert "-H" in nuclei_args and "Authorization: Bearer t123" in nuclei_args
        assert "-H" in ffuf_args and "Cookie: sid=1" in ffuf_args
        assert "-Add-header" in nikto_args and "Authorization: Bearer t123" in nikto_args


class TestOpenApiParserAndAudit:
    """OpenAPI v3 and Swagger v2 endpoint extraction and schema security auditing."""

    def test_parse_and_audit_openapi_v3_yaml(self, tmp_path: Path) -> None:
        spec = tmp_path / "openapi.yaml"
        spec.write_text(
            """
openapi: 3.0.3
info:
  title: Orders API
  version: "1.2.0"
servers:
  - url: http://api.orders.local
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
security:
  - bearerAuth: []
paths:
  /orders/{order_id}:
    get:
      parameters:
        - name: expand
          in: query
  /orders:
    post:
      security: []
""",
            encoding="utf-8",
        )
        urls, findings = audit_openapi_spec(spec)
        assert "http://api.orders.local/orders/1" in urls
        assert "http://api.orders.local/orders" in urls
        titles = [f.title for f in findings]
        assert any("State-Changing Endpoints Lack Security Requirement" in t for t in titles)
        assert any("Cleartext HTTP Server URL" in t for t in titles)

    def test_audit_swagger_v2_missing_security_definitions(self, tmp_path: Path) -> None:
        spec = tmp_path / "swagger.json"
        spec.write_text(
            json.dumps({
                "swagger": "2.0",
                "info": {"title": "Legacy Swagger", "version": "1.0"},
                "host": "legacy.local:8443",
                "basePath": "/api",
                "schemes": ["https"],
                "paths": {"/items/{slug}": {"get": {"responses": {"200": {"description": "ok"}}}}},
            }),
            encoding="utf-8",
        )
        parsed = parse_openapi_spec(spec)
        assert parsed["urls"] == ["https://legacy.local:8443/api/items/test"]
        _, findings = audit_openapi_spec(spec)
        assert any("No Security Schemes Defined" in f.title for f in findings)


class TestCrawlerAndSecretScanner:
    """JS endpoint extraction, masked secret detection, katana wrapper, and live Python crawl."""

    def test_extract_js_endpoints_and_masked_secrets(self) -> None:
        sample_js = """
        const a = fetch('/api/v2/profile');
        axios.post("https://app.local/graphql", {});
        fetch("https://cdn.thirdparty.invalid/analytics");
        const awsKey = "AKIA000000000000TEST";
        const placeholder = "YOUR_API_KEY_EXAMPLE";
        const fakeApiKey = "test_secret_token_99999999";
        """
        endpoints, findings = extract_js_endpoints_and_secrets(sample_js, "https://app.local/static/app.js")
        assert "https://app.local/api/v2/profile" in endpoints
        assert "https://app.local/graphql" in endpoints
        assert all("thirdparty.invalid" not in ep for ep in endpoints)

        assert len(findings) == 2
        ev_blob = "\n".join(f.evidence for f in findings)
        assert "AKIA000000000000TEST" not in ev_blob
        assert "AKIA00...TEST" in ev_blob
        assert "test_secret_token_99999999" not in ev_blob

    @pytest.mark.asyncio
    async def test_katana_crawl_parses_jsonl_with_headers(self) -> None:
        jsonl = (
            json.dumps({"request": {"endpoint": "https://app.local/api/v1/users"}}) + "\n"
            + json.dumps({"endpoint": "https://app.local/static/main.js"}) + "\n"
        )
        with patch(
            "nexus.scanner.crawler.ToolRunner.run",
            AsyncMock(return_value=ToolOutput(tool="katana", args=[], returncode=0, stdout=jsonl, stderr="")),
        ) as mock_run:
            urls = await _katana_crawl(
                "https://app.local", max_depth=2, stealth="normal",
                headers={"Authorization": "Bearer abc"}, timeout=30,
            )

        assert urls == ["https://app.local/api/v1/users", "https://app.local/static/main.js"]
        args = mock_run.call_args.args[1]
        assert "-jc" in args
        assert "Authorization: Bearer abc" in args

    @pytest.mark.asyncio
    async def test_crawl_web_live_python_fallback_discovers_routes_and_secrets(self) -> None:
        class _AppHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/":
                    body = b'<html><script src="/bundle.js"></script><a href="/about">About</a></html>'
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/bundle.js":
                    body = b'fetch("/api/v1/admin-stats"); const client_secret = "token_live_synthetic_987654";'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/javascript")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b"{}")

            def log_message(self, format, *args):
                pass

        srv = HTTPServer(("127.0.0.1", 0), _AppHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with patch("nexus.scanner.crawler.ToolRunner.is_available", return_value=False):
                urls, findings = await crawl_web(f"http://127.0.0.1:{port}/", max_depth=2, stealth="loud")
        finally:
            srv.shutdown()
            srv.server_close()

        assert f"http://127.0.0.1:{port}/bundle.js" in urls
        assert f"http://127.0.0.1:{port}/about" in urls
        assert f"http://127.0.0.1:{port}/api/v1/admin-stats" in urls
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "token_live_synthetic_987654" not in findings[0].evidence


class TestHttpSecurityHeadersAndCors:
    """Verified CORS, CSP, HSTS, Clickjacking, and cookie flag checks."""

    def test_analyze_security_headers_detects_cors_csp_hsts_and_cookies(self) -> None:
        hdrs = {
            "content-type": "text/html; charset=utf-8",
            "content-security-policy": "default-src 'self' 'unsafe-inline'",
        }
        cors_hdrs = {
            "access-control-allow-origin": "https://untrusted.nexus.invalid",
            "access-control-allow-credentials": "true",
        }
        findings = analyze_security_headers(
            "https://secure.local/dashboard",
            hdrs,
            cors_headers=cors_hdrs,
            set_cookies=["session_id=abc123; Path=/"],
        )
        titles = [f.title for f in findings]
        assert any("Arbitrary Origin Reflected With Credentials" in t for t in titles)
        assert any("Missing Strict-Transport-Security" in t for t in titles)
        assert any("Permissive Content-Security-Policy" in t for t in titles)
        assert any("Missing Clickjacking Protection" in t for t in titles)
        assert any("Missing X-Content-Type-Options" in t for t in titles)
        assert any("Session Cookie Missing Security Flag(s)" in t for t in titles)
        assert all(f.confirmed is True for f in findings)

    @pytest.mark.asyncio
    async def test_audit_http_security_live_cors_and_dedup(self) -> None:
        class _CorsHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                origin = self.headers.get("Origin")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Set-Cookie", "auth_token=xyz; Path=/")
                self.end_headers()
                self.wfile.write(b"<h1>ok</h1>")

            def log_message(self, format, *args):
                pass

        srv = HTTPServer(("127.0.0.1", 0), _CorsHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            findings = await audit_http_security([
                f"http://127.0.0.1:{port}/page1",
                f"http://127.0.0.1:{port}/page2",
                f"http://127.0.0.1:{port}/page1",
            ])
        finally:
            srv.shutdown()
            srv.server_close()

        cors_hits = [f for f in findings if "CORS:" in f.title]
        # Per-URL deduplication keeps one verified finding per (host, port, url, title)
        assert len(cors_hits) == 2
        assert cors_hits[0].severity == Severity.MEDIUM
        assert any("HttpOnly" in f.title for f in findings)

    def test_non_html_empty_ctype_and_cookie_token_samesite(self) -> None:
        # Empty content-type should not trigger missing CSP/Clickjacking HTML checks
        findings_empty = analyze_security_headers("https://api.local/health", {})
        titles_empty = [f.title for f in findings_empty]
        assert not any("Missing Content-Security-Policy" in t for t in titles_empty)
        assert not any("Missing Clickjacking" in t for t in titles_empty)

        # Cookie named httponly_test=1 must NOT satisfy HttpOnly or SameSite checks
        findings_ck = analyze_security_headers(
            "https://secure.local/login",
            {"content-type": "text/html"},
            set_cookies=["session_token=httponly_secure_samesite; Path=/"],
        )
        ck_titles = [f.title for f in findings_ck if "Session Cookie" in f.title]
        assert len(ck_titles) == 1
        assert "HttpOnly" in ck_titles[0] and "Secure" in ck_titles[0] and "SameSite" in ck_titles[0]

    def test_openapi_ssrf_guard_and_http_stealth_integration(self, tmp_path: Path) -> None:
        from nexus.scanner._http import make_http_client
        from nexus.stealth.controller import StealthController

        spec = tmp_path / "ssrf.yaml"
        spec.write_text(
            """
openapi: 3.0.3
info:
  title: SSRF Spec
  version: "1.0"
servers:
  - url: http://169.254.169.254/latest/meta-data
  - url: http://127.0.0.1:8080/internal
  - url: https://api.public.example
paths:
  /ping:
    get:
      responses:
        "200":
          description: ok
""",
            encoding="utf-8",
        )
        parsed = parse_openapi_spec(spec)
        assert parsed["base_urls"] == ["https://api.public.example"]

        # StealthController integration in make_http_client
        ctrl = StealthController("quiet")
        cli = make_http_client(stealth=ctrl)
        assert cli.headers["User-Agent"] != "NEXUS-Security-Scanner/1.0"
        assert len(cli.event_hooks["request"]) == 1

    def test_extract_js_endpoints_enforces_scheme_and_port(self) -> None:
        js = """
        fetch("http://app.local/downgrade");
        fetch("https://app.local:8443/altport");
        fetch("https://app.local/sameorigin");
        """
        eps, _ = extract_js_endpoints_and_secrets(js, "https://app.local/app.js")
        assert eps == ["https://app.local/sameorigin"]

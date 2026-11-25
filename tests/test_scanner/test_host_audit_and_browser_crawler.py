"""Wave 7 tests: credentialed Linux host package patch audit and Playwright SPA crawler."""

from __future__ import annotations

import types
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from nexus.brain.knowledge_graph import KnowledgeGraph
from nexus.core.config import NexusConfig, ScanProfile
from nexus.core.engine import NexusEngine
from nexus.recon.runner import ToolOutput
from nexus.scanner.crawler import _browser_crawl, crawl_web
from nexus.scanner.host_audit import (
    audit_host_packages,
    correlate_installed_packages,
    normalize_pkg_version,
    parse_package_lines,
)


class TestHostPackageAuditor:
    def test_normalize_and_correlate_dpkg_packages(self) -> None:
        assert normalize_pkg_version("1:10.6p2-1") == "10.6"
        assert normalize_pkg_version("3.0.2-0ubuntu1.12") == "3.0.2"
        assert normalize_pkg_version("2.4.68-2") == "2.4.68"

        sample_dpkg = (
            "openssl\t3.0.2-0ubuntu1\n"
            "apache2\t2.4.68-2\n"
            "openssh-server\t1:10.6p2-1\n"
            "postgresql\t18+293\n"
            "php-common\t2:99\n"
            "postgresql-15:amd64\t15.3-1+deb12u1\n"
        )
        pkgs = parse_package_lines(sample_dpkg)
        assert ("openssl", "3.0.2-0ubuntu1") in pkgs
        assert ("postgresql-15", "15.3-1+deb12u1") in pkgs

        kg = KnowledgeGraph()
        kg.load_from_directory(NexusConfig().knowledge_dir)
        findings = correlate_installed_packages(pkgs, kg, host="srv.local")
        cves = {c for f in findings for c in f.cve_ids}
        assert "CVE-2022-3602" in cves   # openssl 3.0.2 vulnerable
        assert "CVE-2023-39417" in cves  # postgresql 15.3 vulnerable (<15.4)
        assert "CVE-2024-7348" in cves   # postgresql 15.3 also vulnerable (<16.4)
        # Patched/out-of-range builds and wrapper meta-packages must NOT false-positive
        assert "CVE-2021-41773" not in cves
        assert "CVE-2024-6387" not in cves
        assert "CVE-2024-4577" not in cves
        assert "CVE-2020-25695" not in cves  # postgresql <13.1 does not apply to 15.3
        assert correlate_installed_packages([("postgresql", "18+293"), ("php-common", "2:99")], kg) == []
        assert all(f.tool_source == "host_pkg_audit" and f.confirmed for f in findings)

    @pytest.mark.asyncio
    async def test_audit_host_packages_ssh_invocation_and_username_validation(self, tmp_path: Path) -> None:
        kg = KnowledgeGraph()
        kg.load_from_directory(NexusConfig().knowledge_dir)
        key_file = tmp_path / "id_test"
        key_file.write_text("dummy", encoding="utf-8")

        # Reject unsafe username with shell characters
        assert await audit_host_packages(
            "10.0.0.9", knowledge=kg, ssh_user="bad;id", ssh_key_path=key_file
        ) == []

        mock_run = AsyncMock(return_value=ToolOutput(
            tool="ssh", args=[], returncode=0,
            stdout="redis-server\t7.2.3-1\n", stderr="",
        ))
        with (
            patch("nexus.scanner.host_audit.ToolRunner.is_available", return_value=True),
            patch("nexus.scanner.host_audit.ToolRunner.run", mock_run),
        ):
            findings = await audit_host_packages(
                "10.0.0.9", knowledge=kg, ssh_user="auditor", ssh_key_path=key_file, ssh_port=2222
            )

        assert any("CVE-2023-41056" in f.cve_ids for f in findings)
        cli_args = mock_run.call_args.args[1]
        assert "BatchMode=yes" in cli_args
        assert "2222" in cli_args
        assert "auditor@10.0.0.9" in cli_args

    @pytest.mark.asyncio
    async def test_engine_run_scan_dispatches_host_audit(self, tmp_path: Path) -> None:
        cfg = NexusConfig(
            data_dir=tmp_path / "d", db_path=tmp_path / "n.db", output_dir=tmp_path / "o",
            profile=ScanProfile.NETWORK, local_pkg_audit=True,
        )
        eng = NexusEngine(cfg)
        eng.boot()
        try:
            e = eng.create_engagement("127.0.0.1")
            mock_pkgs = AsyncMock(return_value=[])
            with (
                patch("nexus.core.engine.audit_tls", AsyncMock(return_value=[])),
                patch("nexus.core.engine.audit_ssh", AsyncMock(return_value=[])),
                patch("nexus.core.engine.audit_host_packages", mock_pkgs),
            ):
                await eng.run_scan(e.id, "127.0.0.1")
            mock_pkgs.assert_awaited_once()
            assert mock_pkgs.call_args.kwargs["local"] is True
        finally:
            eng.shutdown()


class TestPlaywrightBrowserCrawler:
    @pytest.mark.asyncio
    async def test_browser_crawl_isolates_cross_origin_headers_and_extracts_dom(self, monkeypatch) -> None:
        route_calls: list[tuple[str, dict | None]] = []

        class _FakeReq:
            def __init__(self, url: str, resource_type: str = "fetch", headers: dict | None = None):
                self.url = url
                self.resource_type = resource_type
                self.headers = headers or {}

        class _FakeRoute:
            def __init__(self, req):
                self.request = req
                self.aborted = False
                self.continued_headers = None

            async def abort(self):
                self.aborted = True
                route_calls.append(("abort:" + self.request.url, None))

            async def continue_(self, headers=None):
                self.continued_headers = headers
                route_calls.append(("continue:" + self.request.url, headers))

        class _FakePage:
            def __init__(self, context):
                self._ctx = context
                self._listeners = {}

            def on(self, event, fn):
                self._listeners[event] = fn

            async def goto(self, url, **_kw):
                if "request" in self._listeners:
                    self._listeners["request"](_FakeReq("https://spa.local/api/v2/me"))
                    self._listeners["request"](_FakeReq("https://evil.external.com/collect"))
                # Trigger cross-origin route guard on third-party script with auth header
                ext_route = _FakeRoute(_FakeReq(
                    "https://cdn.external.com/a.js", resource_type="script",
                    headers={"authorization": "Bearer topsecret", "accept": "*/*"},
                ))
                await self._ctx._route_handler(ext_route)
                doc_route = _FakeRoute(_FakeReq("https://evil.external.com/phish", resource_type="document"))
                await self._ctx._route_handler(doc_route)

            async def wait_for_timeout(self, _ms):
                pass

            async def content(self):
                return (
                    '<html><body><a href="/spa/admin">Admin</a>'
                    '<form method="post" action="/spa/save"><input type="text" name="q"/></form>'
                    '<script>document.body.innerHTML = "hi";</script></body></html>'
                )

            async def evaluate(self, _expr):
                return ["/spa/admin", "/spa/save", "https://outside.invalid/x"]

        class _FakeContext:
            def __init__(self):
                self._route_handler = None

            async def route(self, _pat, fn):
                self._route_handler = fn

            async def new_page(self):
                return _FakePage(self)

        class _FakeBrowser:
            async def new_context(self, **_kw):
                return _FakeContext()

            async def close(self):
                pass

        class _FakePW:
            def __init__(self):
                self.chromium = types.SimpleNamespace(launch=AsyncMock(return_value=_FakeBrowser()))

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

        fake_mod = types.ModuleType("playwright.async_api")
        fake_mod.async_playwright = lambda: _FakePW()
        fake_pkg = types.ModuleType("playwright")
        monkeypatch.setitem(__import__("sys").modules, "playwright", fake_pkg)
        monkeypatch.setitem(__import__("sys").modules, "playwright.async_api", fake_mod)

        with patch("nexus.scanner.crawler.importlib.util.find_spec", return_value=object()):
            urls, findings = await _browser_crawl(
                "https://spa.local/", max_pages=2, headers={"Authorization": "Bearer topsecret"}
            )

        assert "https://spa.local/spa/admin" in urls
        assert "https://spa.local/api/v2/me" in urls
        assert all("external.com" not in u and "outside.invalid" not in u for u in urls)
        assert any(f.title == "POST Form Missing Anti-CSRF Token Field" for f in findings)
        # External document aborted & third-party script had Authorization stripped cleanly
        assert ("abort:https://evil.external.com/phish", None) in route_calls
        cdn_hdrs = [h for k, h in route_calls if k == "continue:https://cdn.external.com/a.js"][0]
        assert "authorization" not in cdn_hdrs

    @pytest.mark.asyncio
    async def test_crawl_web_falls_back_cleanly_when_playwright_errors(self) -> None:
        with (
            patch("nexus.scanner.crawler._browser_crawl", AsyncMock(return_value=([], []))),
            patch("nexus.scanner.crawler.ToolRunner.is_available", return_value=False),
        ):
            urls, findings = await crawl_web("http://127.0.0.1:1/", use_browser=True)
        assert urls == ["http://127.0.0.1:1/"]
        assert findings == []

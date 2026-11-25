"""Wave 7 tests: credentialed Linux host package patch audit and Playwright SPA crawler."""

from __future__ import annotations

import asyncio
import json
import types
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from nexus.brain.knowledge_graph import KnowledgeGraph
from nexus.core.config import NexusConfig, ScanProfile
from nexus.core.engine import NexusEngine
from nexus.recon.runner import ToolOutput
from nexus.scanner.crawler import _browser_crawl, _cdp_browser_crawl, crawl_web
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
        assert normalize_pkg_version("1.1.1t-0+deb11u2") == "1.1.1t"

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
        assert "CVE-2022-3602" in cves  # openssl 3.0.2 vulnerable
        assert "CVE-2023-39417" in cves  # postgresql 15.3 vulnerable (<15.4)
        assert "CVE-2024-7348" in cves  # postgresql 15.3 also vulnerable (<16.4)
        # Patched/out-of-range builds and wrapper meta-packages must NOT false-positive
        assert "CVE-2021-41773" not in cves
        assert "CVE-2024-6387" not in cves
        assert "CVE-2024-4577" not in cves
        assert "CVE-2020-25695" not in cves  # postgresql <13.1 does not apply to 15.3
        assert (
            correlate_installed_packages([("postgresql", "18+293"), ("php-common", "2:99")], kg)
            == []
        )
        assert all(f.tool_source == "host_pkg_audit" and f.confirmed for f in findings)

    @pytest.mark.asyncio
    async def test_audit_host_packages_ssh_invocation_and_username_validation(
        self, tmp_path: Path
    ) -> None:
        kg = KnowledgeGraph()
        kg.load_from_directory(NexusConfig().knowledge_dir)
        key_file = tmp_path / "id_test"
        key_file.write_text("dummy", encoding="utf-8")

        # Reject unsafe username with shell characters
        assert (
            await audit_host_packages(
                "10.0.0.9", knowledge=kg, ssh_user="bad;id", ssh_key_path=key_file
            )
            == []
        )

        mock_run = AsyncMock(
            return_value=ToolOutput(
                tool="ssh",
                args=[],
                returncode=0,
                stdout="redis-server\t7.2.3-1\n",
                stderr="",
            )
        )
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

        # Reject out-of-range / invalid ssh_port before invoking subprocess
        mock_run.reset_mock()
        with (
            patch("nexus.scanner.host_audit.ToolRunner.is_available", return_value=True),
            patch("nexus.scanner.host_audit.ToolRunner.run", mock_run),
        ):
            for bad_port in (0, -1, 65536, "bad"):
                assert (
                    await audit_host_packages(
                        "10.0.0.9",
                        knowledge=kg,
                        ssh_user="auditor",
                        ssh_key_path=key_file,
                        ssh_port=bad_port,  # type: ignore[arg-type]
                    )
                    == []
                )
        mock_run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_engine_run_scan_dispatches_host_audit(self, tmp_path: Path) -> None:
        cfg = NexusConfig(
            data_dir=tmp_path / "d",
            db_path=tmp_path / "n.db",
            output_dir=tmp_path / "o",
            profile=ScanProfile.NETWORK,
            local_pkg_audit=True,
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
    async def test_browser_crawl_isolates_cross_origin_headers_and_extracts_dom(
        self, monkeypatch
    ) -> None:
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
                ext_route = _FakeRoute(
                    _FakeReq(
                        "https://cdn.external.com/a.js",
                        resource_type="script",
                        headers={"authorization": "Bearer topsecret", "accept": "*/*"},
                    )
                )
                await self._ctx._route_handler(ext_route)
                doc_route = _FakeRoute(
                    _FakeReq("https://evil.external.com/phish", resource_type="document")
                )
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

    @pytest.mark.asyncio
    async def test_playwright_route_guard_aborts_302_cross_origin_redirect(
        self, monkeypatch
    ) -> None:
        aborted_urls: list[str] = []

        class _FakeResp:
            status = 302
            headers = {"Location": "https://evil.external.com/steal"}

        class _FakeReq:
            def __init__(self, url: str, resource_type: str = "document"):
                self.url = url
                self.resource_type = resource_type
                self.headers = {"authorization": "Bearer pw_tok"}

        class _FakeRoute:
            def __init__(self, req):
                self.request = req

            async def fetch(self, max_redirects=None):
                assert max_redirects == 0
                return _FakeResp()

            async def abort(self):
                aborted_urls.append(self.request.url)

            async def fulfill(self, response=None):
                raise AssertionError("Cross-origin 302 should be aborted before fulfill")

            async def continue_(self, headers=None):
                pass

        class _FakePage:
            def __init__(self, context):
                self._ctx = context

            def on(self, _e, _fn):
                pass

            async def goto(self, _url, **_kw):
                await self._ctx._route_handler(_FakeRoute(_FakeReq("https://spa.local/redir")))

            async def wait_for_timeout(self, _ms):
                pass

            async def content(self):
                return "<html><body></body></html>"

            async def evaluate(self, _expr):
                return []

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
        monkeypatch.setitem(__import__("sys").modules, "playwright", types.ModuleType("playwright"))
        monkeypatch.setitem(__import__("sys").modules, "playwright.async_api", fake_mod)

        with patch("nexus.scanner.crawler.importlib.util.find_spec", return_value=object()):
            await _browser_crawl(
                "https://spa.local/", max_pages=1, headers={"Authorization": "Bearer pw_tok"}
            )

        assert aborted_urls == ["https://spa.local/redir"]

    @pytest.mark.asyncio
    async def test_browser_crawl_falls_back_to_cdp_crawler(self) -> None:
        mock_cdp = AsyncMock(return_value=(["https://spa.local/", "https://spa.local/app"], []))
        with (
            patch(
                "nexus.scanner.crawler._playwright_browser_crawl", AsyncMock(return_value=([], []))
            ),
            patch("nexus.scanner.crawler._cdp_browser_crawl", mock_cdp),
        ):
            urls, findings = await _browser_crawl(
                "https://spa.local/", max_pages=3, headers={"Authorization": "Bearer cdp_tok"}
            )
        mock_cdp.assert_awaited_once_with(
            "https://spa.local/",
            max_pages=3,
            headers={"Authorization": "Bearer cdp_tok"},
            timeout=25,
        )
        assert urls == ["https://spa.local/", "https://spa.local/app"]
        assert findings == []

    @pytest.mark.asyncio
    async def test_cdp_fetch_isolation_and_katana_off_host_js_filtering(
        self, tmp_path: Path
    ) -> None:
        sent_cmds: list[dict] = []

        class _DummyWriter:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        class _FakeProc:
            returncode = None

            def terminate(self):
                self.returncode = 0

            def kill(self):
                self.returncode = -9

            async def wait(self):
                return 0

        class _FakeWS:
            def __init__(self, port_dir_hint: list[str]):
                self._incoming: asyncio.Queue[str | None] = asyncio.Queue()
                self._hints = port_dir_hint

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def send(self, raw: str):
                msg = json.loads(raw)
                sent_cmds.append(msg)
                mid = msg.get("id")
                method = msg.get("method")
                if method == "Page.navigate":
                    # Inject Fetch.requestPaused scenarios across Request & Response stages
                    paused = [
                        # 1. Scheme downgrade script on same host -> strip Authorization
                        {
                            "method": "Fetch.requestPaused",
                            "params": {
                                "requestId": "r-downgrade",
                                "resourceType": "Script",
                                "request": {
                                    "url": "http://spa.local/downgrade.js",
                                    "headers": {"authorization": "Bearer top", "accept": "*/*"},
                                },
                            },
                        },
                        # 2. Cross-origin 302 -> file:///etc/passwd redirect at Response stage -> Aborted
                        {
                            "method": "Fetch.requestPaused",
                            "params": {
                                "requestId": "r-redir-file",
                                "resourceType": "Document",
                                "responseStatusCode": 302,
                                "responseHeaders": [
                                    {"name": "Location", "value": "file:///etc/passwd"}
                                ],
                                "request": {"url": "https://spa.local/redir"},
                            },
                        },
                        # 3. Network error responseErrorReason at Response stage -> failRequest(NameNotResolved)
                        {
                            "method": "Fetch.requestPaused",
                            "params": {
                                "requestId": "r-neterr",
                                "resourceType": "Fetch",
                                "responseErrorReason": "NameNotResolved",
                                "request": {"url": "https://dead.invalid/x.js"},
                            },
                        },
                    ]
                    for ev in paused:
                        await self._incoming.put(json.dumps(ev))
                    await self._incoming.put(json.dumps({"id": mid, "result": {"frameId": "f1"}}))
                    await self._incoming.put(
                        json.dumps({"method": "Page.loadEventFired", "params": {}})
                    )
                elif method == "Runtime.evaluate":
                    await self._incoming.put(
                        json.dumps(
                            {
                                "id": mid,
                                "result": {
                                    "result": {
                                        "value": {
                                            "href": "https://spa.local/",
                                            "html": "<html><body><a href='/ok'>OK</a></body></html>",
                                            "links": [
                                                "/ok",
                                                "http://spa.local/other-scheme",
                                                "http://spa.local:99999/badport",
                                            ],
                                        }
                                    }
                                },
                            }
                        )
                    )
                elif method == "Browser.close":
                    await self._incoming.put(json.dumps({"id": mid, "result": {}}))
                    await self._incoming.put(None)  # Clean EOF
                elif mid is not None:
                    await self._incoming.put(json.dumps({"id": mid, "result": {}}))

            def __aiter__(self):
                return self

            async def __anext__(self):
                item = await self._incoming.get()
                if item is None:
                    raise StopAsyncIteration
                return item

        async def _fake_exec(*cmd, **_kw):
            for arg in cmd:
                if str(arg).startswith("--user-data-dir="):
                    pdir = Path(str(arg).split("=", 1)[1])
                    (pdir / "DevToolsActivePort").write_text(
                        "9222\n/devtools/browser/1\n", encoding="utf-8"
                    )
            return _FakeProc()

        fake_ws_mod = types.ModuleType("websockets")
        fake_ws_mod.connect = lambda *_a, **_kw: _FakeWS([])

        class _FakeResp:
            status_code = 200

            def json(self):
                return [
                    {"type": "page", "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/1"}
                ]

        class _FakeClient:
            def __init__(self, **_kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def get(self, _u):
                return _FakeResp()

        with (
            patch("nexus.scanner.crawler._find_chromium_binary", return_value="chromium"),
            patch(
                "nexus.scanner.crawler.asyncio.open_connection",
                AsyncMock(return_value=(None, _DummyWriter())),
            ),
            patch("nexus.scanner.crawler.asyncio.create_subprocess_exec", side_effect=_fake_exec),
            patch("nexus.scanner.crawler.httpx.AsyncClient", _FakeClient),
            patch.dict(__import__("sys").modules, {"websockets": fake_ws_mod}),
        ):
            urls, _ = await _cdp_browser_crawl(
                "https://spa.local/",
                max_pages=1,
                headers={"Authorization": "Bearer top"},
                timeout=5,
            )

        assert "https://spa.local/ok" in urls
        assert all("other-scheme" not in u and "badport" not in u for u in urls)

        by_req = {
            c["params"].get("requestId"): (c["method"], c["params"])
            for c in sent_cmds
            if isinstance(c.get("params"), dict) and "requestId" in c["params"]
        }
        assert by_req["r-downgrade"][0] == "Fetch.continueRequest"
        assert all(
            h["name"].lower() != "authorization" for h in by_req["r-downgrade"][1]["headers"]
        )
        assert by_req["r-redir-file"] == (
            "Fetch.failRequest",
            {"requestId": "r-redir-file", "errorReason": "Aborted"},
        )
        assert by_req["r-neterr"] == (
            "Fetch.failRequest",
            {"requestId": "r-neterr", "errorReason": "NameNotResolved"},
        )

        # Also verify katana returning an off-host .js URL never reaches httpx client
        fetched_urls: list[str] = []

        class _TrackingHttpClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def get(self, u, **_kw):
                fetched_urls.append(u)
                return types.SimpleNamespace(
                    is_redirect=False, headers={"content-type": "application/javascript"}, text=""
                )

        with (
            patch("nexus.scanner.crawler._browser_crawl", AsyncMock(return_value=([], []))),
            patch("nexus.scanner.crawler.ToolRunner.is_available", return_value=True),
            patch(
                "nexus.scanner.crawler._katana_crawl",
                AsyncMock(return_value=["https://evil.cdn.com/bad.js", "https://spa.local/app.js"]),
            ),
            patch("nexus.scanner.crawler.make_http_client", return_value=_TrackingHttpClient()),
        ):
            k_urls, _ = await crawl_web(
                "https://spa.local/", headers={"Authorization": "Bearer top"}
            )

        assert fetched_urls == ["https://spa.local/app.js"]
        assert all("evil.cdn.com" not in u for u in k_urls)

    @pytest.mark.asyncio
    async def test_crawler_origin_enforcement_without_headers_and_scheme_blocking(
        self, monkeypatch
    ) -> None:
        from nexus.scanner.crawler import _katana_crawl

        # 1. katana always passes -fs fqdn even when headers=None
        with patch(
            "nexus.scanner.crawler.ToolRunner.run",
            AsyncMock(
                return_value=ToolOutput(tool="katana", args=[], returncode=0, stdout="", stderr="")
            ),
        ) as mock_kat:
            await _katana_crawl(
                "https://app.local/", max_depth=1, stealth="normal", headers=None, timeout=10
            )
        kat_args = mock_kat.call_args.args[1]
        assert "-fs" in kat_args and kat_args[kat_args.index("-fs") + 1] == "fqdn"

        # 2. crawl_web with headers=None rejects scheme downgrade and port escape, and still runs Python fallback when katana returns []
        fetched: list[str] = []

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def get(self, u, **_kw):
                fetched.append(u)
                return types.SimpleNamespace(
                    is_redirect=False,
                    headers={"content-type": "text/html"},
                    text='<a href="http://app.local/downgrade">d</a><a href="https://app.local:8443/alt">p</a><a href="/ok">ok</a>',
                )

        with (
            patch(
                "nexus.scanner.crawler._browser_crawl",
                AsyncMock(return_value=(["https://app.local/"], [])),
            ),
            patch("nexus.scanner.crawler.ToolRunner.is_available", return_value=True),
            patch("nexus.scanner.crawler._katana_crawl", AsyncMock(return_value=[])),
            patch("nexus.scanner.crawler.make_http_client", return_value=_FakeClient()),
        ):
            urls, _ = await crawl_web("https://app.local/", headers=None, max_depth=1)

        assert "https://app.local/ok" in urls
        assert "http://app.local/downgrade" not in urls
        assert "https://app.local:8443/alt" not in urls
        assert "https://app.local/" in fetched

        # 3. Playwright route guard aborts non-HTTP(S) schemes (ws://, file://, blob:, data:)
        aborted: list[str] = []

        class _Req:
            def __init__(self, url: str):
                self.url = url
                self.resource_type = "xhr"
                self.headers = {}

        class _Route:
            def __init__(self, url: str):
                self.request = _Req(url)

            async def abort(self):
                aborted.append(self.request.url)

            async def continue_(self, **_kw):
                raise AssertionError(f"Non-HTTP scheme {self.request.url} should have been aborted")

        class _Page:
            def __init__(self, ctx):
                self._ctx = ctx

            def on(self, _e, _fn):
                pass

            async def goto(self, _u, **_kw):
                for bad_u in (
                    "ws://spa.local/sock",
                    "file:///etc/passwd",
                    "blob:https://spa.local/1",
                    "data:text/plain,x",
                ):
                    await self._ctx._fn(_Route(bad_u))

            async def wait_for_timeout(self, _ms):
                pass

            async def content(self):
                return "<html></html>"

            async def evaluate(self, _e):
                return []

        class _Ctx:
            async def route(self, _p, fn):
                self._fn = fn

            async def new_page(self):
                return _Page(self)

        class _Browser:
            async def new_context(self, **_kw):
                return _Ctx()

            async def close(self):
                pass

        class _PW:
            def __init__(self):
                self.chromium = types.SimpleNamespace(launch=AsyncMock(return_value=_Browser()))

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

        fake_mod = types.ModuleType("playwright.async_api")
        fake_mod.async_playwright = lambda: _PW()
        monkeypatch.setitem(__import__("sys").modules, "playwright", types.ModuleType("playwright"))
        monkeypatch.setitem(__import__("sys").modules, "playwright.async_api", fake_mod)
        with patch("nexus.scanner.crawler.importlib.util.find_spec", return_value=object()):
            await _browser_crawl("https://spa.local/", max_pages=1)

        assert set(aborted) == {
            "ws://spa.local/sock",
            "file:///etc/passwd",
            "blob:https://spa.local/1",
            "data:text/plain,x",
        }

    def test_host_audit_dedups_by_pkg_and_cve_and_preserves_openssl_letter(self) -> None:
        kg = KnowledgeGraph()
        kg.load_from_directory(NexusConfig().knowledge_dir)
        findings = correlate_installed_packages(
            [("openssl", "1.1.1t-0+deb11u2"), ("libssl1.1", "1.1.1-1")],
            kg,
            host="srv.local",
        )
        # 1.1.1t must NOT match <1.1.1t CVEs (like CVE-2023-0286 if present), while 1.1.1 can match
        f_t = [f for f in findings if "1.1.1t" in f.evidence]
        f_old = [f for f in findings if "1.1.1-1" in f.evidence]
        if f_t and f_old:
            # Distinct packages may report their own entries rather than collapsing on CVE alone
            assert all("openssl" in f.evidence for f in f_t)

    @pytest.mark.asyncio
    async def test_cdp_blocks_non_http_and_ignores_third_party_loading_failed(self) -> None:
        sent_cmds: list[dict] = []

        class _DummyWriter:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        class _FakeProc:
            returncode = None

            def terminate(self):
                self.returncode = 0

            def kill(self):
                self.returncode = -9

            async def wait(self):
                return 0

        class _FakeWS:
            def __init__(self):
                self._incoming: asyncio.Queue[str | None] = asyncio.Queue()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def send(self, raw: str):
                msg = json.loads(raw)
                sent_cmds.append(msg)
                mid = msg.get("id")
                method = msg.get("method")
                if method == "Page.navigate":
                    # Non-HTTP scheme paused request + third-party subresource loadingFailed (must NOT settle prematurely!)
                    await self._incoming.put(
                        json.dumps(
                            {
                                "method": "Fetch.requestPaused",
                                "params": {
                                    "requestId": "r-ws",
                                    "resourceType": "WebSocket",
                                    "request": {"url": "ws://spa.local/live", "headers": {}},
                                },
                            }
                        )
                    )
                    await self._incoming.put(
                        json.dumps(
                            {
                                "method": "Network.loadingFailed",
                                "params": {"type": "Script", "frameId": "other"},
                            }
                        )
                    )
                    await self._incoming.put(json.dumps({"id": mid, "result": {"frameId": "main"}}))
                    await asyncio.sleep(0.05)
                    await self._incoming.put(
                        json.dumps({"method": "Page.loadEventFired", "params": {}})
                    )
                elif method == "Runtime.evaluate":
                    await self._incoming.put(
                        json.dumps(
                            {
                                "id": mid,
                                "result": {
                                    "result": {
                                        "value": {
                                            "href": "https://spa.local/",
                                            "html": "<html><body><a href='/after-load'>After</a></body></html>",
                                            "links": ["/after-load"],
                                        }
                                    }
                                },
                            }
                        )
                    )
                elif method == "Browser.close":
                    await self._incoming.put(json.dumps({"id": mid, "result": {}}))
                    await self._incoming.put(None)
                elif mid is not None:
                    await self._incoming.put(json.dumps({"id": mid, "result": {}}))

            def __aiter__(self):
                return self

            async def __anext__(self):
                item = await self._incoming.get()
                if item is None:
                    raise StopAsyncIteration
                return item

        async def _fake_exec(*cmd, **_kw):
            for arg in cmd:
                if str(arg).startswith("--user-data-dir="):
                    pdir = Path(str(arg).split("=", 1)[1])
                    (pdir / "DevToolsActivePort").write_text(
                        "9222\n/devtools/browser/1\n", encoding="utf-8"
                    )
            return _FakeProc()

        fake_ws_mod = types.ModuleType("websockets")
        fake_ws_mod.connect = lambda *_a, **_kw: _FakeWS()

        class _FakeResp:
            status_code = 200

            def json(self):
                return [
                    {"type": "page", "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/1"}
                ]

        class _FakeClient:
            def __init__(self, **_kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def get(self, _u):
                return _FakeResp()

        with (
            patch("nexus.scanner.crawler._find_chromium_binary", return_value="chromium"),
            patch(
                "nexus.scanner.crawler.asyncio.open_connection",
                AsyncMock(return_value=(None, _DummyWriter())),
            ),
            patch("nexus.scanner.crawler.asyncio.create_subprocess_exec", side_effect=_fake_exec),
            patch("nexus.scanner.crawler.httpx.AsyncClient", _FakeClient),
            patch.dict(__import__("sys").modules, {"websockets": fake_ws_mod}),
        ):
            urls, _ = await _cdp_browser_crawl("https://spa.local/", max_pages=1, timeout=5)

        assert "https://spa.local/after-load" in urls
        by_req = {
            c["params"].get("requestId"): (c["method"], c["params"])
            for c in sent_cmds
            if isinstance(c.get("params"), dict) and "requestId" in c["params"]
        }
        assert by_req["r-ws"] == (
            "Fetch.failRequest",
            {"requestId": "r-ws", "errorReason": "Aborted"},
        )

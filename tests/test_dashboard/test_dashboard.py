"""Tests for the NEXUS Dashboard — tests FastAPI endpoints if available, skips otherwise."""

from __future__ import annotations

import json

import pytest

# Skip all tests if FastAPI not installed
fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from nexus.core.config import NexusConfig
from nexus.core.engine import NexusEngine
from nexus.dashboard.app import DashboardApp, _fallback_html, create_app


@pytest.fixture
def engine(tmp_path):
    config = NexusConfig(
        data_dir=tmp_path / ".nexus",
        db_path=tmp_path / ".nexus" / "nexus.db",
        output_dir=tmp_path / "output",
    )
    eng = NexusEngine(config)
    eng.boot()
    return eng


@pytest.fixture
def client(engine):
    app = create_app(engine)
    return TestClient(app)


class TestDashboardAPI:
    def test_status_endpoint(self, client):
        r = client.get("/api/status")
        assert r.status_code == 200
        data = r.json()
        assert "version" in data
        assert data["booted"] is True
        assert "brain" in data

    def test_list_engagements_empty(self, client):
        r = client.get("/api/engagements")
        assert r.status_code == 200
        assert r.json() == []

    def test_get_engagement_not_found(self, client):
        r = client.get("/api/engagements/nonexistent")
        assert r.status_code == 404

    def test_get_findings_empty(self, client, engine):
        # Create an engagement first
        eng = engine.create_engagement("test.example.com")
        r = client.get(f"/api/engagements/{eng.id}/findings")
        assert r.status_code == 200
        assert r.json() == []

    def test_get_chains_empty(self, client, engine):
        eng = engine.create_engagement("test.example.com")
        r = client.get(f"/api/engagements/{eng.id}/chains")
        assert r.status_code == 200
        assert r.json() == []

    def test_get_targets_empty(self, client, engine):
        eng = engine.create_engagement("test.example.com")
        r = client.get(f"/api/engagements/{eng.id}/targets")
        assert r.status_code == 200
        assert r.json() == []

    def test_index_page(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "NEXUS" in r.text

    def test_engagement_with_data(self, client, engine):
        # Create engagement and add data
        eng = engine.create_engagement("example.com", name="Test Engagement")
        from nexus.db.models import Finding, Severity, Target

        t = Target(engagement_id=eng.id, host="example.com", ip="93.184.216.34", is_live=True)
        engine.db.add_target(t)
        f = Finding(
            engagement_id=eng.id,
            host="example.com",
            port=443,
            title="SSL/TLS Certificate Mismatch",
            severity=Severity.LOW,
            tool_source="nexus",
        )
        engine.db.add_finding(f)

        # List engagements
        r = client.get("/api/engagements")
        engs = r.json()
        assert len(engs) == 1
        assert engs[0]["target"] == "example.com"

        # Get engagement summary
        r = client.get(f"/api/engagements/{eng.id}")
        summary = r.json()
        assert summary["targets_found"] == 1

        # Get findings
        r = client.get(f"/api/engagements/{eng.id}/findings")
        findings = r.json()
        assert len(findings) == 1
        assert findings[0]["title"] == "SSL/TLS Certificate Mismatch"

    def test_websocket_ping_pong(self, client):
        with client.websocket_connect("/ws") as ws:
            ws.send_text("ping")
            assert ws.receive_text() == "pong"

    def test_sarif_diff_and_suppressed_filter_endpoints(self, client, engine):
        from nexus.db.models import Finding, Severity

        st = client.get("/api/status").json()
        assert "profile" in st

        e1 = engine.create_engagement("ci.local", name="base")
        engine.db.add_finding(
            Finding(
                engagement_id=e1.id,
                host="ci.local",
                port=443,
                title="Missing HSTS",
                cwe_id="CWE-523",
                severity=Severity.LOW,
            )
        )
        e2 = engine.create_engagement("ci.local", name="head")
        engine.db.add_finding(
            Finding(
                engagement_id=e2.id,
                host="ci.local",
                port=443,
                title="Missing HSTS",
                cwe_id="CWE-523",
                severity=Severity.LOW,
            )
        )
        engine.db.add_finding(
            Finding(
                engagement_id=e2.id,
                host="ci.local",
                port=6379,
                title="Redis Unauth",
                cwe_id="CWE-306",
                severity=Severity.HIGH,
            )
        )
        engine.db.add_finding(
            Finding(
                engagement_id=e2.id,
                host="ci.local",
                port=80,
                title="Ignored Info",
                cwe_id="CWE-693",
                severity=Severity.INFO,
                false_positive=True,
            )
        )

        all_f = client.get(f"/api/engagements/{e2.id}/findings").json()
        active_f = client.get(f"/api/engagements/{e2.id}/findings?include_suppressed=false").json()
        assert len(all_f) == 3
        assert len(active_f) == 2

        sarif_resp = client.get(f"/api/engagements/{e2.id}/sarif")
        assert sarif_resp.status_code == 200
        doc = sarif_resp.json()
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"][0]["results"]) == 3

        assert client.get("/api/engagements/missing_id/sarif").status_code == 404

        diff_resp = client.get(f"/api/diff?old={e1.id}&new={e2.id}")
        assert diff_resp.status_code == 200
        diff_data = diff_resp.json()
        assert diff_data["counts"] == {"new": 1, "resolved": 0, "persistent": 1, "suppressed": 1}

        assert client.get(f"/api/diff?old=missing&new={e2.id}").status_code == 404


class TestFallbackHTML:
    def test_fallback_html_contains_nexus(self):
        html = _fallback_html()
        assert "NEXUS" in html
        assert "/api/status" in html
        assert "/api/engagements" in html
        assert "function esc(" in html


class TestDashboardApp:
    def test_dashboard_app_creation(self, engine):
        dash = DashboardApp(engine)
        assert dash.app is not None
        assert dash.engine._booted is True

    def test_static_spa_has_sarif_diff_and_suppressed_controls(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "Download SARIF" in r.text
        assert "Show suppressed" in r.text
        assert "runDiff()" in r.text
        assert "/api/diff" in r.text
        assert "/sarif" in r.text
        assert "data-eng-id=" in r.text
        assert "loadFindings('" not in r.text
        assert "&quot;" in r.text
        assert "findings-search" in r.text
        assert "findings-sev" in r.text
        assert "dash-token-input" in r.text
        assert "tab-chains" in r.text
        assert "tab-targets" in r.text
        assert "?token=" not in r.text
        assert "location.reload()" not in r.text

    def test_nonexistent_engagement_subresources_return_404(self, client):
        assert client.get("/api/engagements/missing/findings").status_code == 404
        assert client.get("/api/engagements/missing/chains").status_code == 404
        assert client.get("/api/engagements/missing/targets").status_code == 404

    def test_dashboard_token_auth_and_remediation_enrichment(self, engine, tmp_path):
        from starlette.websockets import WebSocketDisconnect

        from nexus.db.models import Finding, Severity

        eng = engine.create_engagement("sec.local", name="Auth Test")
        engine.db.add_finding(
            Finding(
                engagement_id=eng.id,
                host="sec.local",
                port=443,
                title="Log4Shell Match",
                cwe_id="CWE-917",
                cve_ids=["CVE-2021-44228"],
                severity=Severity.CRITICAL,
            )
        )

        auth_app = create_app(engine, api_token="dash_secret_tok_99")
        auth_client = TestClient(auth_app)

        # Unauthenticated / invalid tokens rejected safely with 401 (never 500 TypeError)
        assert auth_client.get("/api/status").status_code == 401
        assert auth_client.get("/api/engagements").status_code == 401
        assert auth_client.get("/").status_code == 200

        # Valid X-Nexus-Token and Authorization: Bearer allowed, remediation enriched
        assert (
            auth_client.get(
                "/api/status", headers={"X-Nexus-Token": "dash_secret_tok_99"}
            ).status_code
            == 200
        )
        fr = auth_client.get(
            f"/api/engagements/{eng.id}/findings",
            headers={"Authorization": "Bearer dash_secret_tok_99"},
        )
        assert fr.status_code == 200
        rows = fr.json()
        assert len(rows) == 1 and "Log4j2" in rows[0]["remediation"]

        # WebSocket rejects query-string ?token=, invalid header, and bad initial auth frame (code 1008)
        with pytest.raises(WebSocketDisconnect):
            with auth_client.websocket_connect("/ws?token=dash_secret_tok_99") as ws:
                ws.send_text("ping")
                ws.receive_text()

        with pytest.raises(WebSocketDisconnect):
            with auth_client.websocket_connect(
                "/ws", headers={"Authorization": "Bearer wrong"}
            ) as ws:
                ws.receive_text()

        with pytest.raises(WebSocketDisconnect):
            with auth_client.websocket_connect("/ws") as ws:
                ws.send_text(json.dumps({"type": "auth", "token": "é_invalid"}))
                ws.receive_text()

        # Accepts initial auth frame {"type": "auth", "token": ...}
        with auth_client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "token": "dash_secret_tok_99"}))
            auth_ack = json.loads(ws.receive_text())
            assert auth_ack["status"] == "ok"
            ws.send_text("ping")
            assert ws.receive_text() == "pong"

        # Accepts Authorization: Bearer header on WS handshake
        with auth_client.websocket_connect(
            "/ws", headers={"Authorization": "Bearer dash_secret_tok_99"}
        ) as ws:
            ws.send_text("ping")
            assert ws.receive_text() == "pong"

    @pytest.mark.asyncio
    async def test_broadcast_and_ws_cleanup(self, engine):
        dash = DashboardApp(engine)
        assert engine.on_progress == dash.broadcast
        client = TestClient(dash.app)
        with client.websocket_connect("/ws") as ws:
            await dash.broadcast("scan_complete", {"findings": 3})
            msg = json.loads(ws.receive_text())
            assert msg["event"] == "scan_complete"
            assert msg["data"]["findings"] == 3
        assert dash._ws_clients == []

    def test_non_loopback_run_dashboard_generates_ephemeral_token(self, engine, capsys):
        from unittest.mock import patch

        from nexus.dashboard.app import run_dashboard

        with patch("uvicorn.run") as mock_uv:
            run_dashboard(host="0.0.0.0", port=8477, engine=engine)

        mock_uv.assert_called_once()
        err = capsys.readouterr().err
        assert "auto-generated dashboard token" in err

    def test_proxy_history_endpoints_diff_and_fallback_auth_ui(self, engine):
        from nexus.db.models import ProxyEntry

        eng = engine.create_engagement("proxy.example.test")
        e1 = ProxyEntry(
            engagement_id=eng.id,
            method="GET",
            url="https://proxy.example.test/items?id=1",
            host="proxy.example.test",
            port=443,
            status_code=200,
            response_body="alpha\nbeta\n",
        )
        e2 = ProxyEntry(
            engagement_id=eng.id,
            method="GET",
            url="https://proxy.example.test/items?id=2",
            host="proxy.example.test",
            port=443,
            status_code=403,
            response_body="alpha\ngamma\n",
        )
        engine.db.add_proxy_entry(e1)
        engine.db.add_proxy_entry(e2)

        dash = DashboardApp(engine)
        client = TestClient(dash.app)

        r_eng = client.get(f"/api/engagements/{eng.id}/proxy")
        assert r_eng.status_code == 200
        assert len(r_eng.json()) == 2

        r_all = client.get("/api/proxy/history")
        assert r_all.status_code == 200
        assert len(r_all.json()) >= 2

        r_diff = client.get(f"/api/proxy/diff?left={e1.id}&right={e2.id}")
        assert r_diff.status_code == 200
        diff_data = r_diff.json()
        assert diff_data["left"]["status_code"] == 200
        assert diff_data["right"]["status_code"] == 403
        assert "-beta" in diff_data["diff"]
        assert "+gamma" in diff_data["diff"]

        r_missing = client.get("/api/proxy/diff?left=missing1&right=missing2")
        assert r_missing.status_code == 404

        from nexus.dashboard.app import _fallback_html

        fallback = _fallback_html()
        assert "X-Nexus-Token" in fallback
        assert "sessionStorage" in fallback
        assert "'auth'" in fallback

        index_html = client.get("/").text
        assert "Proxy History" in index_html or "/api/proxy/diff" in index_html
        assert "proxy-repeater-send" in index_html
        assert "rep-url" in index_html

        # Priority backlog endpoint
        from nexus.db.models import Finding, Severity

        engine.db.add_finding(
            Finding(
                engagement_id=eng.id,
                host="proxy.example.test",
                title="KEV Alert",
                cve_ids=["CVE-2021-44228"],
                severity=Severity.CRITICAL,
                confirmed=True,
            )
        )
        r_pri = client.get(f"/api/engagements/{eng.id}/priority")
        assert r_pri.status_code == 200
        assert r_pri.json()["kev_flagged"] == 1
        assert client.get("/api/engagements/missing/priority").status_code == 404

    def test_proxy_replay_scope_validation_and_persistence(self, engine):
        from unittest.mock import AsyncMock, MagicMock, patch

        from nexus.core.scope import ScopeEnforcer

        dash = DashboardApp(engine)
        client = TestClient(dash.app)

        # 1. Fail-closed when no engagement scope is active
        engine.scope = None
        r_no_scope = client.post(
            "/api/proxy/replay", json={"method": "GET", "url": "https://app.example.test/"}
        )
        assert r_no_scope.status_code == 403

        # 2. Enforce scope and reject invalid method / header / off-scope URLs
        eng = engine.create_engagement("app.example.test")
        engine.scope = ScopeEnforcer.for_target("app.example.test")
        assert (
            client.post(
                "/api/proxy/replay",
                json={"method": "GET", "url": "https://evil.otherdomain.test/"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/proxy/replay",
                json={"method": "TRACE", "url": "https://app.example.test/"},
            ).status_code
            == 400
        )
        assert (
            client.post(
                "/api/proxy/replay",
                json={
                    "method": "GET",
                    "url": "https://app.example.test/",
                    "headers": {"Bad\r\nHeader": "x"},
                },
            ).status_code
            == 400
        )

        # 3. Valid in-scope replay redacts secrets and records ProxyEntry
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.headers = {"Content-Type": "application/json", "Set-Cookie": "sid=topsecret"}
        fake_resp.text = '{"ok":true}'

        fake_client = MagicMock()
        fake_client.request = AsyncMock(return_value=fake_resp)
        fake_client.__aenter__ = AsyncMock(return_value=fake_client)
        fake_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("nexus.core.scope.socket.getaddrinfo", return_value=[]),
            patch("nexus.scanner._http.make_http_client", return_value=fake_client),
        ):
            r_ok = client.post(
                "/api/proxy/replay",
                json={
                    "engagement_id": eng.id,
                    "method": "POST",
                    "url": "https://app.example.test/api/v1",
                    "headers": {"Authorization": "Bearer secret-tok"},
                    "body": '{"test":1}',
                },
            )
        assert r_ok.status_code == 200
        data = r_ok.json()
        assert data["status_code"] == 200
        assert data["request_headers"]["Authorization"] != "Bearer secret-tok"
        assert len(engine.db.get_proxy_history(eng.id)) >= 1

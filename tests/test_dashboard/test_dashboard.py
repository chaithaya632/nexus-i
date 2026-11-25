"""Tests for the NEXUS Dashboard — tests FastAPI endpoints if available, skips otherwise."""

from __future__ import annotations

import pytest
import json

# Skip all tests if FastAPI not installed
fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient
from nexus.dashboard.app import create_app, DashboardApp, _fallback_html
from nexus.core.engine import NexusEngine
from nexus.core.config import NexusConfig


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
        from nexus.db.models import Finding, Target, Severity
        t = Target(engagement_id=eng.id, host="example.com", ip="93.184.216.34", is_live=True)
        engine.db.add_target(t)
        f = Finding(
            engagement_id=eng.id, host="example.com", port=443,
            title="SSL/TLS Certificate Mismatch", severity=Severity.LOW,
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
        engine.db.add_finding(Finding(
            engagement_id=e1.id, host="ci.local", port=443, title="Missing HSTS",
            cwe_id="CWE-523", severity=Severity.LOW,
        ))
        e2 = engine.create_engagement("ci.local", name="head")
        engine.db.add_finding(Finding(
            engagement_id=e2.id, host="ci.local", port=443, title="Missing HSTS",
            cwe_id="CWE-523", severity=Severity.LOW,
        ))
        engine.db.add_finding(Finding(
            engagement_id=e2.id, host="ci.local", port=6379, title="Redis Unauth",
            cwe_id="CWE-306", severity=Severity.HIGH,
        ))
        engine.db.add_finding(Finding(
            engagement_id=e2.id, host="ci.local", port=80, title="Ignored Info",
            cwe_id="CWE-693", severity=Severity.INFO, false_positive=True,
        ))

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

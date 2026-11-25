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

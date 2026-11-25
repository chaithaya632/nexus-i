"""Tests for nexus.db.store."""

import json
from pathlib import Path

import pytest

from nexus.db.models import (
    AttackChain,
    ChainStep,
    Credential,
    Engagement,
    EngagementPhase,
    Finding,
    Port,
    Severity,
    Target,
)
from nexus.db.store import EngagementStore


@pytest.fixture
def store(tmp_path) -> EngagementStore:
    return EngagementStore(tmp_path / "test.db")


class TestEngagementStore:
    def test_create_and_get_engagement(self, store):
        eng = Engagement(name="test", target="example.com")
        eng_id = store.create_engagement(eng)

        retrieved = store.get_engagement(eng_id)
        assert retrieved is not None
        assert retrieved.name == "test"
        assert retrieved.target == "example.com"
        assert retrieved.phase == EngagementPhase.INIT

    def test_list_engagements(self, store):
        store.create_engagement(Engagement(name="e1", target="a.com"))
        store.create_engagement(Engagement(name="e2", target="b.com"))
        engs = store.list_engagements()
        assert len(engs) == 2

    def test_update_phase(self, store):
        eng = Engagement(name="test", target="example.com")
        eng_id = store.create_engagement(eng)
        store.update_phase(eng_id, EngagementPhase.RECON)

        retrieved = store.get_engagement(eng_id)
        assert retrieved.phase == EngagementPhase.RECON

    def test_delete_engagement(self, store):
        eng = Engagement(name="test", target="example.com")
        eng_id = store.create_engagement(eng)
        store.delete_engagement(eng_id)
        assert store.get_engagement(eng_id) is None

    def test_add_target(self, store):
        eng = Engagement(name="test", target="example.com")
        eng_id = store.create_engagement(eng)
        target = Target(engagement_id=eng_id, host="sub.example.com",
                        ip="10.0.0.1", is_live=True, tech_stack=["nginx", "php"])
        store.add_target(target)

        targets = store.get_targets(eng_id)
        assert len(targets) == 1
        assert targets[0].host == "sub.example.com"
        assert "nginx" in targets[0].tech_stack

    def test_add_port(self, store):
        eng = Engagement(name="test", target="example.com")
        eng_id = store.create_engagement(eng)
        target = Target(engagement_id=eng_id, host="example.com")
        tid = store.add_target(target)

        port = Port(target_id=tid, port=80, service="http", version="nginx/1.18")
        store.add_port(port)

        ports = store.get_ports(tid)
        assert len(ports) == 1
        assert ports[0].port == 80
        assert ports[0].service == "http"

    def test_add_finding(self, store):
        eng = Engagement(name="test", target="example.com")
        eng_id = store.create_engagement(eng)

        finding = Finding(
            engagement_id=eng_id, host="example.com", port=80,
            title="SQL Injection", severity=Severity.CRITICAL,
            cve_ids=["CVE-2024-1234"], tool_source="sqlmap",
        )
        store.add_finding(finding)

        findings = store.get_findings(eng_id)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "CVE-2024-1234" in findings[0].cve_ids

    def test_findings_by_severity(self, store):
        eng = Engagement(name="test", target="example.com")
        eng_id = store.create_engagement(eng)

        store.add_finding(Finding(engagement_id=eng_id, title="crit", severity=Severity.CRITICAL))
        store.add_finding(Finding(engagement_id=eng_id, title="high", severity=Severity.HIGH))
        store.add_finding(Finding(engagement_id=eng_id, title="info", severity=Severity.INFO))

        counts = store.count_findings_by_severity(eng_id)
        assert counts.get("critical") == 1
        assert counts.get("high") == 1
        assert counts.get("info") == 1

    def test_add_credential(self, store):
        eng = Engagement(name="test", target="example.com")
        eng_id = store.create_engagement(eng)

        cred = Credential(engagement_id=eng_id, host="example.com", port=22,
                          service="ssh", username="admin", password="admin123",
                          source="hydra", confirmed=True)
        store.add_credential(cred)

        creds = store.get_credentials(eng_id)
        assert len(creds) == 1
        assert creds[0].username == "admin"
        assert creds[0].confirmed is True

    def test_add_chain(self, store):
        eng = Engagement(name="test", target="example.com")
        eng_id = store.create_engagement(eng)

        chain = AttackChain(
            engagement_id=eng_id, name="SQLi to RCE",
            steps=[
                ChainStep(order=1, action="sqli", tool="sqlmap", target="example.com"),
                ChainStep(order=2, action="rce", tool="custom", target="example.com"),
            ],
            confidence=0.8, impact=Severity.CRITICAL,
        )
        store.add_chain(chain)

        chains = store.get_chains(eng_id)
        assert len(chains) == 1
        assert chains[0].name == "SQLi to RCE"
        assert len(chains[0].steps) == 2

    def test_export_json(self, store):
        eng = Engagement(name="test", target="example.com")
        eng_id = store.create_engagement(eng)
        store.add_finding(Finding(engagement_id=eng_id, title="test finding"))
        store.add_credential(Credential(
            engagement_id=eng_id, host="example.com", port=22,
            service="ssh", username="svc_user", password="super_secret_pw_val",
            hash_value="ntlm_secret_hash_val", source="audit", confirmed=True,
        ))

        data = store.export_engagement_json(eng_id)
        assert "engagement" in data
        assert "findings" in data
        assert len(data["findings"]) == 1
        assert data["credentials"][0]["password"] == "***REDACTED***"
        assert data["credentials"][0]["hash_value"] == "***REDACTED***"
        assert "super_secret_pw_val" not in str(data)
        assert "ntlm_secret_hash_val" not in str(data)

    def test_nonexistent_engagement(self, store):
        assert store.get_engagement("nonexistent") is None
        data = store.export_engagement_json("nonexistent")
        assert data == {}

    def test_update_target_after_port_preserves_fk(self, store):
        """Regression: add_target() after add_port() must update via ON CONFLICT without FK failure."""
        eng = Engagement(name="fk_test", target="app.local")
        eng_id = store.create_engagement(eng)
        t = Target(engagement_id=eng_id, host="app.local")
        store.add_target(t)
        store.add_port(Port(target_id=t.id, port=80, service="http"))

        # Re-save enriched target with child port existing
        t.is_live = True
        t.os_guess = "Linux"
        t.tech_stack = ["nginx"]
        store.add_target(t)

        assert store.get_targets(eng_id)[0].os_guess == "Linux"
        assert len(store.get_ports(t.id)) == 1

        # replace_findings + delete_engagement cascade cleanly
        store.add_finding(Finding(engagement_id=eng_id, title="raw1"))
        store.add_finding(Finding(engagement_id=eng_id, title="raw2"))
        store.replace_findings(eng_id, [Finding(engagement_id=eng_id, title="deduped", owasp_category="A03")])
        assert [f.title for f in store.get_findings(eng_id)] == ["deduped"]

        store.delete_engagement(eng_id)
        assert store.get_ports(t.id) == []
        assert store.get_findings(eng_id) == []


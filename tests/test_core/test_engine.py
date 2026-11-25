"""Engine lifecycle tests — boot, create_engagement, summary, shutdown."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from nexus.core.config import NexusConfig, Tier, StealthLevel
from nexus.core.engine import NexusEngine


@pytest.fixture()
def engine(tmp_path: Path) -> NexusEngine:
    """Return a booted engine using a temp directory."""
    cfg = NexusConfig(
        data_dir=tmp_path / "nexus_data",
        db_path=str(tmp_path / "test.db"),
        tier=Tier.MINIMAL,
        stealth=StealthLevel.OFF,
    )
    eng = NexusEngine(cfg)
    eng.boot()
    yield eng
    eng.shutdown()


class TestEngineLifecycle:
    """Boot → use → shutdown tests."""

    def test_boot_sets_flag(self, engine: NexusEngine) -> None:
        assert engine._booted is True

    def test_double_boot_is_noop(self, engine: NexusEngine) -> None:
        engine.boot()  # second call, should not crash
        assert engine._booted is True

    def test_shutdown_clears_flag(self, tmp_path: Path) -> None:
        cfg = NexusConfig(
            data_dir=tmp_path / "sd",
            db_path=str(tmp_path / "sd.db"),
            tier=Tier.MINIMAL,
        )
        eng = NexusEngine(cfg)
        eng.boot()
        eng.shutdown()
        assert eng._booted is False

    def test_require_boot_raises(self) -> None:
        eng = NexusEngine()
        with pytest.raises(RuntimeError, match="boot"):
            eng._require_boot()


class TestBrainStats:
    """brain_stats() returns populated dict after boot."""

    def test_has_expert_rules(self, engine: NexusEngine) -> None:
        stats = engine.brain_stats()
        assert "expert_rules" in stats
        assert stats["expert_rules"] > 0

    def test_has_chain_stats(self, engine: NexusEngine) -> None:
        stats = engine.brain_stats()
        assert "nodes" in stats or "edges" in stats

    def test_ai_key_present(self, engine: NexusEngine) -> None:
        stats = engine.brain_stats()
        # AI boost is always initialized; available may be False on Windows
        assert "ai_available" in stats


class TestEngagement:
    """create_engagement and engagement_summary."""

    def test_create_engagement(self, engine: NexusEngine) -> None:
        eng = engine.create_engagement("example.com", "test-eng")
        assert eng.id
        assert eng.target == "example.com"
        assert eng.name == "test-eng"

    def test_engagement_summary(self, engine: NexusEngine) -> None:
        eng = engine.create_engagement("example.com")
        summary = engine.engagement_summary(eng.id)
        assert summary["id"] == eng.id
        assert summary["target"] == "example.com"
        assert "severity_counts" in summary

    def test_summary_not_found(self, engine: NexusEngine) -> None:
        result = engine.engagement_summary("nonexistent-id")
        assert result == {}


class TestStealthMapping:
    """Stealth config levels map correctly to controller profiles."""

    @pytest.mark.parametrize(
        "level,expected_profile",
        [
            (StealthLevel.OFF, "loud"),
            (StealthLevel.LOW, "loud"),
            (StealthLevel.MEDIUM, "normal"),
            (StealthLevel.HIGH, "quiet"),
            (StealthLevel.PARANOID, "ghost"),
        ],
    )
    def test_stealth_level_maps(
        self, tmp_path: Path, level: StealthLevel, expected_profile: str,
    ) -> None:
        cfg = NexusConfig(
            data_dir=tmp_path / f"s_{level.value}",
            db_path=str(tmp_path / f"s_{level.value}.db"),
            tier=Tier.MINIMAL,
            stealth=level,
        )
        eng = NexusEngine(cfg)
        eng.boot()
        assert eng.stealth is not None
        assert eng.stealth.level == expected_profile
        eng.shutdown()


class TestEngineIntegrationContracts:
    """Tests for scope wiring, FK ordering in recon, correlate persistence, and plugins."""

    def test_scope_propagates_to_exploit_executor(self, engine: NexusEngine, tmp_path: Path) -> None:
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("allowed_domains:\n  - example.com\n", encoding="utf-8")

        engine.create_engagement("example.com", scope_file=str(scope_file))
        assert engine.scope is not None
        assert engine.exploit_executor is not None
        assert engine.exploit_executor._scope is engine.scope
        assert engine.scope.is_in_scope("example.com")
        assert not engine.scope.is_in_scope("evil.com")

    @pytest.mark.asyncio
    async def test_run_recon_rejects_out_of_scope_target(self, engine: NexusEngine, tmp_path: Path) -> None:
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("allowed_domains:\n  - allowed.com\n", encoding="utf-8")
        eng = engine.create_engagement("allowed.com", scope_file=str(scope_file))

        with pytest.raises(ValueError, match="SCOPE VIOLATION"):
            await engine.run_recon(eng.id, "evil.com")

    @pytest.mark.asyncio
    async def test_run_recon_ports_and_correlate_persistence(self, engine: NexusEngine) -> None:
        from unittest.mock import patch, AsyncMock
        from nexus.db.models import Finding, Port, Severity, Target

        eng = engine.create_engagement("app.local")
        fake_nmap = {
            "targets": [Target(host="app.local", ip="127.0.0.1", is_live=True, os_guess="Linux 6.x")],
            "ports": [Port(port=8080, protocol="tcp", state="open", service="http", version="Apache/2.4")],
            "findings": [Finding(
                host="app.local", port=8080, protocol="http",
                title="SQL Injection in login", cwe_id="CWE-89",
                severity=Severity.HIGH, tool_source="nmap",
            )],
            "raw_xml": "",
        }

        with (
            patch("nexus.core.engine.enumerate_subdomains", AsyncMock(return_value=[Target(host="app.local")])),
            patch("nexus.core.engine.enumerate_dns", AsyncMock(side_effect=lambda ts: (ts, []))),
            patch("nexus.core.engine.nmap_scan", AsyncMock(return_value=fake_nmap)),
            patch("nexus.core.engine.detect_tech_stack", AsyncMock(side_effect=lambda ts: ts)),
            patch("nexus.core.engine.detect_waf", AsyncMock(side_effect=lambda ts: (ts, []))),
            patch("nexus.core.engine.gather_osint", AsyncMock(return_value=([], []))),
        ):
            findings = await engine.run_recon(eng.id, "app.local")

        assert len(findings) == 1
        targets_in_db = engine.db.get_targets(eng.id)
        assert len(targets_in_db) == 1
        assert targets_in_db[0].is_live is True
        ports_in_db = engine.db.get_ports(targets_in_db[0].id)
        assert len(ports_in_db) == 1
        assert ports_in_db[0].port == 8080

        # Correlate should persist OWASP/remediation/chains back to SQLite
        chains = await engine.run_correlate(eng.id)
        assert len(chains) > 0
        persisted_findings = engine.db.get_findings(eng.id)
        assert len(persisted_findings) == 1
        assert "A03" in persisted_findings[0].owasp_category
        assert persisted_findings[0].remediation != ""

    def test_plugins_and_cves_loaded_on_boot(self, engine: NexusEngine) -> None:
        stats = engine.brain_stats()
        assert stats.get("knowledge_cves", 0) >= 20
        assert "plugins" in stats

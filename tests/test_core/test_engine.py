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
        assert stats.get("vector_entries", 0) >= 20
        assert "plugins" in stats

    @pytest.mark.asyncio
    async def test_run_recon_parallel_and_banner_cve(self, engine: NexusEngine) -> None:
        from unittest.mock import patch, AsyncMock
        from nexus.core.config import ScanProfile
        from nexus.db.models import Port, Target

        engine.config.profile = ScanProfile.QUICK
        eng = engine.create_engagement("multi.local")

        async def _fake_nmap(host: str, stealth: str = "normal"):
            if host == "web.multi.local":
                return {
                    "targets": [Target(host="web.multi.local", ip="10.0.0.10", is_live=True)],
                    "ports": [Port(port=80, protocol="tcp", state="open", service="http", version="Apache/2.4.49")],
                    "findings": [],
                    "raw_xml": "",
                }
            return {
                "targets": [Target(host="ssh.multi.local", ip="10.0.0.11", is_live=True)],
                "ports": [Port(port=22, protocol="tcp", state="open", service="ssh", version="OpenSSH 8.9p1")],
                "findings": [],
                "raw_xml": "",
            }

        with (
            patch(
                "nexus.core.engine.enumerate_subdomains",
                AsyncMock(return_value=[Target(host="web.multi.local"), Target(host="ssh.multi.local")]),
            ),
            patch("nexus.core.engine.enumerate_dns", AsyncMock(side_effect=lambda ts: (ts, []))),
            patch("nexus.core.engine.nmap_scan", AsyncMock(side_effect=_fake_nmap)),
            patch("nexus.core.engine.detect_tech_stack", AsyncMock(side_effect=lambda ts: ts)),
            patch("nexus.core.engine.detect_waf", AsyncMock(side_effect=lambda ts: (ts, []))) as mock_waf,
            patch("nexus.core.engine.gather_osint", AsyncMock(return_value=([], []))) as mock_osint,
        ):
            findings = await engine.run_recon(eng.id, "multi.local")

        # QUICK profile skips WAF & OSINT
        mock_waf.assert_not_called()
        mock_osint.assert_not_called()
        all_cves = {c for f in findings for c in f.cve_ids}
        assert "CVE-2021-41773" in all_cves
        assert "CVE-2024-6387" in all_cves
        assert all(f.tool_source == "knowledge_banner" for f in findings if f.cve_ids)

    @pytest.mark.asyncio
    async def test_run_scan_dynamic_routing_and_waf_throttle(self, engine: NexusEngine) -> None:
        from unittest.mock import patch, AsyncMock
        from nexus.core.config import ScanProfile
        from nexus.db.models import Finding, Port, Severity, Target

        engine.config.profile = ScanProfile.WEB
        eng = engine.create_engagement("web.local")
        t = Target(
            engagement_id=eng.id,
            host="web.local",
            ip="10.0.0.20",
            is_live=True,
            tech_stack=["WordPress", "PHP"],
            waf_detected="Cloudflare",
        )
        engine.db.add_target(t)
        engine.db.add_port(Port(target_id=t.id, port=443, protocol="tcp", state="open", service="https"))
        engine.db.add_port(Port(target_id=t.id, port=22, protocol="tcp", state="open", service="ssh"))

        nuclei_mock = AsyncMock(return_value=[])
        ffuf_mock = AsyncMock(return_value=[])
        tls_mock = AsyncMock(return_value=[
            Finding(host="web.local", port=443, protocol="https", title="TLS Check", severity=Severity.LOW, tool_source="sslyze")
        ])
        ssh_mock = AsyncMock(return_value=[
            Finding(host="web.local", port=22, protocol="ssh", title="SSH Check", severity=Severity.LOW, tool_source="nmap_ssh")
        ])

        with (
            patch(
                "nexus.core.engine.ToolRunner.is_available",
                side_effect=lambda name: name in ("nuclei", "ffuf"),
            ),
            patch("nexus.core.engine.crawl_web", AsyncMock(return_value=([], []))),
            patch("nexus.core.engine.audit_http_security", AsyncMock(return_value=[])),
            patch("nexus.core.engine.nuclei_scan", nuclei_mock),
            patch("nexus.core.engine.ffuf_scan", ffuf_mock),
            patch("nexus.core.engine.audit_tls", tls_mock),
            patch("nexus.core.engine.audit_ssh", ssh_mock),
        ):
            findings = await engine.run_scan(eng.id, "web.local")

        # WEB profile runs nuclei & TLS, skips SSH
        assert len(findings) == 1
        assert findings[0].tool_source == "sslyze"
        tls_mock.assert_awaited_once_with("web.local", 443)
        ssh_mock.assert_not_awaited()

        # Cloudflare WAF should throttle stealth to quiet and apply targeted tags
        assert nuclei_mock.call_args.kwargs["stealth"] == "quiet"
        assert nuclei_mock.call_args.kwargs["extra_args"] == ["-tags", "php,wordpress"]
        assert ffuf_mock.call_args.kwargs["stealth"] == "quiet"

        # Audit log should capture routing_plan with RuleEngine decisions
        import json
        ok, _ = engine.audit.verify_chain()
        assert ok is True
        entries = [
            json.loads(line)
            for line in engine.audit._path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        routing_entries = [e for e in entries if e.get("action") == "routing_plan"]
        assert len(routing_entries) == 1
        plan = routing_entries[0]["extra"]
        assert plan["effective_stealth"] == "quiet"
        rule_names = {r["rule"] for r in plan["expert_rules"]}
        assert "https_detected" in rule_names
        assert "wordpress_detected" in rule_names
        assert "waf_cloudflare" in rule_names

    @pytest.mark.asyncio
    async def test_run_scan_network_profile_skips_web_and_runs_ssh_tls(self, engine: NexusEngine) -> None:
        from unittest.mock import patch, AsyncMock
        from nexus.core.config import ScanProfile
        from nexus.db.models import Finding, Port, Severity, Target

        engine.config.profile = ScanProfile.NETWORK
        eng = engine.create_engagement("net.local")
        t = Target(engagement_id=eng.id, host="net.local", ip="10.0.0.30", is_live=True)
        engine.db.add_target(t)
        engine.db.add_port(Port(target_id=t.id, port=443, protocol="tcp", state="open", service="https"))
        engine.db.add_port(Port(target_id=t.id, port=22, protocol="tcp", state="open", service="ssh"))

        nuclei_mock = AsyncMock(return_value=[])
        tls_mock = AsyncMock(return_value=[
            Finding(host="net.local", port=443, protocol="https", title="TLS Test", severity=Severity.LOW, tool_source="sslyze")
        ])
        ssh_mock = AsyncMock(return_value=[
            Finding(host="net.local", port=22, protocol="ssh", title="SSH Test", severity=Severity.LOW, tool_source="nmap_ssh")
        ])

        with (
            patch("nexus.core.engine.ToolRunner.is_available", return_value=True),
            patch("nexus.core.engine.nuclei_scan", nuclei_mock),
            patch("nexus.core.engine.audit_tls", tls_mock),
            patch("nexus.core.engine.audit_ssh", ssh_mock),
        ):
            findings = await engine.run_scan(eng.id, "net.local")

        nuclei_mock.assert_not_awaited()
        assert {f.tool_source for f in findings} == {"sslyze", "nmap_ssh"}

    @pytest.mark.asyncio
    async def test_engage_resume_skips_completed_phases(self, engine: NexusEngine, tmp_path: Path) -> None:
        from unittest.mock import patch, AsyncMock
        from nexus.db.models import EngagementPhase

        eng = engine.create_engagement("resume.local")
        engine._advance_phase(eng.id, EngagementPhase.CORRELATE)

        recon_mock = AsyncMock(return_value=[])
        scan_mock = AsyncMock(return_value=[])
        correlate_mock = AsyncMock(return_value=[])
        exploit_mock = AsyncMock(return_value=[])

        with (
            patch.object(engine, "run_recon", recon_mock),
            patch.object(engine, "run_scan", scan_mock),
            patch.object(engine, "run_correlate", correlate_mock),
            patch.object(engine, "run_exploit", exploit_mock),
            patch("nexus.core.engine.generate_report", return_value=[tmp_path / "r.md"]) as mock_rep,
        ):
            resumed_id = await engine.engage(skip_exploit=True, profile="quick", resume_id=eng.id)

        assert resumed_id == eng.id
        recon_mock.assert_not_awaited()
        scan_mock.assert_not_awaited()
        correlate_mock.assert_awaited_once_with(eng.id)
        exploit_mock.assert_not_awaited()
        mock_rep.assert_called_once()
        assert engine.db.get_engagement(eng.id).phase == EngagementPhase.COMPLETE

    @pytest.mark.asyncio
    async def test_run_scan_wave2_auth_openapi_crawl_headers_and_redaction(
        self, engine: NexusEngine, tmp_path: Path,
    ) -> None:
        from unittest.mock import patch, AsyncMock
        from nexus.core.config import ScanProfile
        from nexus.db.models import Finding, Port, Severity, Target

        spec_file = tmp_path / "api.yaml"
        spec_file.write_text(
            """
openapi: 3.0.3
info:
  title: Scope API
  version: "1.0"
servers:
  - url: https://api.local
paths:
  /v1/users:
    get:
      responses:
        "200":
          description: ok
""",
            encoding="utf-8",
        )
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("allowed_domains:\n  - api.local\n", encoding="utf-8")

        engine.config.profile = ScanProfile.API
        engine.config.auth_headers = {
            "Authorization": "Bearer topsecret_wave2_token",
            "Cookie": "sid=secret_cookie_val",
        }
        engine.config.openapi_spec = spec_file

        eng = engine.create_engagement("api.local", scope_file=str(scope_file))
        t = Target(engagement_id=eng.id, host="api.local", ip="10.0.0.40", is_live=True)
        engine.db.add_target(t)
        engine.db.add_port(Port(target_id=t.id, port=443, protocol="tcp", state="open", service="https"))

        crawl_mock = AsyncMock(return_value=(
            ["https://api.local/v1/from-js", "https://evil.external.com/leak"],
            [Finding(host="api.local", port=443, protocol="https", title="Client-Side Secret Exposed: Test", severity=Severity.MEDIUM, tool_source="crawler")],
        ))
        hdr_mock = AsyncMock(return_value=[
            Finding(host="api.local", port=443, protocol="https", title="HTTP: Missing CSP", severity=Severity.LOW, tool_source="http_headers", confirmed=True),
        ])
        nuclei_mock = AsyncMock(return_value=[])
        ffuf_mock = AsyncMock(return_value=[])
        tls_mock = AsyncMock(return_value=[])

        with (
            patch(
                "nexus.core.engine.ToolRunner.is_available",
                side_effect=lambda name: name in ("nuclei", "ffuf"),
            ),
            patch("nexus.core.engine.crawl_web", crawl_mock),
            patch("nexus.core.engine.audit_http_security", hdr_mock),
            patch("nexus.core.engine.nuclei_scan", nuclei_mock),
            patch("nexus.core.engine.ffuf_scan", ffuf_mock),
            patch("nexus.core.engine.audit_tls", tls_mock),
        ):
            findings = await engine.run_scan(eng.id, "api.local")

        # OpenAPI URL + same-scope crawled JS route reached nuclei (out-of-scope blocked)
        scanned_urls = nuclei_mock.call_args.args[0]
        assert "https://api.local/v1/users" in scanned_urls
        assert "https://api.local/v1/from-js" in scanned_urls
        assert all("evil.external.com" not in u for u in scanned_urls)
        assert nuclei_mock.call_args.kwargs["headers"] == engine.config.auth_headers
        assert ffuf_mock.call_args.kwargs["headers"] == engine.config.auth_headers
        assert ffuf_mock.call_count == 1
        assert ffuf_mock.call_args.args[0] == "https://api.local"
        assert hdr_mock.call_args.kwargs["headers"] == engine.config.auth_headers

        # Audit log must redact sensitive header secrets cleanly
        audit_text = engine.audit._path.read_text(encoding="utf-8")
        assert "topsecret_wave2_token" not in audit_text
        assert "secret_cookie_val" not in audit_text
        assert "***REDACTED***" in audit_text
        assert len(findings) >= 3  # OpenAPI, crawler secret, http_headers

    @pytest.mark.asyncio
    async def test_run_correlate_applies_nexusignore_baseline(self, engine: NexusEngine, tmp_path: Path) -> None:
        from nexus.db.models import Finding, Severity

        ign = tmp_path / ".nexusignore"
        ign.write_text("CWE-693\n", encoding="utf-8")
        engine.config.ignore_file = ign

        eng = engine.create_engagement("ci.local")
        engine.db.add_finding(Finding(
            engagement_id=eng.id, host="ci.local", port=443, protocol="https",
            title="Missing CSP", cwe_id="CWE-693", severity=Severity.LOW, tool_source="http_headers",
        ))
        engine.db.add_finding(Finding(
            engagement_id=eng.id, host="ci.local", port=443, protocol="https",
            title="SQL Injection", cwe_id="CWE-89", severity=Severity.CRITICAL, tool_source="nuclei",
        ))

        await engine.run_correlate(eng.id)
        counts = engine.db.count_findings_by_severity(eng.id)
        assert counts.get("critical") == 1
        assert counts.get("low", 0) == 0

        persisted = {f.cwe_id: f for f in engine.db.get_findings(eng.id)}
        assert persisted["CWE-693"].false_positive is True
        assert persisted["CWE-89"].false_positive is False
        assert engine.brain_stats().get("remediations", 0) >= 15

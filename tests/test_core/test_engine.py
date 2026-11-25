"""Engine lifecycle tests — boot, create_engagement, summary, shutdown."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus.core.config import NexusConfig, StealthLevel, Tier
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
        self,
        tmp_path: Path,
        level: StealthLevel,
        expected_profile: str,
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

    def test_scope_propagates_to_exploit_executor(
        self, engine: NexusEngine, tmp_path: Path
    ) -> None:
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("allowed_domains:\n  - example.com\n", encoding="utf-8")

        engine.create_engagement("example.com", scope_file=str(scope_file))
        assert engine.scope is not None
        assert engine.exploit_executor is not None
        assert engine.exploit_executor._scope is engine.scope
        assert engine.scope.is_in_scope("example.com")
        assert not engine.scope.is_in_scope("evil.com")

    @pytest.mark.asyncio
    async def test_run_recon_rejects_out_of_scope_target(
        self, engine: NexusEngine, tmp_path: Path
    ) -> None:
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("allowed_domains:\n  - allowed.com\n", encoding="utf-8")
        eng = engine.create_engagement("allowed.com", scope_file=str(scope_file))

        with pytest.raises(ValueError, match="SCOPE VIOLATION"):
            await engine.run_recon(eng.id, "evil.com")

    @pytest.mark.asyncio
    async def test_run_recon_ports_and_correlate_persistence(self, engine: NexusEngine) -> None:
        from unittest.mock import AsyncMock, patch

        from nexus.db.models import Finding, Port, Severity, Target

        eng = engine.create_engagement("app.local")
        fake_nmap = {
            "targets": [
                Target(host="app.local", ip="127.0.0.1", is_live=True, os_guess="Linux 6.x")
            ],
            "ports": [
                Port(port=8080, protocol="tcp", state="open", service="http", version="Apache/2.4")
            ],
            "findings": [
                Finding(
                    host="app.local",
                    port=8080,
                    protocol="http",
                    title="SQL Injection in login",
                    cwe_id="CWE-89",
                    severity=Severity.HIGH,
                    tool_source="nmap",
                )
            ],
            "raw_xml": "",
        }

        with (
            patch(
                "nexus.core.engine.enumerate_subdomains",
                AsyncMock(return_value=[Target(host="app.local")]),
            ),
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
        from unittest.mock import AsyncMock, patch

        from nexus.core.config import ScanProfile
        from nexus.db.models import Port, Target

        engine.config.profile = ScanProfile.QUICK
        eng = engine.create_engagement("multi.local")

        async def _fake_nmap(host: str, stealth: str = "normal"):
            if host == "web.multi.local":
                return {
                    "targets": [Target(host="web.multi.local", ip="10.0.0.10", is_live=True)],
                    "ports": [
                        Port(
                            port=80,
                            protocol="tcp",
                            state="open",
                            service="http",
                            version="Apache/2.4.49",
                        )
                    ],
                    "findings": [],
                    "raw_xml": "",
                }
            return {
                "targets": [Target(host="ssh.multi.local", ip="10.0.0.11", is_live=True)],
                "ports": [
                    Port(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        version="OpenSSH 8.9p1",
                    )
                ],
                "findings": [],
                "raw_xml": "",
            }

        with (
            patch(
                "nexus.core.engine.enumerate_subdomains",
                AsyncMock(
                    return_value=[Target(host="web.multi.local"), Target(host="ssh.multi.local")]
                ),
            ),
            patch("nexus.core.engine.enumerate_dns", AsyncMock(side_effect=lambda ts: (ts, []))),
            patch("nexus.core.engine.nmap_scan", AsyncMock(side_effect=_fake_nmap)),
            patch("nexus.core.engine.detect_tech_stack", AsyncMock(side_effect=lambda ts: ts)),
            patch(
                "nexus.core.engine.detect_waf", AsyncMock(side_effect=lambda ts: (ts, []))
            ) as mock_waf,
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
        from unittest.mock import AsyncMock, patch

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
        engine.db.add_port(
            Port(target_id=t.id, port=443, protocol="tcp", state="open", service="https")
        )
        engine.db.add_port(
            Port(target_id=t.id, port=22, protocol="tcp", state="open", service="ssh")
        )

        nuclei_mock = AsyncMock(return_value=[])
        ffuf_mock = AsyncMock(return_value=[])
        tls_mock = AsyncMock(
            return_value=[
                Finding(
                    host="web.local",
                    port=443,
                    protocol="https",
                    title="TLS Check",
                    severity=Severity.LOW,
                    tool_source="sslyze",
                )
            ]
        )
        ssh_mock = AsyncMock(
            return_value=[
                Finding(
                    host="web.local",
                    port=22,
                    protocol="ssh",
                    title="SSH Check",
                    severity=Severity.LOW,
                    tool_source="nmap_ssh",
                )
            ]
        )

        with (
            patch(
                "nexus.core.engine.ToolRunner.is_available",
                side_effect=lambda name: name in ("nuclei", "ffuf"),
            ),
            patch("nexus.core.engine.crawl_web", AsyncMock(return_value=([], []))),
            patch("nexus.core.engine.audit_http_security", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_exposed_artifacts", AsyncMock(return_value=[])),
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
    async def test_run_scan_network_profile_skips_web_and_runs_ssh_tls(
        self, engine: NexusEngine
    ) -> None:
        from unittest.mock import AsyncMock, patch

        from nexus.core.config import ScanProfile
        from nexus.db.models import Finding, Port, Severity, Target

        engine.config.profile = ScanProfile.NETWORK
        eng = engine.create_engagement("net.local")
        t = Target(engagement_id=eng.id, host="net.local", ip="10.0.0.30", is_live=True)
        engine.db.add_target(t)
        engine.db.add_port(
            Port(target_id=t.id, port=443, protocol="tcp", state="open", service="https")
        )
        engine.db.add_port(
            Port(target_id=t.id, port=22, protocol="tcp", state="open", service="ssh")
        )

        nuclei_mock = AsyncMock(return_value=[])
        tls_mock = AsyncMock(
            return_value=[
                Finding(
                    host="net.local",
                    port=443,
                    protocol="https",
                    title="TLS Test",
                    severity=Severity.LOW,
                    tool_source="sslyze",
                )
            ]
        )
        ssh_mock = AsyncMock(
            return_value=[
                Finding(
                    host="net.local",
                    port=22,
                    protocol="ssh",
                    title="SSH Test",
                    severity=Severity.LOW,
                    tool_source="nmap_ssh",
                )
            ]
        )

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
    async def test_engage_resume_skips_completed_phases(
        self, engine: NexusEngine, tmp_path: Path
    ) -> None:
        from unittest.mock import AsyncMock, patch

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
            patch(
                "nexus.core.engine.generate_report", return_value=[tmp_path / "r.md"]
            ) as mock_rep,
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
        self,
        engine: NexusEngine,
        tmp_path: Path,
    ) -> None:
        from unittest.mock import AsyncMock, patch

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
        engine.db.add_port(
            Port(target_id=t.id, port=443, protocol="tcp", state="open", service="https")
        )

        crawl_mock = AsyncMock(
            return_value=(
                ["https://api.local/v1/from-js", "https://evil.external.com/leak"],
                [
                    Finding(
                        host="api.local",
                        port=443,
                        protocol="https",
                        title="Client-Side Secret Exposed: Test",
                        severity=Severity.MEDIUM,
                        tool_source="crawler",
                    )
                ],
            )
        )
        hdr_mock = AsyncMock(
            return_value=[
                Finding(
                    host="api.local",
                    port=443,
                    protocol="https",
                    title="HTTP: Missing CSP",
                    severity=Severity.LOW,
                    tool_source="http_headers",
                    confirmed=True,
                ),
            ]
        )
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
            patch("nexus.core.engine.audit_exposed_artifacts", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_graphql_introspection", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_auth_enforcement", AsyncMock(return_value=[])),
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
    async def test_run_correlate_applies_nexusignore_baseline(
        self, engine: NexusEngine, tmp_path: Path
    ) -> None:
        from nexus.db.models import Finding, Severity

        ign = tmp_path / ".nexusignore"
        ign.write_text("CWE-693\n", encoding="utf-8")
        engine.config.ignore_file = ign

        eng = engine.create_engagement("ci.local")
        engine.db.add_finding(
            Finding(
                engagement_id=eng.id,
                host="ci.local",
                port=443,
                protocol="https",
                title="Missing CSP",
                cwe_id="CWE-693",
                severity=Severity.LOW,
                tool_source="http_headers",
            )
        )
        engine.db.add_finding(
            Finding(
                engagement_id=eng.id,
                host="ci.local",
                port=443,
                protocol="https",
                title="SQL Injection",
                cwe_id="CWE-89",
                severity=Severity.CRITICAL,
                tool_source="nuclei",
            )
        )

        await engine.run_correlate(eng.id)
        counts = engine.db.count_findings_by_severity(eng.id)
        assert counts.get("critical") == 1
        assert counts.get("low", 0) == 0

        persisted = {f.cwe_id: f for f in engine.db.get_findings(eng.id)}
        assert persisted["CWE-693"].false_positive is True
        assert persisted["CWE-89"].false_positive is False
        assert engine.brain_stats().get("remediations", 0) >= 15

    @pytest.mark.asyncio
    async def test_run_scan_dispatches_network_auditors(self, engine: NexusEngine) -> None:
        from unittest.mock import AsyncMock, patch

        from nexus.core.config import ScanProfile
        from nexus.db.models import Finding, Port, Severity, Target

        engine.config.profile = ScanProfile.NETWORK
        eng = engine.create_engagement("infra.local")
        t = Target(engagement_id=eng.id, host="infra.local", ip="10.0.0.50", is_live=True)
        engine.db.add_target(t)
        engine.db.add_port(
            Port(target_id=t.id, port=6379, protocol="tcp", state="open", service="redis")
        )
        engine.db.add_port(
            Port(target_id=t.id, port=445, protocol="tcp", state="open", service="microsoft-ds")
        )

        net_mock = AsyncMock(
            side_effect=[
                [
                    Finding(
                        host="infra.local",
                        port=6379,
                        protocol="redis",
                        title="Redis Open",
                        severity=Severity.HIGH,
                        tool_source="redis_probe",
                    )
                ],
                [
                    Finding(
                        host="infra.local",
                        port=445,
                        protocol="smb",
                        title="SMB Signing Disabled",
                        severity=Severity.MEDIUM,
                        tool_source="nmap_smb",
                    )
                ],
            ]
        )
        with patch("nexus.core.engine.audit_network_service", net_mock):
            findings = await engine.run_scan(eng.id, "infra.local")

        assert net_mock.await_count == 2
        assert {f.tool_source for f in findings} == {"redis_probe", "nmap_smb"}

    @pytest.mark.asyncio
    async def test_run_scan_wave5_exposure_and_wpscan_smart_dispatch(
        self, engine: NexusEngine
    ) -> None:
        from unittest.mock import AsyncMock, patch

        from nexus.core.config import ScanProfile
        from nexus.db.models import Finding, Port, Severity, Target

        engine.config.profile = ScanProfile.WEB
        eng = engine.create_engagement("wp.local")
        t = Target(
            engagement_id=eng.id,
            host="wp.local",
            ip="10.0.0.60",
            is_live=True,
            tech_stack=["WordPress", "PHP"],
        )
        engine.db.add_target(t)
        engine.db.add_port(
            Port(target_id=t.id, port=443, protocol="tcp", state="open", service="https")
        )

        exp_mock = AsyncMock(
            return_value=[
                Finding(
                    host="wp.local",
                    port=443,
                    protocol="https",
                    title="Exposed Git",
                    severity=Severity.HIGH,
                    tool_source="exposure_probe",
                )
            ]
        )
        wp_mock = AsyncMock(
            return_value=[
                Finding(
                    host="wp.local",
                    port=443,
                    protocol="https",
                    title="WPScan Enum",
                    severity=Severity.INFO,
                    tool_source="wpscan",
                )
            ]
        )
        with (
            patch(
                "nexus.core.engine.ToolRunner.is_available",
                side_effect=lambda name: name == "wpscan",
            ),
            patch("nexus.core.engine.crawl_web", AsyncMock(return_value=([], []))),
            patch("nexus.core.engine.audit_http_security", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_tls", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_exposed_artifacts", exp_mock),
            patch("nexus.core.engine.audit_graphql_introspection", AsyncMock(return_value=[])),
            patch("nexus.core.engine.wpscan_audit", wp_mock),
        ):
            findings = await engine.run_scan(eng.id, "wp.local")

        exp_mock.assert_awaited_once()
        wp_mock.assert_awaited_once()
        assert {f.tool_source for f in findings} == {"exposure_probe", "wpscan"}

    @pytest.mark.asyncio
    async def test_run_scan_forwards_wpscan_api_token(
        self, engine: NexusEngine, monkeypatch
    ) -> None:
        from unittest.mock import AsyncMock, patch

        from nexus.core.config import ScanProfile
        from nexus.db.models import Port, Target

        engine.config.profile = ScanProfile.WEB
        monkeypatch.setenv("WPSCAN_API_TOKEN", "env_wp_tok_456")
        eng = engine.create_engagement("wp-tok.local")
        t = Target(
            engagement_id=eng.id,
            host="wp-tok.local",
            ip="10.0.0.61",
            is_live=True,
            tech_stack=["WordPress"],
        )
        engine.db.add_target(t)
        engine.db.add_port(
            Port(target_id=t.id, port=443, protocol="tcp", state="open", service="https")
        )

        wp_mock = AsyncMock(return_value=[])
        with (
            patch(
                "nexus.core.engine.ToolRunner.is_available",
                side_effect=lambda name: name == "wpscan",
            ),
            patch("nexus.core.engine.crawl_web", AsyncMock(return_value=([], []))),
            patch("nexus.core.engine.audit_http_security", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_tls", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_exposed_artifacts", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_graphql_introspection", AsyncMock(return_value=[])),
            patch("nexus.core.engine.wpscan_audit", wp_mock),
        ):
            await engine.run_scan(eng.id, "wp-tok.local")

        wp_mock.assert_awaited_once()
        assert wp_mock.call_args.kwargs.get("api_token") == "env_wp_tok_456"

    @pytest.mark.asyncio
    async def test_run_scan_wave6_graphql_auth_diff_and_db_probes(
        self, engine: NexusEngine
    ) -> None:
        from unittest.mock import AsyncMock, patch

        from nexus.core.config import ScanProfile
        from nexus.db.models import Finding, Port, Severity, Target

        engine.config.profile = ScanProfile.API
        engine.config.auth_headers = {"Authorization": "Bearer wave6_tok"}
        eng = engine.create_engagement("api6.local")
        t = Target(engagement_id=eng.id, host="api6.local", ip="10.0.0.70", is_live=True)
        engine.db.add_target(t)
        engine.db.add_port(
            Port(target_id=t.id, port=443, protocol="tcp", state="open", service="https")
        )

        gql_mock = AsyncMock(
            return_value=[
                Finding(
                    host="api6.local",
                    port=443,
                    protocol="https",
                    title="GraphQL Schema Introspection Enabled",
                    severity=Severity.LOW,
                    tool_source="graphql_probe",
                )
            ]
        )
        auth_mock = AsyncMock(
            return_value=[
                Finding(
                    host="api6.local",
                    port=443,
                    protocol="https",
                    title="API Endpoint Accessible Without Authentication",
                    severity=Severity.HIGH,
                    tool_source="auth_diff",
                )
            ]
        )
        with (
            patch("nexus.core.engine.ToolRunner.is_available", return_value=False),
            patch(
                "nexus.core.engine.crawl_web",
                AsyncMock(return_value=(["https://api6.local/api/users"], [])),
            ),
            patch("nexus.core.engine.audit_http_security", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_tls", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_exposed_artifacts", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_graphql_introspection", gql_mock),
            patch("nexus.core.engine.audit_auth_enforcement", auth_mock),
        ):
            api_findings = await engine.run_scan(eng.id, "api6.local")

        gql_mock.assert_awaited_once()
        auth_mock.assert_awaited_once()
        assert {f.tool_source for f in api_findings} == {"graphql_probe", "auth_diff"}

        # Network profile dispatches DB ports (5432, 27017, 2379)
        engine.config.profile = ScanProfile.NETWORK
        eng_net = engine.create_engagement("db.local")
        t_net = Target(engagement_id=eng_net.id, host="db.local", ip="10.0.0.71", is_live=True)
        engine.db.add_target(t_net)
        engine.db.add_port(
            Port(target_id=t_net.id, port=5432, protocol="tcp", state="open", service="postgresql")
        )
        engine.db.add_port(
            Port(target_id=t_net.id, port=27017, protocol="tcp", state="open", service="mongodb")
        )

        net_mock = AsyncMock(
            side_effect=[
                [
                    Finding(
                        host="db.local",
                        port=5432,
                        protocol="postgresql",
                        title="PostgreSQL Trust Auth",
                        severity=Severity.CRITICAL,
                        tool_source="postgres_probe",
                    )
                ],
                [
                    Finding(
                        host="db.local",
                        port=27017,
                        protocol="mongodb",
                        title="MongoDB Open",
                        severity=Severity.HIGH,
                        tool_source="mongodb_probe",
                    )
                ],
            ]
        )
        with (
            patch("nexus.core.engine.audit_tls", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_ssh", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_network_service", net_mock),
        ):
            net_findings = await engine.run_scan(eng_net.id, "db.local")

        assert net_mock.await_count == 2
        assert {f.tool_source for f in net_findings} == {"postgres_probe", "mongodb_probe"}

    def test_fail_closed_scope_and_explicit_minimal_tier(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        from nexus.core.hardware import HardwareInfo

        eng_unbooted = NexusEngine(NexusConfig(data_dir=tmp_path / "u"))
        assert eng_unbooted._is_in_scope("example.com") is False

        # Explicit Tier.MINIMAL must NOT be overridden even on high-RAM hosts
        cfg_explicit = NexusConfig(data_dir=tmp_path / "m", tier=Tier.MINIMAL)
        eng_explicit = NexusEngine(cfg_explicit)
        with patch(
            "nexus.core.engine.detect_hardware",
            return_value=HardwareInfo(32768, 24000, 16, False, "None"),
        ):
            eng_explicit.boot(connect_ai=False)
        assert eng_explicit.config.tier == Tier.MINIMAL
        eng_explicit.shutdown()

        # Default (unset tier) auto-selects from hardware
        cfg_default = NexusConfig(data_dir=tmp_path / "a")
        eng_default = NexusEngine(cfg_default)
        with patch(
            "nexus.core.engine.detect_hardware",
            return_value=HardwareInfo(32768, 24000, 16, False, "None"),
        ):
            eng_default.boot(connect_ai=False)
        assert eng_default.config.tier == Tier.FULL
        eng_default.shutdown()

    def test_create_engagement_without_scope_file_uses_target_scope(
        self, engine: NexusEngine
    ) -> None:
        eng = engine.create_engagement("scoped.example.com")
        assert eng.id
        assert engine.scope is not None
        assert engine.scope.is_in_scope("scoped.example.com") is True
        assert engine.scope.is_in_scope("api.scoped.example.com") is True
        assert engine.scope.is_in_scope("evil.com") is False
        assert engine.msf is not None
        assert engine.msf._scope is engine.scope
        assert engine.msf._audit is engine.audit

    @pytest.mark.asyncio
    async def test_run_recon_scope_checks_portless_osint_and_plugins(
        self,
        engine: NexusEngine,
        tmp_path: Path,
    ) -> None:
        from unittest.mock import AsyncMock, patch

        from nexus.db.models import Finding, Port, Severity, Target

        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text(
            "allowed_domains:\n  - '*.app.local'\nexcluded_targets:\n  - 10.0.0.99\n",
            encoding="utf-8",
        )
        eng = engine.create_engagement("app.local", scope_file=str(scope_file))

        async def _fake_plugin_recon(target: str, **_):
            return [
                {"host": "sub.app.local", "title": "In-Scope Dict Finding", "severity": "low"},
                {
                    "host": "outside.evil.com",
                    "title": "Out-of-Scope Dict Finding",
                    "severity": "high",
                },
            ]

        engine.plugins.registry.add_recon("test-recon", _fake_plugin_recon)

        fake_nmap = {
            "targets": [Target(host="sub.app.local", ip="10.0.0.2", is_live=True)],
            "ports": [Port(port=443, protocol="tcp", state="open", service="https")],
            "findings": [
                Finding(
                    host="outside.evil.com",
                    port=None,
                    title="Portless OOS",
                    severity=Severity.HIGH,
                    tool_source="nmap",
                ),
                Finding(
                    host="sub.app.local",
                    port=None,
                    title="Portless InScope",
                    severity=Severity.INFO,
                    tool_source="nmap",
                ),
            ],
            "raw_xml": "",
        }
        with (
            patch(
                "nexus.core.engine.enumerate_subdomains",
                AsyncMock(
                    return_value=[
                        Target(host="sub.app.local"),
                        Target(host="excluded.app.local", ip="10.0.0.99"),
                    ]
                ),
            ),
            patch("nexus.core.engine.enumerate_dns", AsyncMock(side_effect=lambda ts: (ts, []))),
            patch("nexus.core.engine.nmap_scan", AsyncMock(return_value=fake_nmap)),
            patch("nexus.core.engine.detect_tech_stack", AsyncMock(side_effect=lambda ts: ts)),
            patch("nexus.core.engine.detect_waf", AsyncMock(side_effect=lambda ts: (ts, []))),
            patch(
                "nexus.core.engine.gather_osint",
                AsyncMock(
                    return_value=(
                        [],
                        [
                            Finding(
                                host="evil.org",
                                title="OOS OSINT",
                                severity=Severity.LOW,
                                tool_source="theharvester",
                            )
                        ],
                    )
                ),
            ),
        ):
            findings = await engine.run_recon(eng.id, "app.local")

        titles = {f.title for f in findings}
        assert "Portless InScope" in titles
        assert "In-Scope Dict Finding" in titles
        assert "Portless OOS" not in titles
        assert "Out-of-Scope Dict Finding" not in titles
        assert "OOS OSINT" not in titles

    @pytest.mark.asyncio
    async def test_run_exploit_requires_confirmation_and_uses_executor(
        self,
        engine: NexusEngine,
        tmp_path: Path,
    ) -> None:
        from unittest.mock import AsyncMock, patch

        from nexus.db.models import Finding, Severity, Target
        from nexus.recon.runner import ToolRunner

        eng = engine.create_engagement("exp.local")
        engine.db.add_target(Target(engagement_id=eng.id, host="exp.local"))
        engine.db.add_finding(
            Finding(
                engagement_id=eng.id,
                host="exp.local",
                port=443,
                title="Param Finding",
                evidence="GET https://[2001:db8::1]:8443/search?q=1",
                severity=Severity.MEDIUM,
            )
        )

        # Default confirm=False skips active exploitation
        skipped = await engine.run_exploit(eng.id)
        assert skipped == []

        # confirm=True invokes ExploitExecutor with IPv6-safe URL parsing
        sqlmap_mock = AsyncMock(return_value=[])
        scope_file = tmp_path / "s6.yaml"
        scope_file.write_text(
            "allowed_ips:\n  - 2001:db8::1\nallowed_ports:\n  - 8443\n", encoding="utf-8"
        )
        from nexus.core.scope import ScopeEnforcer

        engine._set_scope(ScopeEnforcer.from_file(scope_file))

        with (
            patch.object(ToolRunner, "is_available", side_effect=lambda t: t == "sqlmap"),
            patch("nexus.core.engine.sqlmap_scan", sqlmap_mock),
        ):
            await engine.run_exploit(eng.id, confirm=True)

        sqlmap_mock.assert_awaited_once()
        assert len(engine.exploit_executor.attempts) == 1
        assert engine.exploit_executor.attempts[0].target == "2001:db8::1"
        assert engine.exploit_executor.attempts[0].port == 8443

    @pytest.mark.asyncio
    async def test_engage_does_not_mutate_config_and_honors_output_dir(
        self,
        engine: NexusEngine,
        tmp_path: Path,
    ) -> None:
        from unittest.mock import AsyncMock, patch

        from nexus.core.config import get_config

        custom_out = tmp_path / "custom_reports"
        engine.config.output_dir = custom_out
        orig_profile = engine.config.profile
        progress_events: list[str] = []
        engine.on_progress = lambda ev, data: progress_events.append(ev)

        with (
            patch.object(engine, "run_recon", AsyncMock(return_value=[])),
            patch.object(engine, "run_scan", AsyncMock(return_value=[])),
            patch.object(engine, "run_correlate", AsyncMock(return_value=[])),
            patch("nexus.core.engine.generate_report", return_value=[]) as mock_rep,
        ):
            eng_id = await engine.engage("imm.local", skip_exploit=True, profile="api")

        assert engine.config.profile == orig_profile
        assert get_config().profile == orig_profile
        assert mock_rep.call_args.args[2] == custom_out / eng_id
        assert "engage_complete" in progress_events

    @pytest.mark.asyncio
    async def test_stateful_auth_session_unrestricted_scope_and_scan_feedback(
        self,
        tmp_path: Path,
    ) -> None:
        from unittest.mock import AsyncMock, MagicMock, patch

        from nexus.core.auth import StatefulAuthSession
        from nexus.core.config import NexusConfig
        from nexus.core.scope import ScopeEnforcer
        from nexus.db.models import Finding, ProxyEntry, Severity, Target

        # 1. StatefulAuthSession extracts token + cookies and enforces scope
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.cookies = {"sid": "abc123"}
        fake_resp.json.return_value = {"access_token": "jwt-token-xyz"}

        fake_client = MagicMock()
        fake_client.post = AsyncMock(return_value=fake_resp)
        fake_client.__aenter__ = AsyncMock(return_value=fake_client)
        fake_client.__aexit__ = AsyncMock(return_value=False)

        sess = StatefulAuthSession(
            "https://app.example.test/api/login",
            login_body={"user": "tester"},
        )
        with patch("nexus.core.auth.make_http_client", return_value=fake_client):
            hdrs = await sess.authenticate(scope=ScopeEnforcer.for_target("app.example.test"))
        assert hdrs["Authorization"] == "Bearer jwt-token-xyz"
        assert "sid=abc123" in hdrs["Cookie"]

        # Callback refresh path increments counter
        cb_sess = StatefulAuthSession(refresh_callback=lambda: {"X-Session": "refreshed"})
        refreshed = await cb_sess.refresh()
        assert refreshed["X-Session"] == "refreshed"
        assert cb_sess.refresh_count == 1

        # 2. NexusEngine loads YAML rules, respects unrestricted_scope, and wires proxy + ZAP in ScanPhase
        cfg = NexusConfig(
            data_dir=tmp_path / "data",
            db_path=str(tmp_path / "nexus.db"),
            unrestricted_scope=True,
        )
        eng_mgr = NexusEngine(cfg)
        eng_mgr.boot()
        try:
            assert eng_mgr.yaml_rules is not None
            assert eng_mgr.yaml_rules.rule_count >= 3

            eng = eng_mgr.create_engagement("app.example.test")
            assert eng_mgr.scope is not None
            assert eng_mgr.scope.is_in_scope("unrestricted-lab.example.test")

            eng_mgr.db.add_proxy_entry(
                ProxyEntry(
                    engagement_id=eng.id,
                    method="GET",
                    url="https://app.example.test/from-proxy",
                    host="app.example.test",
                    port=443,
                    status_code=200,
                )
            )
            fake_zap_finding = Finding(
                host="app.example.test",
                port=443,
                protocol="https",
                title="ZAP Sample Alert",
                severity=Severity.MEDIUM,
                tool_source="owasp_zap",
            )
            fake_http_resp = MagicMock()
            fake_http_resp.status_code = 500
            fake_http_resp.headers = {"Content-Type": "text/html"}
            fake_http_resp.text = (
                "You're seeing this error because you have <code>DEBUG = True</code>"
            )
            fake_http_client = MagicMock()
            fake_http_client.get = AsyncMock(return_value=fake_http_resp)
            fake_http_client.__aenter__ = AsyncMock(return_value=fake_http_client)
            fake_http_client.__aexit__ = AsyncMock(return_value=False)

            with (
                patch("nexus.core.engine.crawl_web", AsyncMock(return_value=([], []))),
                patch("nexus.core.engine.nuclei_scan", AsyncMock(return_value=[])),
                patch("nexus.core.engine.nikto_scan", AsyncMock(return_value=[])),
                patch(
                    "nexus.core.engine.audit_http_security", AsyncMock(return_value=[])
                ) as hdr_mock,
                patch("nexus.core.engine.audit_exposed_artifacts", AsyncMock(return_value=[])),
                patch("nexus.core.engine.audit_graphql_introspection", AsyncMock(return_value=[])),
                patch("nexus.scanner._http.make_http_client", return_value=fake_http_client),
                patch(
                    "nexus.core.engine.ToolRunner.is_available",
                    side_effect=lambda t: "zap" in str(t),
                ),
                patch(
                    "nexus.core.phases.scan.zap_scan", AsyncMock(return_value=[fake_zap_finding])
                ),
            ):
                eng_mgr.db.add_target(
                    Target(
                        engagement_id=eng.id, host="app.example.test", ip="192.0.2.10", is_live=True
                    )
                )
                findings = await eng_mgr.run_scan(eng.id, "app.example.test")

            assert any(f.tool_source == "owasp_zap" for f in findings)
            assert any(f.tool_source == "yaml_rule:django-debug-page" for f in findings)
            assert "https://app.example.test/from-proxy" in hdr_mock.await_args.args[0]
        finally:
            eng_mgr.shutdown()

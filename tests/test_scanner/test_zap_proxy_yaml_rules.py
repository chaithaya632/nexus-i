"""Tests for parser regression fixtures, OWASP ZAP wrapper, YAML passive rules, and MITM proxy."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from nexus.core.scope import ScopeEnforcer, ScopeViolation
from nexus.db.models import Engagement, Severity
from nexus.db.store import EngagementStore
from nexus.exploit.sqli import sqlmap_scan
from nexus.recon.ports import _parse_nmap_xml
from nexus.recon.runner import ToolOutput, ToolRunner
from nexus.scanner.nikto import _parse_nikto_csv
from nexus.scanner.nuclei import _parse_nuclei_line
from nexus.scanner.proxy import NexusMitmAddon, NexusProxyRecorder
from nexus.scanner.yaml_rules import PassiveRule, YamlPassiveRuleEngine
from nexus.scanner.zap import build_zap_automation_plan, parse_zap_json_report, zap_scan

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
BUNDLED_RULES_DIR = Path(__file__).resolve().parents[2] / "nexus" / "brain" / "knowledge" / "rules"


# ── Parser Regression Fixtures ────────────────────────────────────


def test_nmap_sample_fixture_parses_ports_os_and_scripts() -> None:
    xml_text = (FIXTURES_DIR / "nmap_sample.xml").read_text(encoding="utf-8")
    parsed = _parse_nmap_xml(xml_text, default_host="192.0.2.10")

    assert len(parsed["targets"]) == 1
    tgt = parsed["targets"][0]
    assert tgt.host == "app.example.test"
    assert tgt.ip == "192.0.2.10"
    assert tgt.is_live is True
    assert tgt.os_guess == "Linux 5.15"

    # Ports 22 and 80 open; 443 closed -> ignored
    assert [p.port for p in parsed["ports"]] == [22, 80]
    assert parsed["ports"][0].service == "ssh"
    assert "OpenSSH 8.9p1" in parsed["ports"][0].version

    # Two open-port INFO findings + one port NSE script finding
    assert len(parsed["findings"]) == 3
    script_findings = [f for f in parsed["findings"] if "Nmap script:" in f.title]
    assert len(script_findings) == 1
    assert script_findings[0].port == 80


def test_nuclei_sample_fixture_parses_jsonl() -> None:
    lines = [
        line.strip()
        for line in (FIXTURES_DIR / "nuclei_sample.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    findings = [f for line in lines if (f := _parse_nuclei_line(line)) is not None]
    assert len(findings) == 2
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].cwe_id == "CWE-200"
    assert findings[0].port == 80

    assert findings[1].severity == Severity.HIGH
    assert findings[1].cve_ids == ["CVE-2021-41773"]
    assert findings[1].cwe_id == "CWE-22"
    assert findings[1].port == 8443


def test_nikto_sample_fixture_parses_csv_and_classifies_severity() -> None:
    csv_text = (FIXTURES_DIR / "nikto_sample.csv").read_text(encoding="utf-8")
    findings = _parse_nikto_csv(csv_text, target="app.example.test", ssl=True)

    assert len(findings) == 3
    assert all(f.port == 443 and f.protocol == "https" for f in findings)
    sevs = {f.severity for f in findings}
    assert Severity.HIGH in sevs
    assert Severity.MEDIUM in sevs
    assert Severity.LOW in sevs


@pytest.mark.asyncio
async def test_sqlmap_sample_fixture_parses_parameter_blocks_safely() -> None:
    sample_stdout = (FIXTURES_DIR / "sqlmap_sample.txt").read_text(encoding="utf-8")
    fake_out = ToolOutput(tool="sqlmap", args=[], returncode=0, stdout=sample_stdout, stderr="")

    with patch.object(ToolRunner, "run", AsyncMock(return_value=fake_out)):
        findings = await sqlmap_scan("http://scanner.example.test/items?id=1", timeout=30)

    # One parameter injection finding + one enumerated DB confirmation (ignored parameter skipped)
    assert len(findings) == 2
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].cwe_id == "CWE-89"
    assert "Parameter: id (GET)" in findings[0].evidence
    assert findings[1].title == "SQL Injection — Database Enumeration Successful"


def test_zap_sample_fixture_parses_json_alerts() -> None:
    raw = (FIXTURES_DIR / "zap_sample.json").read_text(encoding="utf-8")
    findings = parse_zap_json_report(raw)

    assert len(findings) == 2
    assert findings[0].host == "app.example.test"
    assert findings[0].port == 8443
    assert findings[0].protocol == "https"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].cwe_id == "CWE-693"
    assert findings[0].confirmed is True
    assert findings[0].description == "CSP header is missing on responses."

    assert findings[1].severity == Severity.HIGH
    assert findings[1].cwe_id == "CWE-1021"
    assert findings[1].confirmed is False


# ── OWASP ZAP Automation Framework Wrapper ────────────────────────


def test_build_zap_automation_plan_structure() -> None:
    plan = build_zap_automation_plan(
        "https://app.example.test:8443/v1",
        "/tmp/zap_out",
        exclude_regexes=[r".*/logout.*"],
        max_crawl_minutes=3,
        active_scan=True,
    )
    ctx = plan["env"]["contexts"][0]
    assert ctx["name"] == "nexus-scope"
    assert ctx["urls"] == ["https://app.example.test:8443"]
    assert ctx["excludePaths"] == [r".*/logout.*"]

    job_types = [j["type"] for j in plan["jobs"]]
    assert job_types == [
        "passiveScan-config",
        "spider",
        "passiveScan-wait",
        "activeScan",
        "report",
    ]


@pytest.mark.asyncio
async def test_zap_scan_enforces_scope_and_handles_missing_binary(tmp_path: Path) -> None:
    scope = ScopeEnforcer.for_target("allowed.example.test")
    with pytest.raises(ScopeViolation):
        await zap_scan("https://forbidden.example.test/", scope=scope)

    with patch.object(ToolRunner, "is_available", return_value=False):
        res = await zap_scan("https://allowed.example.test/", scope=scope)
    assert res == []


@pytest.mark.asyncio
async def test_zap_scan_runs_and_parses_report(tmp_path: Path) -> None:
    zap_json = (FIXTURES_DIR / "zap_sample.json").read_text(encoding="utf-8")
    plan_file = tmp_path / "plan.yaml"

    async def fake_run(exe: str, args: list[str], timeout: int = 300) -> ToolOutput:
        assert args[:2] == ["-cmd", "-autorun"]
        generated_plan = Path(args[2]).read_text(encoding="utf-8")
        import yaml

        loaded = yaml.safe_load(generated_plan)
        rep_job = [j for j in loaded["jobs"] if j["type"] == "report"][0]["parameters"]
        rep_path = Path(rep_job["reportDir"]) / rep_job["reportFile"]
        rep_path.write_text(zap_json, encoding="utf-8")
        return ToolOutput(tool=exe, args=args, returncode=0, stdout="done", stderr="")

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "make_temp_path", return_value=str(plan_file)),
        patch.object(ToolRunner, "run", side_effect=fake_run),
    ):
        findings = await zap_scan(
            "https://app.example.test:8443",
            scope=ScopeEnforcer.for_target("app.example.test"),
        )

    assert len(findings) == 2
    assert findings[0].tool_source == "owasp_zap"


# ── Declarative YAML Passive Rule Engine ──────────────────────────


def test_yaml_passive_rules_bundled_and_custom(tmp_path: Path) -> None:
    engine = YamlPassiveRuleEngine()
    loaded = engine.load_directory(BUNDLED_RULES_DIR)
    assert loaded >= 3

    trace_findings = engine.inspect_response(
        "https://app.example.test/api/users",
        status_code=500,
        headers={"Content-Type": "text/plain"},
        body="Traceback (most recent call last):\n  File 'app.py', line 42",
    )
    assert any(f.tool_source == "yaml_rule:debug-stacktrace-leak" for f in trace_findings)

    rfc_findings = engine.inspect_response(
        "https://app.example.test/home",
        status_code=200,
        headers={"X-Backend-Server": "10.20.30.40"},
        body="ok",
    )
    assert any(f.tool_source == "yaml_rule:internal-rfc1918-ip-leak" for f in rfc_findings)

    swagger_findings = engine.inspect_response(
        "https://app.example.test/swagger-ui/",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<script>SwaggerUIBundle({})</script>",
    )
    assert any(f.tool_source == "yaml_rule:swagger-ui-public" for f in swagger_findings)

    # Invalid regex in programmatic rule is skipped safely rather than crashing
    engine.add_rule(PassiveRule(id="bad-regex", title="Broken", body_regex="[unclosed("))
    assert engine.rule_count == loaded


# ── Scoped Passive Proxy Recorder & mitmproxy Addon ───────────────


def test_proxy_recorder_and_mitm_addon_enforce_scope_and_persist(tmp_path: Path) -> None:
    store = EngagementStore(tmp_path / "proxy_test.db")
    eng = Engagement(name="Proxy Test", target="app.example.test")
    store.create_engagement(eng)
    scope = ScopeEnforcer.for_target("app.example.test")

    recorder = NexusProxyRecorder(
        engagement_id=eng.id,
        scope=scope,
        store=store,
        rules_dir=BUNDLED_RULES_DIR,
    )

    # Out-of-scope domain is dropped completely
    entry_out, f_out = recorder.inspect_exchange(
        method="GET",
        url="https://thirdparty.otherdomain.test/script.js",
        status_code=200,
    )
    assert entry_out is None
    assert f_out == []

    # In-scope exchange via NexusMitmAddon runs passive checks + persists redacted headers
    addon = NexusMitmAddon(recorder)
    fake_flow = SimpleNamespace(
        request=SimpleNamespace(
            method="POST",
            pretty_url="https://app.example.test/swagger-ui/",
            headers={"Authorization": "Bearer secret-token-value", "Host": "app.example.test"},
            get_text=lambda strict=False: '{"ping":true}',
        ),
        response=SimpleNamespace(
            status_code=200,
            headers={"Content-Type": "text/html", "X-Backend-Server": "10.0.1.5"},
            get_text=lambda strict=False: (
                "<html><form action='http://app.example.test/login'></form>SwaggerUIBundle</html>"
            ),
        ),
    )
    addon.response(fake_flow)

    assert len(recorder.history) == 1
    assert "https://app.example.test/swagger-ui/" in recorder.discovered_urls

    stored_history = store.get_proxy_history(eng.id)
    assert len(stored_history) == 1
    assert stored_history[0].request_headers["Authorization"] != "Bearer secret-token-value"
    assert stored_history[0].findings_count >= 2

    stored_findings = store.get_findings(eng.id)
    assert any(f.tool_source == "yaml_rule:swagger-ui-public" for f in stored_findings)
    assert any(f.tool_source == "yaml_rule:internal-rfc1918-ip-leak" for f in stored_findings)

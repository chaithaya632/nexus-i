"""CLI tests using Click CliRunner across all NEXUS commands."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus.core.config import set_config
from nexus.db.models import Finding, Severity
from nexus.main import cli


@pytest.fixture()
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate CLI runs to a temporary data dir & DB."""
    data_dir = tmp_path / "nexus_data"
    db_path = data_dir / "nexus.db"
    out_dir = tmp_path / "nexus_out"
    monkeypatch.setenv("NEXUS_DATA_DIR", str(data_dir))
    monkeypatch.setenv("NEXUS_DB_PATH", str(db_path))
    monkeypatch.setenv("NEXUS_OUTPUT_DIR", str(out_dir))
    set_config(None)  # type: ignore[arg-type]
    return data_dir


def test_cli_help():
    runner = CliRunner()
    res = runner.invoke(cli, ["--help"])
    assert res.exit_code == 0
    for cmd in ("engage", "recon", "scan", "exploit", "report", "engagements", "kb", "ai", "init", "audit", "version"):
        assert cmd in res.output


def test_cli_version(cli_env):
    runner = CliRunner()
    res = runner.invoke(cli, ["version"])
    assert res.exit_code == 0
    assert "NEXUS" in res.output


def test_cli_kb_stats_and_search(cli_env):
    runner = CliRunner()
    res_stats = runner.invoke(cli, ["kb", "stats"])
    assert res_stats.exit_code == 0
    assert "Knowledge Cves" in res_stats.output
    # KnowledgeGraph now loads builtin CVEs (not 0)
    assert "| Knowledge Cves   |     0 |" not in res_stats.output

    res_search = runner.invoke(cli, ["kb", "search", "Log4j"])
    assert res_search.exit_code == 0
    assert "CVE-2021-44228" in res_search.output


def test_cli_engagements_empty_and_audit_chain(cli_env):
    runner = CliRunner()
    r1 = runner.invoke(cli, ["kb", "stats"])
    r2 = runner.invoke(cli, ["engagements", "list"])
    assert r1.exit_code == 0
    assert r2.exit_code == 0

    r_audit = runner.invoke(cli, ["audit", "verify"])
    assert r_audit.exit_code == 0
    assert "VALID" in r_audit.output


def test_cli_ai_status(cli_env):
    runner = CliRunner()
    res = runner.invoke(cli, ["ai", "status"])
    assert res.exit_code == 0


def test_cli_report_generation(cli_env, tmp_path: Path):
    from nexus.core.config import NexusConfig
    from nexus.core.engine import NexusEngine

    cfg = NexusConfig(data_dir=cli_env, db_path=cli_env / "nexus.db")
    eng = NexusEngine(cfg)
    eng.boot()
    e = eng.create_engagement("target.local", name="cli_rep")
    eng.db.add_finding(Finding(
        engagement_id=e.id, host="target.local", port=80,
        title="SQLi", severity=Severity.CRITICAL, cwe_id="CWE-89",
    ))
    eng.shutdown()

    runner = CliRunner()
    out_dir = tmp_path / "rep_out"
    res = runner.invoke(cli, ["report", "-e", e.id, "-f", "md", "-o", str(out_dir)])
    assert res.exit_code == 0
    assert (out_dir / f"nexus_report_{e.id}.md").is_file()

    json_file = tmp_path / "rep.json"
    res_json = runner.invoke(cli, ["report", "-e", e.id, "-f", "json", "-o", str(json_file)])
    assert res_json.exit_code == 0
    assert json_file.is_file()
    assert "SQLi" in json_file.read_text(encoding="utf-8")

    res_show = runner.invoke(cli, ["engagements", "show", e.id])
    assert res_show.exit_code == 0
    assert "target.local" in res_show.output


def test_cli_engage_help_and_validation(cli_env):
    runner = CliRunner()
    res_help = runner.invoke(cli, ["engage", "--help"])
    assert res_help.exit_code == 0
    assert "--profile" in res_help.output
    assert "--resume" in res_help.output

    res_missing = runner.invoke(cli, ["engage"])
    assert res_missing.exit_code != 0
    assert "TARGET" in res_missing.output or "--resume" in res_missing.output


def test_cli_engage_passes_profile_and_resume(cli_env, monkeypatch):
    from unittest.mock import AsyncMock
    from nexus.core.engine import NexusEngine

    mock_engage = AsyncMock(return_value="eng_resumed_01")
    monkeypatch.setattr(NexusEngine, "engage", mock_engage)

    runner = CliRunner()
    res = runner.invoke(cli, ["engage", "--profile", "quick", "--resume", "eng_resumed_01", "--no-exploit"])
    assert res.exit_code == 0
    assert "eng_resumed_01" in res.output
    mock_engage.assert_awaited_once_with(
        "",
        name="",
        scope_file=None,
        skip_exploit=True,
        profile="quick",
        resume_id="eng_resumed_01",
    )


def test_cli_wave2_auth_and_openapi_flags(cli_env, tmp_path: Path, monkeypatch):
    from unittest.mock import AsyncMock
    from nexus.core.engine import NexusEngine
    from nexus.core.config import ScanProfile

    spec = tmp_path / "spec.yaml"
    spec.write_text("openapi: 3.0.0\ninfo:\n  title: t\n  version: '1'\npaths: {}\n", encoding="utf-8")

    runner = CliRunner()
    res_eng_help = runner.invoke(cli, ["engage", "--help"])
    res_scan_help = runner.invoke(cli, ["scan", "--help"])
    for flag in ("--header", "--cookie", "--auth-bearer", "--openapi"):
        assert flag in res_eng_help.output
        assert flag in res_scan_help.output

    # Bad header syntax fails cleanly
    res_bad = runner.invoke(cli, ["engage", "app.local", "--header", "NoColonHere"])
    assert res_bad.exit_code != 0

    # Valid flags configure NexusConfig for scan
    eng = NexusEngine()
    eng.config.data_dir = cli_env
    eng.config.db_path = cli_env / "nexus.db"
    eng.boot()
    created = eng.create_engagement("app.local")
    eng.shutdown()

    captured_cfg = {}

    async def _fake_scan(self, eng_id, target):
        captured_cfg["profile"] = self.config.profile
        captured_cfg["headers"] = dict(self.config.auth_headers)
        captured_cfg["openapi"] = str(self.config.openapi_spec)
        return []

    monkeypatch.setattr(NexusEngine, "run_scan", _fake_scan)
    res_ok = runner.invoke(
        cli,
        [
            "scan", "app.local", "-e", created.id,
            "-p", "api",
            "-H", "X-Org: lab",
            "--cookie", "sess=abc",
            "--auth-bearer", "jwt_tok",
            "--openapi", str(spec),
        ],
    )
    assert res_ok.exit_code == 0
    assert captured_cfg["profile"] == ScanProfile.API
    assert captured_cfg["headers"] == {"X-Org": "lab", "Cookie": "sess=abc", "Authorization": "Bearer jwt_tok"}
    assert captured_cfg["openapi"] == str(spec)


def test_cli_wave3_sarif_diff_and_ignore(cli_env, tmp_path: Path):
    import json
    from nexus.core.config import NexusConfig
    from nexus.core.engine import NexusEngine
    from nexus.db.models import Finding, Severity

    cfg = NexusConfig(data_dir=cli_env, db_path=cli_env / "nexus.db")
    eng = NexusEngine(cfg)
    eng.boot()
    e1 = eng.create_engagement("ci.local", name="baseline")
    eng.db.add_finding(Finding(
        engagement_id=e1.id, host="ci.local", port=443, protocol="https",
        title="Missing HSTS", cwe_id="CWE-523", severity=Severity.LOW,
    ))
    e2 = eng.create_engagement("ci.local", name="pr-build")
    eng.db.add_finding(Finding(
        engagement_id=e2.id, host="ci.local", port=443, protocol="https",
        title="Missing HSTS", cwe_id="CWE-523", severity=Severity.LOW,
    ))
    eng.db.add_finding(Finding(
        engagement_id=e2.id, host="ci.local", port=443, protocol="https",
        title="Spring4Shell RCE", cve_ids=["CVE-2022-22965"], cwe_id="CWE-94", severity=Severity.CRITICAL,
    ))
    eng.shutdown()

    runner = CliRunner()
    assert "diff" in runner.invoke(cli, ["--help"]).output
    assert "--ignore" in runner.invoke(cli, ["engage", "--help"]).output

    sarif_out = tmp_path / "results.sarif"
    res_sarif = runner.invoke(cli, ["report", "-e", e2.id, "-f", "sarif", "-o", str(sarif_out)])
    assert res_sarif.exit_code == 0
    assert sarif_out.is_file()
    sarif_doc = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"][0]["results"]) == 2

    res_diff = runner.invoke(cli, ["diff", e1.id, e2.id, "-f", "json"])
    assert res_diff.exit_code == 0
    diff_data = json.loads(res_diff.output)
    assert diff_data["counts"]["new"] == 1
    assert diff_data["counts"]["persistent"] == 1

    # Fail-on-new gate triggers exit code 2 for critical regression, 0 when gating only info
    res_fail = runner.invoke(cli, ["diff", e1.id, e2.id, "--fail-on-new", "critical,high"])
    assert res_fail.exit_code == 2
    res_pass = runner.invoke(cli, ["diff", e1.id, e2.id, "--fail-on-new", "info"])
    assert res_pass.exit_code == 0

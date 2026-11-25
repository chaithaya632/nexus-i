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

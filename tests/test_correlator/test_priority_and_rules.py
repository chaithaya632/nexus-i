"""Tests for risk prioritization, confidence scoring, Markdown backlog, and expanded YAML passive rules."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from nexus.correlator.engine import correlate
from nexus.correlator.prioritize import (
    build_remediation_plan,
    compute_confidence,
    load_kev_cve_set,
    rank_findings_by_priority,
)
from nexus.db.models import AttackChain, Finding, ReportMeta, Severity
from nexus.reporter.generator import ReportData
from nexus.reporter.markdown import render_markdown
from nexus.scanner.yaml_rules import YamlPassiveRuleEngine


def test_kev_snapshot_loads_cves() -> None:
    kevs = load_kev_cve_set()
    assert len(kevs) >= 1000
    assert "CVE-2021-44228" in kevs


def test_confidence_and_priority_boosts_and_dict_compatibility() -> None:
    kev_finding = Finding(
        host="app.example.com",
        title="Log4Shell",
        severity=Severity.HIGH,
        cvss_score=10.0,
        cve_ids=["CVE-2021-44228"],
        cwe_id="CWE-502",
        tool_source="nuclei,zap",
        evidence="Matched JNDI callback header",
        confirmed=True,
    )
    info_finding = Finding(
        host="app.example.com",
        title="Info banner",
        severity=Severity.INFO,
        tool_source="headers",
    )

    conf, tools, _ = compute_confidence(kev_finding)
    assert tools == 2
    assert conf >= 90

    chain = AttackChain(
        name="Web to RCE",
        steps=[{"finding_id": kev_finding.id, "host": "app.example.com"}],
    )
    ranked = rank_findings_by_priority([info_finding, kev_finding], [chain])
    assert ranked[0].finding.id == kev_finding.id
    assert ranked[0].is_kev is True
    assert ranked[0].in_attack_chain is True
    assert ranked[0].priority_score >= 90
    assert ranked[0].priority_score > ranked[1].priority_score

    plan = build_remediation_plan([info_finding, kev_finding], [chain])
    assert plan["kev_flagged"] == 1
    assert plan["chain_linked"] == 1
    assert plan["total_actionable"] == 2

    # Serialized dicts (as in ReportData) and Markdown backlog escaping
    dict_findings = [
        kev_finding.model_dump(mode="json"),
        {
            "title": "Table | Injection\nTest",
            "host": "app.example.com",
            "severity": "medium",
            "cwe_id": "CWE-79",
        },
    ]
    report_data = ReportData(
        meta=ReportMeta(
            title="Priority Test",
            engagement_id="eng-1",
            target="app.example.com",
            date=datetime(2026, 11, 25, tzinfo=UTC),
            total_findings=2,
            high_count=1,
            medium_count=1,
        ),
        engagement={"target": "app.example.com"},
        targets=[],
        findings=dict_findings,
        chains=[chain.model_dump(mode="json")],
        credentials=[],
        severity_counts={"high": 1, "medium": 1},
        executive_summary="Summary",
        methodology="Standard",
    )
    md = render_markdown(report_data)
    assert "## Prioritized Remediation Backlog" in md
    assert "Log4Shell" in md
    assert r"Table \| Injection Test" in md

    # End-to-end correlate() places higher-priority findings first
    ordered, _ = correlate([info_finding, kev_finding])
    assert ordered[0].id == kev_finding.id


def test_expanded_passive_yaml_rules() -> None:
    rules_dir = Path(__file__).resolve().parents[2] / "nexus" / "brain" / "knowledge" / "rules"
    engine = YamlPassiveRuleEngine()
    loaded = engine.load_directory(rules_dir)
    assert loaded >= 10

    f_django = engine.inspect_response(
        "https://example.com/missing",
        status_code=404,
        headers={},
        body="You're seeing this error because you have <code>DEBUG = True</code>",
    )
    assert any(f.tool_source == "yaml_rule:django-debug-page" for f in f_django)

    f_cors = engine.inspect_response(
        "https://api.example.com/v1/me",
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        body="{}",
    )
    assert any(f.tool_source == "yaml_rule:cors-wildcard-credentials" for f in f_cors)

    f_sourcemap = engine.inspect_response(
        "https://app.example.com/app.js",
        status_code=200,
        headers={},
        body="//# sourceMappingURL=app.js.map",
    )
    assert any(f.tool_source == "yaml_rule:js-sourcemap-exposed" for f in f_sourcemap)

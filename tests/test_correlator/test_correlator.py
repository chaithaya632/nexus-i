"""Tests for the correlator: dedup, enrichment, graph, and pipeline."""

# ── Dedup tests ───────────────────────────────────────────────────
from nexus.correlator.dedup import deduplicate_findings
from nexus.db.models import Finding, Severity


def _make_finding(**kw) -> Finding:
    defaults = {
        "host": "example.com",
        "port": 80,
        "protocol": "http",
        "title": "Test",
        "severity": Severity.INFO,
        "tool_source": "test",
    }
    defaults.update(kw)
    return Finding(**defaults)


def test_dedup_no_duplicates():
    findings = [
        _make_finding(title="XSS", cwe_id="CWE-79", port=80),
        _make_finding(title="SQLi", cwe_id="CWE-89", port=80),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 2


def test_dedup_exact_duplicates():
    findings = [
        _make_finding(title="XSS", cwe_id="CWE-79", severity=Severity.MEDIUM, tool_source="nuclei"),
        _make_finding(title="XSS", cwe_id="CWE-79", severity=Severity.HIGH, tool_source="nikto"),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1
    # Keeps highest severity
    assert result[0].severity == Severity.HIGH
    # Merged tool sources
    assert "nuclei" in result[0].tool_source
    assert "nikto" in result[0].tool_source


def test_dedup_different_ports():
    findings = [
        _make_finding(title="XSS", cwe_id="CWE-79", port=80),
        _make_finding(title="XSS", cwe_id="CWE-79", port=443),
    ]
    result = deduplicate_findings(findings)
    # Different ports → different findings
    assert len(result) == 2


def test_dedup_merge_cves():
    findings = [
        _make_finding(cwe_id="CWE-79", cve_ids=["CVE-2023-001"]),
        _make_finding(cwe_id="CWE-79", cve_ids=["CVE-2023-002"]),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1
    assert "CVE-2023-001" in result[0].cve_ids
    assert "CVE-2023-002" in result[0].cve_ids


def test_dedup_empty():
    assert deduplicate_findings([]) == []


def test_dedup_keeps_confirmed():
    findings = [
        _make_finding(cwe_id="CWE-79", confirmed=True),
        _make_finding(cwe_id="CWE-79", confirmed=False),
    ]
    result = deduplicate_findings(findings)
    assert result[0].confirmed is True


# ── Enrichment tests ─────────────────────────────────────────────

from nexus.correlator.enrichment import enrich_findings


def test_enrich_cvss_severity():
    findings = [
        _make_finding(cvss_score=9.5, severity=Severity.LOW),
    ]
    result = enrich_findings(findings)
    assert result[0].severity == Severity.CRITICAL


def test_enrich_no_crash_without_subsystems():
    findings = [_make_finding()]
    result = enrich_findings(findings)
    assert len(result) == 1


# ── Correlator graph tests ───────────────────────────────────────

from nexus.correlator.graph import _find_related_finding, build_attack_chains


def test_build_chains_empty():
    assert build_attack_chains([]) == []


def test_build_chains_no_builder():
    findings = [_make_finding(port=80)]
    assert build_attack_chains(findings, chain_builder=None) == []


def test_find_related_by_port():
    f = _make_finding(port=22)
    result = _find_related_finding([f], "port_22")
    assert result is f


def test_find_related_by_cwe():
    f = _make_finding(cwe_id="CWE-79")
    result = _find_related_finding([f], "vuln_cwe-79")
    assert result is f


def test_find_related_no_match():
    f = _make_finding(port=80)
    assert _find_related_finding([f], "port_9999") is None


# ── Full pipeline tests ──────────────────────────────────────────

from nexus.correlator.engine import correlate


def test_correlate_pipeline():
    findings = [
        _make_finding(title="XSS", cwe_id="CWE-79", severity=Severity.MEDIUM, tool_source="nuclei"),
        _make_finding(title="XSS", cwe_id="CWE-79", severity=Severity.HIGH, tool_source="nikto"),
        _make_finding(title="SQLi", cwe_id="CWE-89", severity=Severity.HIGH, cvss_score=8.5),
    ]
    enriched, chains = correlate(findings)
    # XSS duplicates merged → 2 unique findings
    assert len(enriched) == 2
    # Chains may or may not be built without a chain_builder, but should not crash
    assert isinstance(chains, list)


def test_correlate_empty():
    enriched, chains = correlate([])
    assert enriched == []
    assert chains == []


# ── Module import smoke test ─────────────────────────────────────


def test_correlator_package_imports():
    from nexus.correlator import (
        correlate,
    )

    assert callable(correlate)


def test_correlate_with_all_real_brain_subsystems():
    """Verify correlate() integrates TaxonomyMapper, RemediationDB, KnowledgeGraph, ChainBuilder, and RuleEngine cleanly."""
    from pathlib import Path

    from nexus.brain.chain_builder import ChainBuilder
    from nexus.brain.expert import RuleEngine, build_service_rules
    from nexus.brain.knowledge_graph import KnowledgeGraph
    from nexus.brain.remediation import RemediationDB
    from nexus.brain.taxonomy import TaxonomyMapper

    kb_dir = Path(__file__).resolve().parents[2] / "nexus" / "brain" / "knowledge"
    kg = KnowledgeGraph()
    kg.load_from_directory(kb_dir)
    assert kg.cve_count >= 20
    assert kg.has_cve("CVE-2021-44228")

    cb = ChainBuilder()
    cb.build_default_graph()
    cb.load_templates(kb_dir)

    expert = RuleEngine()
    for rule in build_service_rules():
        expert.add_rule(rule)

    rem = RemediationDB()
    tax = TaxonomyMapper()

    findings = [
        _make_finding(
            host="app.local",
            port=8080,
            protocol="http",
            title="[nuclei] SQL Injection in /search",
            cwe_id="CWE-89",
            severity=Severity.LOW,
            cve_ids=["CVE-2021-44228"],
            tool_source="nuclei",
        ),
        _make_finding(
            host="app.local",
            port=8080,
            protocol="http",
            title="[nikto] Apache HTTP Server vulnerable",
            cwe_id="CWE-22",
            severity=Severity.MEDIUM,
            tool_source="nikto",
        ),
    ]

    enriched, chains = correlate(
        findings,
        taxonomy=tax,
        remediation_db=rem,
        knowledge_graph=kg,
        chain_builder=cb,
        expert=expert,
    )
    assert len(enriched) == 2
    # OWASP mapped via TaxonomyMapper.map_cwe
    assert "A03" in enriched[0].owasp_category
    assert enriched[0].remediation != ""
    # CVSS populated & severity upgraded via KnowledgeGraph + CVSS normalization
    assert enriched[0].severity == Severity.CRITICAL
    # Attack chains discovered against real ChainBuilder goals
    assert len(chains) > 0
    assert all(len(c.steps) > 0 for c in chains)


def test_dedup_preserves_distinct_endpoints():
    findings = [
        _make_finding(
            host="app.local",
            port=443,
            cwe_id="CWE-89",
            title="SQL Injection",
            evidence="URL: https://app.local/login",
        ),
        _make_finding(
            host="app.local",
            port=443,
            cwe_id="CWE-89",
            title="SQL Injection",
            evidence="URL: https://app.local/api/search",
        ),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 2


def test_enrich_uses_max_cve_cvss_and_low_severity():
    from nexus.brain.knowledge_graph import KnowledgeGraph, ServiceKnowledge, VulnEntry

    kg = KnowledgeGraph()
    sk = ServiceKnowledge(name="demo")
    v_low = VulnEntry(cve="CVE-2024-0001", cvss=3.1)
    v_high = VulnEntry(cve="CVE-2024-0002", cvss=8.8)
    sk.vulns.extend([v_low, v_high])
    kg._services["demo"] = sk
    kg._cve_index["CVE-2024-0001"] = ("demo", v_low)
    kg._cve_index["CVE-2024-0002"] = ("demo", v_high)

    f_multi = _make_finding(cve_ids=["CVE-2024-0001", "CVE-2024-0002"], severity=Severity.INFO)
    f_low = _make_finding(cvss_score=2.5, severity=Severity.INFO)
    enrich_findings([f_multi, f_low], knowledge_graph=kg)
    assert f_multi.cvss_score == 8.8
    assert f_multi.severity == Severity.HIGH
    assert f_low.severity == Severity.LOW


def test_graph_mysql_not_sqli_and_expert_str_actions_expand_states():
    from nexus.brain.chain_builder import ChainBuilder
    from nexus.brain.expert import Rule, RuleEngine

    cb = ChainBuilder()
    cb.build_default_graph()

    # MySQL banner finding must NOT trigger sqli_found
    mysql_finding = _make_finding(
        host="db.local", port=3306, protocol="mysql", title="MySQL 8.0 exposed"
    )
    chains_mysql = build_attack_chains([mysql_finding], chain_builder=cb)
    assert not any("sqli" in c.name for c in chains_mysql)

    # Expert Rule with str action should expand graph states (e.g. 'sqli_found' -> 'rce_achieved')
    expert = RuleEngine()
    expert.add_rule(
        Rule(
            name="custom_port_to_sqli",
            conditions=[lambda facts: "port_8080" in facts],
            actions=["check_sqli"],
        )
    )
    port_finding = _make_finding(
        host="web.local", port=8080, protocol="http", title="HTTP Port 8080"
    )
    chains = build_attack_chains([port_finding], chain_builder=cb, expert=expert)
    assert any("sqli_found" in c.name for c in chains)

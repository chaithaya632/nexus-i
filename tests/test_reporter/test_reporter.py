"""Tests for the report generator — markdown, HTML, and data builder."""

import tempfile
import pytest
from pathlib import Path

from nexus.db.models import (
    Engagement,
    EngagementPhase,
    Finding,
    Severity,
    Target,
    ReportMeta,
)
from nexus.db.store import EngagementStore
from nexus.reporter.generator import build_report_data, generate_report, ReportData
from nexus.reporter.markdown import render_markdown
from nexus.reporter.html import render_html


@pytest.fixture
def db_with_data(tmp_path):
    """Create a DB with an engagement, targets, and findings for report testing."""
    db = EngagementStore(tmp_path / "test.db")
    eng = Engagement(name="Test Engagement", target="example.com", phase=EngagementPhase.REPORT)
    db.create_engagement(eng)

    t = Target(host="example.com", ip="93.184.216.34", is_live=True, tech_stack=["nginx", "PHP"],
               engagement_id=eng.id)
    db.add_target(t)

    findings = [
        Finding(
            engagement_id=eng.id,
            host="example.com", port=80, protocol="http",
            title="SQL Injection in login", severity=Severity.CRITICAL,
            cwe_id="CWE-89", cve_ids=["CVE-2024-1234"],
            cvss_score=9.8, tool_source="sqlmap",
            description="SQL injection via username parameter.",
            evidence="Parameter: username\nPayload: ' OR 1=1--",
            remediation="Use parameterized queries.",
            confirmed=True,
        ),
        Finding(
            engagement_id=eng.id,
            host="example.com", port=443, protocol="https",
            title="Missing HSTS Header", severity=Severity.MEDIUM,
            cwe_id="CWE-311", tool_source="nikto",
            description="Strict-Transport-Security header is not set.",
            remediation="Add HSTS header with max-age of at least 1 year.",
        ),
        Finding(
            engagement_id=eng.id,
            host="example.com", port=80, protocol="http",
            title="Open port 80/tcp — http", severity=Severity.INFO,
            tool_source="nmap",
            description="HTTP service detected.",
        ),
    ]
    for f in findings:
        db.add_finding(f)
    return db, eng.id


def test_build_report_data(db_with_data):
    db, eng_id = db_with_data
    data = build_report_data(db, eng_id, title="Test Report", client="ACME Corp")
    assert isinstance(data, ReportData)
    assert data.meta.total_findings == 3
    assert data.meta.critical_count == 1
    assert data.meta.medium_count == 1
    assert data.meta.info_count == 1
    assert "CRITICAL" in data.executive_summary
    assert len(data.findings) == 3
    assert data.meta.client == "ACME Corp"


def test_build_report_data_missing_engagement(db_with_data):
    db, _ = db_with_data
    with pytest.raises(ValueError, match="not found"):
        build_report_data(db, "nonexistent_id")


def test_render_markdown(db_with_data):
    db, eng_id = db_with_data
    data = build_report_data(db, eng_id)
    md = render_markdown(data)
    assert "# Penetration Test Report" in md
    assert "SQL Injection" in md
    assert "CRITICAL" in md
    assert "CWE-89" in md
    assert "CVE-2024-1234" in md
    assert "Missing HSTS" in md
    assert "Methodology" in md
    assert "Executive Summary" in md
    assert "NEXUS" in md


def test_render_html(db_with_data):
    db, eng_id = db_with_data
    data = build_report_data(db, eng_id)
    html = render_html(data)
    assert "<!DOCTYPE html>" in html
    assert "SQL Injection" in html
    assert "CRITICAL" in html
    assert "#dc2626" in html  # critical color
    assert "CWE-89" in html
    assert "NEXUS" in html


def test_generate_report_md_html(db_with_data, tmp_path):
    db, eng_id = db_with_data
    out = tmp_path / "reports"
    generated = generate_report(db, eng_id, out, formats=["md", "html"])
    assert len(generated) == 2
    assert any(p.endswith(".md") for p in generated)
    assert any(p.endswith(".html") for p in generated)
    # Verify files exist and have content
    for p in generated:
        content = Path(p).read_text(encoding="utf-8")
        assert len(content) > 100


def test_generate_report_pdf_missing_dep(db_with_data, tmp_path):
    """PDF generation should log warning if weasyprint not installed, not crash."""
    db, eng_id = db_with_data
    out = tmp_path / "reports"
    # This may or may not generate PDF depending on weasyprint install
    generated = generate_report(db, eng_id, out, formats=["pdf"])
    # Should not raise — gracefully handled
    assert isinstance(generated, list)


def test_severity_badge():
    from nexus.reporter.markdown import _severity_badge
    assert "CRITICAL" in _severity_badge("critical")
    assert "HIGH" in _severity_badge("high")
    assert "INFO" in _severity_badge("info")


def test_html_escaping():
    from nexus.reporter.html import _esc
    assert _esc("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" or "&lt;script&gt;" in _esc("<script>")


def test_reporter_package_imports():
    from nexus.reporter import generate_report, build_report_data, ReportData
    assert callable(generate_report)


def test_generate_report_prepends_ai_summary(db_with_data, tmp_path):
    db, eng_id = db_with_data
    out = tmp_path / "reports_ai"
    generated = generate_report(
        db, eng_id, out, formats=["md"],
        ai_summary="Custom AI insight: Prioritize SQLi remediation immediately.",
    )
    assert len(generated) == 1
    md = Path(generated[0]).read_text(encoding="utf-8")
    assert "Custom AI insight" in md
    assert "This penetration test identified 3 findings" in md


def test_reporter_redacts_secrets_and_parity_across_md_html_docx(tmp_path):
    import json
    from nexus.db.models import AttackChain, ChainStep, Credential
    from nexus.reporter.sarif import render_sarif

    db = EngagementStore(tmp_path / "full_rep.db")
    eng = Engagement(name="Full", target="app.local", phase=EngagementPhase.REPORT)
    db.create_engagement(eng)
    db.add_target(Target(engagement_id=eng.id, host="app.local", ip="10.0.0.5", is_live=True, os_guess="Linux"))
    db.add_credential(Credential(
        engagement_id=eng.id, host="app.local", port=22, service="ssh",
        username="deploy", password="TopSecretPassword!", hash_value="hashSecret!", source="hydra",
    ))
    db.add_chain(AttackChain(
        engagement_id=eng.id, name="Web to RCE", impact=Severity.CRITICAL,
        steps=[ChainStep(order=1, action="sqli", tool="sqlmap")],
    ))
    db.add_finding(Finding(
        engagement_id=eng.id, host="app.local", port=None, protocol="http",
        title="SQL Injection | 'union' select\nin /login", cwe_id="CWE-89",
        severity=Severity.HIGH, tool_source="sqlmap",
    ))
    db.add_finding(Finding(
        engagement_id=eng.id, host="app.local", port=443, protocol="https",
        title="Second CWE-89 finding", cwe_id="CWE-89",
        severity=Severity.MEDIUM, tool_source="sqlmap", cvss_score="invalid_float",  # type: ignore[arg-type]
    ) if False else Finding(
        engagement_id=eng.id, host="app.local", port=443, protocol="https",
        title="Second CWE-89 finding", cwe_id="CWE-89",
        severity=Severity.MEDIUM, tool_source="sqlmap",
    ))

    data = build_report_data(db, eng.id)
    assert data.credentials[0]["password"] == "***REDACTED***"
    assert "TopSecretPassword!" not in str(data)

    out = tmp_path / "out"
    files = generate_report(db, eng.id, out, formats=["md", "html", "docx", "sarif"])
    assert len(files) == 4

    md_txt = (out / f"nexus_report_{eng.id}.md").read_text(encoding="utf-8")
    assert "Severity.CRITICAL" not in md_txt
    assert "CRITICAL" in md_txt
    assert "\\|" in md_txt

    html_txt = (out / f"nexus_report_{eng.id}.html").read_text(encoding="utf-8")
    assert "Discovered Credentials" in html_txt
    assert "Targets" in html_txt
    assert ">None<" not in html_txt
    assert "TopSecretPassword!" not in html_txt
    assert "@page" in html_txt
    assert "max-height: 300px" not in html_txt
    assert "max-height:300px" not in html_txt

    from docx import Document
    doc = Document(str(out / f"nexus_report_{eng.id}.docx"))
    doc_text = "\n".join(p.text for p in doc.paragraphs)
    assert "Discovered Credentials" in doc_text
    assert "Targets" in doc_text
    assert "TopSecretPassword!" not in doc_text
    assert "**CRITICAL**" not in doc_text

    sarif_doc = json.loads((out / f"nexus_report_{eng.id}.sarif").read_text(encoding="utf-8"))
    rules = sarif_doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2  # Distinct titles with same CWE-89 get distinct ruleIds

    from nexus.reporter.html import _esc
    assert _esc(None) == ""
    assert _esc("a'b") == "a&#x27;b"

    # Guard invalid float cvss_score in SARIF dict inputs
    data.findings.append({"title": "Bad CVSS", "host": "app.local", "severity": "low", "cvss_score": "bad"})
    sarif_raw = json.loads(render_sarif(data))
    assert len(sarif_raw["runs"][0]["results"]) == 3


"""Wave 3 tests: SARIF v2.1.0 export, .nexusignore baseline suppressions, diffing, and CVE packs."""

from __future__ import annotations

import json
from pathlib import Path

from nexus.brain.knowledge_graph import KnowledgeGraph
from nexus.brain.remediation import RemediationDB
from nexus.core.config import NexusConfig
from nexus.correlator.baseline import (
    apply_baseline_suppressions,
    load_ignore_rules,
)
from nexus.correlator.diff import diff_engagements
from nexus.db.models import Engagement, EngagementPhase, Finding, Severity, Target
from nexus.db.store import EngagementStore
from nexus.reporter.generator import build_report_data, generate_report


class TestSarifExportAndSuppressions:
    """SARIF v2.1.0 schema, severity mapping, and .nexusignore baseline suppression."""

    def test_sarif_generation_with_suppressed_and_active_findings(self, tmp_path: Path) -> None:
        db = EngagementStore(tmp_path / "sarif.db")
        eng = Engagement(name="sarif-ci", target="app.local", phase=EngagementPhase.REPORT)
        db.create_engagement(eng)
        db.add_target(Target(engagement_id=eng.id, host="app.local", is_live=True))

        f_crit = Finding(
            engagement_id=eng.id, host="app.local", port=443, protocol="https",
            title="Spring4Shell RCE", severity=Severity.CRITICAL, cvss_score=9.8,
            cve_ids=["CVE-2022-22965"], cwe_id="CWE-94", owasp_category="A03:2021",
            tool_source="nuclei", remediation="Upgrade Spring Framework to 5.3.18+",
        )
        f_supp = Finding(
            engagement_id=eng.id, host="app.local", port=80, protocol="http",
            title="HTTP: Missing X-Content-Type-Options: nosniff",
            severity=Severity.INFO, cwe_id="CWE-693", tool_source="http_headers",
            false_positive=True,
        )
        db.add_finding(f_crit)
        db.add_finding(f_supp)

        # Active report excludes false_positive while SARIF includes suppressions metadata
        data = build_report_data(db, eng.id)
        assert data.meta.total_findings == 1
        assert len(data.findings) == 1
        assert len(data.suppressed_findings) == 1

        out_files = generate_report(db, eng.id, tmp_path / "rep", formats=["sarif"])
        assert len(out_files) == 1
        sarif_path = Path(out_files[0])
        assert sarif_path.name.endswith(".sarif")

        doc = json.loads(sarif_path.read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"
        run = doc["runs"][0]
        driver = run["tool"]["driver"]
        assert driver["name"] == "NEXUS"
        rule_ids = {r["id"] for r in driver["rules"]}
        results = run["results"]
        assert len(results) == 2
        for res in results:
            assert res["ruleId"] in rule_ids

        crit_res = next(r for r in results if r["ruleId"] == "CVE-2022-22965")
        supp_res = next(r for r in results if r["ruleId"] != "CVE-2022-22965")
        assert crit_res["level"] == "error"
        assert "suppressions" not in crit_res
        assert supp_res["suppressions"][0]["kind"] == "inSource"

    def test_nexusignore_text_and_yaml_rules(self, tmp_path: Path) -> None:
        ign_txt = tmp_path / ".nexusignore"
        ign_txt.write_text(
            "# Baseline CI suppressions\n"
            "CVE-2023-44487\n"
            "CWE-693 host:staging.local\n"
            "title:*HSTS*\n",
            encoding="utf-8",
        )
        rules = load_ignore_rules(ign_txt)
        assert len(rules) == 3

        f1 = Finding(host="prod.local", port=443, title="Rapid Reset", cve_ids=["CVE-2023-44487"], severity=Severity.HIGH)
        f2 = Finding(host="staging.local", port=80, title="Missing CSP", cwe_id="CWE-693", severity=Severity.LOW)
        f3 = Finding(host="prod.local", port=80, title="Missing CSP", cwe_id="CWE-693", severity=Severity.LOW)
        f4 = Finding(host="prod.local", port=443, title="Missing HSTS Header", severity=Severity.LOW)

        res, count = apply_baseline_suppressions([f1, f2, f3, f4], rules)
        assert count == 3
        assert res[0].false_positive is True   # CVE-2023-44487
        assert res[1].false_positive is True   # CWE-693 on staging.local
        assert res[2].false_positive is False  # CWE-693 on prod.local stays active!
        assert res[3].false_positive is True   # *HSTS*

        ign_yaml = tmp_path / "ignore.yaml"
        ign_yaml.write_text(
            "ignores:\n  - cwe: CWE-1021\n    host: '*.internal'\n    reason: accepted internally\n",
            encoding="utf-8",
        )
        y_rules = load_ignore_rules(ign_yaml)
        fy = Finding(host="app.internal", title="No XFO", cwe_id="CWE-1021", severity=Severity.LOW)
        _, y_cnt = apply_baseline_suppressions([fy], y_rules)
        assert y_cnt == 1


class TestEngagementDiffing:
    """Baseline diff detects new regressions, resolved fixes, and persistent findings."""

    def test_diff_engagements_classifies_findings(self, tmp_path: Path) -> None:
        db = EngagementStore(tmp_path / "diff.db")
        e1 = Engagement(id="eng_old", name="old", target="app.local", phase=EngagementPhase.COMPLETE)
        e2 = Engagement(id="eng_new", name="new", target="app.local", phase=EngagementPhase.COMPLETE)
        db.create_engagement(e1)
        db.create_engagement(e2)

        # Old: XSS (fixed) + HSTS (persists)
        db.add_finding(Finding(engagement_id=e1.id, host="app.local", port=443, title="Reflected XSS", cwe_id="CWE-79", severity=Severity.HIGH))
        db.add_finding(Finding(engagement_id=e1.id, host="app.local", port=443, title="Missing HSTS", cwe_id="CWE-523", severity=Severity.LOW))

        # New: HSTS (persists) + SQLi (new regression) + suppressed info
        db.add_finding(Finding(engagement_id=e2.id, host="app.local", port=443, title="Missing HSTS", cwe_id="CWE-523", severity=Severity.LOW))
        db.add_finding(Finding(engagement_id=e2.id, host="app.local", port=443, title="SQL Injection", cwe_id="CWE-89", severity=Severity.CRITICAL))
        db.add_finding(Finding(engagement_id=e2.id, host="app.local", port=443, title="Banner Info", severity=Severity.INFO, false_positive=True))

        diff = diff_engagements(db, e1.id, e2.id)
        assert diff["counts"] == {"new": 1, "resolved": 1, "persistent": 1, "suppressed": 1}
        assert diff["new"][0]["title"] == "SQL Injection"
        assert diff["resolved"][0]["title"] == "Reflected XSS"
        assert diff["persistent"][0]["title"] == "Missing HSTS"
        assert diff["new_by_severity"] == {"critical": 1}


class TestExpandedKnowledgeAndRemediationPacks:
    """Expanded version-bounded CVE packs and CVE remediation YAML integration."""

    def test_version_bounded_cves_and_ambiguous_minor_guard(self) -> None:
        cfg = NexusConfig()
        kg = KnowledgeGraph()
        kg.load_from_directory(cfg.knowledge_dir)
        assert kg.cve_count >= 30

        # Ambiguous minor-only banner MUST NOT trigger patch-specific CVEs (prevents Apache/2.4 FPs)
        assert kg.match_banner_vulns("http", "Apache/2.4") == []

        # Concrete vulnerable vs patched versions
        a30 = {e.cve for _, e in kg.match_banner_vulns("http", "Apache/2.4.30")}
        assert "CVE-2019-0211" in a30 and "CVE-2023-25690" in a30
        assert kg.match_banner_vulns("http", "Apache/2.4.62") == []

        j_vuln = {e.cve for _, e in kg.match_banner_vulns("http", "Jenkins 2.441")}
        j_patch = {e.cve for _, e in kg.match_banner_vulns("http", "Jenkins 2.442")}
        assert "CVE-2024-23897" in j_vuln
        assert "CVE-2024-23897" not in j_patch

        n_vuln = {e.cve for _, e in kg.match_banner_vulns("http", "nginx/1.24.0")}
        n_patch = {e.cve for _, e in kg.match_banner_vulns("http", "nginx/1.26.0")}
        assert "CVE-2023-44487" in n_vuln
        assert "CVE-2023-44487" not in n_patch

        rem = RemediationDB()
        rem.load_from_yaml(cfg.knowledge_dir / "remediations")
        r = rem.get_for_finding(cve_ids=["CVE-2024-23897"])
        assert r is not None
        assert "2.442" in r.short_fix

        # CMS CVE bounds (Wave 4 accuracy)
        d_vuln = {e.cve for _, e in kg.match_banner_vulns("http", "Drupal 7.50")}
        d_patch = {e.cve for _, e in kg.match_banner_vulns("http", "Drupal 7.58")}
        assert "CVE-2018-7600" in d_vuln
        assert "CVE-2018-7600" not in d_patch

        j_cms_vuln = {e.cve for _, e in kg.match_banner_vulns("http", "Joomla 4.2.5")}
        j_cms_patch = {e.cve for _, e in kg.match_banner_vulns("http", "Joomla 4.2.8")}
        assert "CVE-2023-23752" in j_cms_vuln
        assert "CVE-2023-23752" not in j_cms_patch

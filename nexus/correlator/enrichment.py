"""Finding enrichment — add CVSS/EPSS scores and taxonomy mappings."""

from __future__ import annotations

import logging
from typing import Protocol

from nexus.correlator.dedup import severity_rank
from nexus.db.models import Finding, Severity

log = logging.getLogger("nexus.correlator.enrichment")


class TaxonomyLike(Protocol):
    def map_finding(self, finding: Finding) -> str: ...


class RemediationLike(Protocol):
    def get_for_finding(self, cwe_id: str = "", cve_ids: list[str] | None = None) -> object | None: ...


class KnowledgeGraphLike(Protocol):
    def lookup_cve(self, cve_id: str) -> tuple[str, object] | None: ...


def _upgrade_severity(current: Severity, target: Severity) -> Severity:
    return target if severity_rank(target) > severity_rank(current) else current


def enrich_findings(
    findings: list[Finding],
    *,
    taxonomy: TaxonomyLike | None = None,
    remediation_db: RemediationLike | None = None,
    knowledge_graph: KnowledgeGraphLike | None = None,
) -> list[Finding]:
    """Enrich findings with taxonomy, remediation, and KB lookups.

    Modifies findings in-place and returns them.
    """
    for f in findings:
        # 1. OWASP category mapping via TaxonomyMapper.map_finding()
        if taxonomy and not f.owasp_category:
            mapped = taxonomy.map_finding(f)
            if mapped:
                f.owasp_category = mapped

        # 2. Known CVEs from knowledge graph (max CVSS across all CVEs, populate CWE, upgrade if exploit exists)
        if knowledge_graph and f.cve_ids:
            cve_scores: list[float] = []
            for cve_id in f.cve_ids:
                hit = knowledge_graph.lookup_cve(cve_id)
                if not hit:
                    continue
                _, entry = hit
                cvss_val = float(getattr(entry, "cvss", 0.0) or 0.0)
                if cvss_val > 0:
                    cve_scores.append(cvss_val)
                vuln_type = str(getattr(entry, "vuln_type", "") or "")
                if not f.cwe_id and vuln_type.upper().startswith("CWE-"):
                    f.cwe_id = vuln_type.upper()
                if getattr(entry, "exploits", None) and severity_rank(f.severity) < severity_rank(Severity.HIGH):
                    log.info(
                        "Upgrading %s severity: known exploit for %s",
                        f.title, cve_id,
                    )
                    f.severity = Severity.HIGH
            if f.cvss_score is None and cve_scores:
                f.cvss_score = max(cve_scores)

        # 3. Remediation from KB (run after CWE/CVE enrichment so newly added CWEs match)
        if remediation_db and not f.remediation:
            rem = remediation_db.get_for_finding(f.cwe_id, f.cve_ids)
            if rem:
                f.remediation = getattr(rem, "short_fix", "") or ""

        # 4. CVSS-based severity normalization (CRITICAL >=9.0, HIGH >=7.0, MEDIUM >=4.0, LOW >0.0)
        if f.cvss_score is not None and f.cvss_score > 0:
            if f.cvss_score >= 9.0:
                f.severity = Severity.CRITICAL
            elif f.cvss_score >= 7.0:
                f.severity = _upgrade_severity(f.severity, Severity.HIGH)
            elif f.cvss_score >= 4.0:
                f.severity = _upgrade_severity(f.severity, Severity.MEDIUM)
            else:
                f.severity = _upgrade_severity(f.severity, Severity.LOW)

    log.info("Enriched %d findings", len(findings))
    return findings

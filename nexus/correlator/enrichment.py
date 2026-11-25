"""Finding enrichment — add CVSS/EPSS scores and taxonomy mappings."""

from __future__ import annotations

import logging
from typing import Any

from nexus.db.models import Finding

log = logging.getLogger("nexus.correlator.enrichment")


def enrich_findings(
    findings: list[Finding],
    *,
    taxonomy: Any = None,
    remediation_db: Any = None,
    knowledge_graph: Any = None,
) -> list[Finding]:
    """Enrich findings with taxonomy, remediation, and KB lookups.

    Modifies findings in-place and returns them.

    Args:
        taxonomy: TaxonomyMapper instance for OWASP/CWE mapping.
        remediation_db: RemediationDB instance for fix suggestions.
        knowledge_graph: KnowledgeGraph for CVE→exploit mapping.
    """
    for f in findings:
        # 1. OWASP category mapping (prefer CWE map, fallback to title/desc keywords)
        if taxonomy and not f.owasp_category:
            if f.cwe_id:
                mapping = taxonomy.map_cwe(f.cwe_id)
                if mapping:
                    f.owasp_category = mapping.get("owasp", "")
            if not f.owasp_category:
                cat_id = taxonomy.classify_owasp(f.title, f.description)
                if cat_id:
                    f.owasp_category = f"{cat_id} — {taxonomy.get_owasp_name(cat_id)}"

        # 2. Known CVEs from knowledge graph (populate CWE/CVSS + upgrade if exploit exists)
        if knowledge_graph and f.cve_ids:
            from nexus.db.models import Severity
            for cve_id in f.cve_ids:
                hit = knowledge_graph.lookup_cve(cve_id)
                if not hit:
                    continue
                _, entry = hit
                if f.cvss_score is None and entry.cvss > 0:
                    f.cvss_score = entry.cvss
                if not f.cwe_id and entry.vuln_type.upper().startswith("CWE-"):
                    f.cwe_id = entry.vuln_type.upper()
                if entry.exploits and f.severity.value not in ("critical", "high"):
                    log.info(
                        "Upgrading %s severity: known exploit for %s",
                        f.title, cve_id,
                    )
                    f.severity = Severity.HIGH

        # 3. Remediation from KB (run after CWE/CVE enrichment so newly added CWEs match)
        if remediation_db and not f.remediation:
            rem = remediation_db.get_for_finding(f.cwe_id, f.cve_ids)
            if rem:
                f.remediation = rem.short_fix

        # 4. CVSS-based severity normalization
        if f.cvss_score is not None and f.cvss_score > 0:
            from nexus.db.models import Severity
            if f.cvss_score >= 9.0:
                f.severity = Severity.CRITICAL
            elif f.cvss_score >= 7.0:
                f.severity = max(f.severity, Severity.HIGH, key=lambda s: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(s.value, 0))
            elif f.cvss_score >= 4.0:
                f.severity = max(f.severity, Severity.MEDIUM, key=lambda s: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(s.value, 0))

    log.info("Enriched %d findings", len(findings))
    return findings

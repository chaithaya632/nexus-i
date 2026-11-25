"""Finding deduplication — merge duplicate/near-duplicate findings."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from nexus.db.models import Finding, Severity

log = logging.getLogger("nexus.correlator.dedup")

# Severity ranking for merge (keep the highest)
_SEV_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate and near-duplicate findings.

    Dedup key: (host, port, cwe_id or title_normalized).
    When merging, keep the highest severity, merge CVE lists, and
    concatenate evidence from all sources.
    """
    if not findings:
        return []

    buckets: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        key = _dedup_key(f)
        buckets[key].append(f)

    merged: list[Finding] = []
    for key, group in buckets.items():
        if len(group) == 1:
            merged.append(group[0])
        else:
            merged.append(_merge_findings(group))

    deduped = len(findings) - len(merged)
    if deduped > 0:
        log.info("Deduplicated %d findings → %d unique", len(findings), len(merged))
    return merged


def _dedup_key(f: Finding) -> str:
    """Generate a dedup key from a finding."""
    # Use CWE if available, otherwise normalize the title
    identifier = f.cwe_id if f.cwe_id else _normalize_title(f.title)
    return f"{f.host}:{f.port or 0}:{identifier}"


def _normalize_title(title: str) -> str:
    """Normalize a title for dedup comparison."""
    # Strip tool prefixes like [nuclei], [Nessus], etc.
    title = title.strip()
    for prefix in ("[nuclei]", "[Nessus]", "[Burp]", "[Nikto]", "Nikto:", "Nmap script:"):
        if title.startswith(prefix):
            title = title[len(prefix):].strip()
    return title.lower()


def _merge_findings(group: list[Finding]) -> Finding:
    """Merge a group of duplicate findings into one."""
    # Sort by severity (highest first)
    group.sort(key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
    best = group[0]

    # Merge CVE IDs
    all_cves: set[str] = set()
    for f in group:
        all_cves.update(f.cve_ids)
    best.cve_ids = sorted(all_cves)

    # Keep highest CVSS
    scores = [f.cvss_score for f in group if f.cvss_score is not None]
    if scores:
        best.cvss_score = max(scores)

    # Merge tool sources
    tools = sorted(set(f.tool_source for f in group if f.tool_source))
    best.tool_source = ", ".join(tools)

    # Merge evidence (cap at 4000 chars)
    evidence_parts = [f.evidence for f in group if f.evidence]
    if evidence_parts:
        best.evidence = "\n---\n".join(evidence_parts)[:4000]

    # Keep best remediation
    if not best.remediation:
        for f in group:
            if f.remediation:
                best.remediation = f.remediation
                break

    # Mark as confirmed if any source confirmed it
    if any(f.confirmed for f in group):
        best.confirmed = True

    return best

"""Finding deduplication — merge duplicate/near-duplicate findings."""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from urllib.parse import urlsplit

from nexus.db.models import Finding, Severity

log = logging.getLogger("nexus.correlator.dedup")

# Severity ranking for merge (keep the highest)
SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}
_SEV_RANK = SEVERITY_RANK

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_HTTP_REQ_RE = re.compile(
    r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s\"'<>?]*)", re.IGNORECASE
)
_PATH_RE = re.compile(r"(?:^|[\s\"'(=])(/[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)*)")


def severity_rank(sev: Severity | str | None) -> int:
    """Return numeric severity rank (5=critical .. 1=info, 0=unknown)."""
    if isinstance(sev, Severity):
        return SEVERITY_RANK.get(sev, 0)
    s = str(sev or "").strip().lower()
    for member, rank in SEVERITY_RANK.items():
        if member.value == s:
            return rank
    return 0


def extract_endpoint(f: Finding) -> str:
    """Extract normalized URL path/endpoint from finding request, evidence, description, or title."""
    for text in (f.request, f.evidence, f.description, f.title):
        if not text:
            continue
        url_m = _URL_RE.search(text)
        if url_m:
            path = urlsplit(url_m.group(0)).path.rstrip("/")
            return (path or "/").lower()
        req_m = _HTTP_REQ_RE.search(text)
        if req_m:
            path = req_m.group(1).rstrip("/")
            return (path or "/").lower()
        path_m = _PATH_RE.search(text)
        if path_m:
            candidate = path_m.group(1).rstrip("/")
            if candidate.lower() not in ("/tcp", "/udp"):
                return candidate.lower()
    return ""


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate and near-duplicate findings.

    Dedup key: (host, port, cwe_id or title_normalized, endpoint).
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
    for group in buckets.values():
        if len(group) == 1:
            merged.append(group[0])
        else:
            merged.append(_merge_findings(group))

    deduped = len(findings) - len(merged)
    if deduped > 0:
        log.info("Deduplicated %d findings → %d unique", len(findings), len(merged))
    return merged


def _dedup_key(f: Finding) -> str:
    """Generate a dedup key from a finding, preserving distinct endpoints."""
    identifier = f.cwe_id.strip().upper() if f.cwe_id else _normalize_title(f.title)
    endpoint = extract_endpoint(f)
    return f"{f.host.strip().lower()}:{f.port or 0}:{identifier}:{endpoint}"


def _normalize_title(title: str) -> str:
    """Normalize a title for dedup comparison."""
    title = title.strip()
    for prefix in ("[nuclei]", "[Nessus]", "[Burp]", "[Nikto]", "Nikto:", "Nmap script:"):
        if title.startswith(prefix):
            title = title[len(prefix) :].strip()
    return title.lower()


def _merge_findings(group: list[Finding]) -> Finding:
    """Merge a group of duplicate findings into one."""
    group.sort(key=lambda f: severity_rank(f.severity), reverse=True)
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

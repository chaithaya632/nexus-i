"""Engagement baseline comparison (`nexus diff`) for CI/CD regression gating."""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

from nexus.correlator.dedup import extract_endpoint
from nexus.db.models import Finding
from nexus.db.store import EngagementStore


def finding_fingerprint(f: Finding) -> tuple[str, int, str, tuple[str, ...], str, str]:
    """Stable identity key matching findings across consecutive engagement runs."""
    endpoint = extract_endpoint(f)
    if not endpoint and f.description.strip():
        endpoint = "desc:" + hashlib.sha1(f.description.strip().lower().encode("utf-8")).hexdigest()[:10]
    return (
        f.host.strip().lower(),
        int(f.port or 0),
        f.cwe_id.strip().upper(),
        tuple(sorted(c.strip().upper() for c in f.cve_ids)),
        f.title.strip().lower(),
        endpoint,
    )


def diff_engagements(store: EngagementStore, old_id: str, new_id: str) -> dict[str, Any]:
    """Compare two engagements and classify active findings as new, resolved, or persistent."""
    old_eng = store.get_engagement(old_id)
    if not old_eng:
        raise ValueError(f"Baseline engagement '{old_id}' not found.")
    new_eng = store.get_engagement(new_id)
    if not new_eng:
        raise ValueError(f"Target engagement '{new_id}' not found.")

    old_all = store.get_findings(old_id)
    new_all = store.get_findings(new_id)

    old_active = {finding_fingerprint(f): f for f in old_all if not f.false_positive}
    new_active = {finding_fingerprint(f): f for f in new_all if not f.false_positive}

    new_findings = [f for fp, f in new_active.items() if fp not in old_active]
    resolved_findings = [f for fp, f in old_active.items() if fp not in new_active]
    persistent_findings = [f for fp, f in new_active.items() if fp in old_active]
    suppressed_new = sum(1 for f in new_all if f.false_positive)

    new_sev = dict(Counter(f.severity.value for f in new_findings))
    resolved_sev = dict(Counter(f.severity.value for f in resolved_findings))

    return {
        "old_id": old_id,
        "new_id": new_id,
        "old_target": old_eng.target,
        "new_target": new_eng.target,
        "new": [f.model_dump(mode="json") for f in new_findings],
        "resolved": [f.model_dump(mode="json") for f in resolved_findings],
        "persistent": [f.model_dump(mode="json") for f in persistent_findings],
        "suppressed_in_new": suppressed_new,
        "counts": {
            "new": len(new_findings),
            "resolved": len(resolved_findings),
            "persistent": len(persistent_findings),
            "suppressed": suppressed_new,
        },
        "new_by_severity": new_sev,
        "resolved_by_severity": resolved_sev,
    }

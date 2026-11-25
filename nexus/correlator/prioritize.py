"""Risk prioritization, confidence scoring, and remediation backlog builder."""

from __future__ import annotations

import gzip
import json
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from nexus.db.models import AttackChain, Finding, Severity

log = logging.getLogger("nexus.correlator.prioritize")

_SEV_BASE: dict[Severity, float] = {
    Severity.CRITICAL: 45.0,
    Severity.HIGH: 35.0,
    Severity.MEDIUM: 22.0,
    Severity.LOW: 10.0,
    Severity.INFO: 3.0,
}


def _coerce_finding(item: Finding | dict[str, Any]) -> Finding:
    """Normalize either a Finding model or serialized ReportData dict into a Finding."""
    if isinstance(item, Finding):
        return item
    if isinstance(item, dict):
        return Finding.model_validate(item)
    return Finding(title=str(item), severity=Severity.INFO)


@lru_cache(maxsize=1)
def load_kev_cve_set() -> frozenset[str]:
    """Load CVE IDs from the bundled compressed CISA KEV snapshot."""
    kev_path = (
        Path(__file__).resolve().parents[1]
        / "brain"
        / "knowledge"
        / "cves"
        / "cisa_kev_snapshot.json.gz"
    )
    if not kev_path.is_file():
        return frozenset()
    try:
        with gzip.open(kev_path, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
        cve_ids: set[str] = set()
        if isinstance(data, dict):
            if isinstance(data.get("cves"), dict):
                cve_ids.update(str(k).upper() for k in data["cves"].keys() if k)
            vulns = data.get("vulnerabilities", [])
            if isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, dict) and (v.get("cveID") or v.get("cve_id")):
                        cve_ids.add(str(v.get("cveID") or v.get("cve_id")).upper())
        return frozenset(cve_ids)
    except Exception as exc:
        log.debug("Could not load bundled CISA KEV snapshot: %s", exc)
        return frozenset()


@dataclass
class PrioritizedFinding:
    """Finding annotated with deterministic confidence and risk-priority scores."""

    finding: Finding
    confidence_score: int
    priority_score: int
    is_kev: bool = False
    in_attack_chain: bool = False
    corroborating_tools: int = 1
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding.id,
            "title": self.finding.title,
            "host": self.finding.host,
            "port": self.finding.port,
            "severity": self.finding.severity.value,
            "cvss_score": self.finding.cvss_score,
            "cwe_id": self.finding.cwe_id,
            "owasp_category": self.finding.owasp_category,
            "cve_ids": list(self.finding.cve_ids),
            "tool_source": self.finding.tool_source,
            "confidence_score": self.confidence_score,
            "priority_score": self.priority_score,
            "is_kev": self.is_kev,
            "in_attack_chain": self.in_attack_chain,
            "corroborating_tools": self.corroborating_tools,
            "reasons": list(self.reasons),
            "remediation": self.finding.remediation,
        }


def compute_confidence(finding: Finding | dict[str, Any]) -> tuple[int, int, list[str]]:
    """Return (confidence_0_to_100, tool_count, reasons) for a finding."""
    model = _coerce_finding(finding)
    score = 25
    reasons: list[str] = []

    tools = [t.strip() for t in (model.tool_source or "").split(",") if t.strip()]
    tool_count = max(1, len(set(tools)))
    if tool_count > 1:
        bonus = min(30, (tool_count - 1) * 20)
        score += bonus
        reasons.append(f"corroborated by {tool_count} tools (+{bonus})")

    if model.confirmed:
        score += 35
        reasons.append("verified/confirmed (+35)")

    if model.evidence and len(model.evidence.strip()) >= 12:
        score += 15
        reasons.append("structured evidence (+15)")

    if model.cwe_id or model.cve_ids:
        score += 10
        reasons.append("CWE/CVE mapped (+10)")

    return min(100, score), tool_count, reasons


def rank_findings_by_priority(
    findings: list[Finding | dict[str, Any]],
    chains: list[AttackChain | dict[str, Any]] | None = None,
    *,
    kev_cves: frozenset[str] | None = None,
) -> list[PrioritizedFinding]:
    """Score and rank findings by composite business/remediation priority (0-100)."""
    kev_set = kev_cves if kev_cves is not None else load_kev_cve_set()
    chain_finding_ids: set[str] = set()
    chain_hosts: set[str] = set()
    for ch in chains or []:
        steps = ch.get("steps", []) if isinstance(ch, dict) else getattr(ch, "steps", [])
        for step in steps or []:
            fid = (
                getattr(step, "finding_id", "")
                if not isinstance(step, dict)
                else step.get("finding_id", "")
            )
            host = getattr(step, "host", "") if not isinstance(step, dict) else step.get("host", "")
            if fid:
                chain_finding_ids.add(str(fid))
            if host:
                chain_hosts.add(str(host).lower())

    ranked: list[PrioritizedFinding] = []
    for raw in findings:
        f = _coerce_finding(raw)
        if f.false_positive:
            continue
        conf, tool_count, reasons = compute_confidence(f)

        # Base score from CVSS (preferred) or severity
        if f.cvss_score is not None and f.cvss_score > 0:
            base = min(45.0, (f.cvss_score / 10.0) * 45.0)
        else:
            base = _SEV_BASE.get(f.severity, 3.0)

        # CISA KEV boost
        matched_kev = [c.upper() for c in f.cve_ids if c.upper() in kev_set]
        is_kev = bool(matched_kev)
        kev_bonus = 25.0 if is_kev else 0.0
        if is_kev:
            reasons.append(f"CISA KEV listed: {', '.join(matched_kev[:3])} (+25)")

        # Attack-chain participation boost
        in_chain = (f.id in chain_finding_ids) or (
            bool(f.host)
            and f.host.lower() in chain_hosts
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        chain_bonus = 20.0 if in_chain else 0.0
        if in_chain:
            reasons.append("part of correlated risk chain (+20)")

        conf_bonus = round((conf / 100.0) * 10.0, 1)
        priority = min(100, int(round(base + kev_bonus + chain_bonus + conf_bonus)))

        ranked.append(
            PrioritizedFinding(
                finding=f,
                confidence_score=conf,
                priority_score=priority,
                is_kev=is_kev,
                in_attack_chain=in_chain,
                corroborating_tools=tool_count,
                reasons=reasons,
            )
        )

    ranked.sort(
        key=lambda pf: (pf.priority_score, pf.confidence_score, pf.finding.cvss_score or 0.0),
        reverse=True,
    )
    return ranked


def build_remediation_plan(
    findings: list[Finding | dict[str, Any]],
    chains: list[AttackChain | dict[str, Any]] | None = None,
    *,
    top_n: int = 10,
) -> dict[str, Any]:
    """Generate an executive remediation backlog grouped by CWE/OWASP and priority."""
    ranked = rank_findings_by_priority(findings, chains)
    kev_count = sum(1 for pf in ranked if pf.is_kev)
    chain_count = sum(1 for pf in ranked if pf.in_attack_chain)
    avg_conf = round(sum(pf.confidence_score for pf in ranked) / len(ranked), 1) if ranked else 0.0

    by_owasp: dict[str, int] = {}
    for pf in ranked:
        cat = pf.finding.owasp_category or "Uncategorized"
        by_owasp[cat] = by_owasp.get(cat, 0) + 1

    return {
        "total_actionable": len(ranked),
        "kev_flagged": kev_count,
        "chain_linked": chain_count,
        "average_confidence": avg_conf,
        "owasp_breakdown": dict(sorted(by_owasp.items(), key=lambda kv: -kv[1])),
        "top_items": [pf.to_dict() for pf in ranked[:top_n]],
    }

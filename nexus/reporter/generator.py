"""Report orchestrator — generates penetration test reports in multiple formats."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nexus.db.models import ReportMeta

log = logging.getLogger("nexus.reporter.generator")


@dataclass
class ReportData:
    """All data needed to render a report."""
    meta: ReportMeta
    engagement: dict[str, Any]
    targets: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    chains: list[dict[str, Any]]
    credentials: list[dict[str, Any]]
    severity_counts: dict[str, int]
    executive_summary: str
    methodology: str
    suppressed_findings: list[dict[str, Any]] = field(default_factory=list)


def build_report_data(
    db: Any,
    eng_id: str,
    *,
    title: str = "",
    author: str = "NEXUS Automated Report",
    client: str = "",
) -> ReportData:
    """Collect all engagement data into a ReportData structure."""
    eng = db.get_engagement(eng_id)
    if not eng:
        raise ValueError(f"Engagement not found: {eng_id}")

    all_raw = db.get_findings(eng_id)
    findings = [
        f for f in all_raw
        if not (f.get("false_positive", False) if isinstance(f, dict) else getattr(f, "false_positive", False))
    ]
    suppressed = [
        f for f in all_raw
        if (f.get("false_positive", False) if isinstance(f, dict) else getattr(f, "false_positive", False))
    ]
    targets = db.get_targets(eng_id)
    chains = db.get_chains(eng_id)
    creds = db.get_credentials(eng_id)
    severity_counts = db.count_findings_by_severity(eng_id)

    # Sort findings by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    if findings and hasattr(findings[0], "severity"):
        findings.sort(
            key=lambda f: sev_order.get(
                f.severity.value if hasattr(f.severity, "value") else f.severity, 5
            )
        )

    # Serialize to dicts for template rendering
    def _to_dict(obj: Any) -> dict[str, Any]:
        if isinstance(obj, dict):
            return obj
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return {"value": str(obj)}

    eng_target = eng.target if hasattr(eng, "target") else eng.get("target", eng_id)

    meta = ReportMeta(
        engagement_id=eng_id,
        title=title or f"Penetration Test Report — {eng_target}",
        author=author,
        client=client,
        total_findings=len(findings),
        critical_count=severity_counts.get("critical", 0),
        high_count=severity_counts.get("high", 0),
        medium_count=severity_counts.get("medium", 0),
        low_count=severity_counts.get("low", 0),
        info_count=severity_counts.get("info", 0),
        chains_found=len(chains),
    )

    executive_summary = _generate_executive_summary(meta, severity_counts)
    methodology = _standard_methodology()

    return ReportData(
        meta=meta,
        engagement=_to_dict(eng),
        targets=[_to_dict(t) for t in targets],
        findings=[_to_dict(f) for f in findings],
        chains=[_to_dict(c) for c in chains],
        credentials=[_to_dict(c) for c in creds],
        severity_counts=severity_counts,
        executive_summary=executive_summary,
        methodology=methodology,
        suppressed_findings=[_to_dict(f) for f in suppressed],
    )


def generate_report(
    db: Any,
    eng_id: str,
    output_dir: str | Path,
    *,
    formats: list[str] | None = None,
    title: str = "",
    author: str = "NEXUS Automated Report",
    client: str = "",
    ai_summary: str = "",
) -> list[str]:
    """Generate reports in the requested formats.

    Args:
        db: EngagementStore instance.
        eng_id: engagement ID.
        output_dir: directory to write reports to.
        formats: list of formats — "md", "html", "pdf", "docx". Default: ["md", "html"].
        ai_summary: optional AI-generated executive summary to prepend.

    Returns:
        List of generated file paths.
    """
    formats = formats or ["md", "html"]
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data = build_report_data(db, eng_id, title=title, author=author, client=client)

    # Prepend AI summary when available
    if ai_summary:
        data.executive_summary = ai_summary + "\n\n---\n\n" + data.executive_summary
    generated: list[str] = []

    for fmt in formats:
        try:
            if fmt == "md":
                from nexus.reporter.markdown import render_markdown
                path = out_dir / f"nexus_report_{eng_id}.md"
                path.write_text(render_markdown(data), encoding="utf-8")
                generated.append(str(path))

            elif fmt == "html":
                from nexus.reporter.html import render_html
                path = out_dir / f"nexus_report_{eng_id}.html"
                path.write_text(render_html(data), encoding="utf-8")
                generated.append(str(path))

            elif fmt == "pdf":
                from nexus.reporter.pdf import render_pdf
                path = out_dir / f"nexus_report_{eng_id}.pdf"
                render_pdf(data, str(path))
                generated.append(str(path))

            elif fmt == "docx":
                from nexus.reporter.docx import render_docx
                path = out_dir / f"nexus_report_{eng_id}.docx"
                render_docx(data, str(path))
                generated.append(str(path))

            elif fmt == "sarif":
                from nexus.reporter.sarif import render_sarif
                sarif_data = ReportData(
                    meta=data.meta,
                    engagement=data.engagement,
                    targets=data.targets,
                    findings=data.findings + data.suppressed_findings,
                    chains=data.chains,
                    credentials=data.credentials,
                    severity_counts=data.severity_counts,
                    executive_summary=data.executive_summary,
                    methodology=data.methodology,
                    suppressed_findings=data.suppressed_findings,
                )
                path = out_dir / f"nexus_report_{eng_id}.sarif"
                path.write_text(render_sarif(sarif_data), encoding="utf-8")
                generated.append(str(path))

            else:
                log.warning("Unknown report format: %s", fmt)

        except ImportError as e:
            log.warning("Cannot generate %s report — missing dependency: %s", fmt, e)
        except Exception as e:
            log.error("Failed to generate %s report: %s", fmt, e)

    log.info("Generated %d reports for engagement %s", len(generated), eng_id)
    return generated


def _generate_executive_summary(meta: ReportMeta, counts: dict[str, int]) -> str:
    total = meta.total_findings
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)

    risk = "LOW"
    if crit > 0:
        risk = "CRITICAL"
    elif high > 0:
        risk = "HIGH"
    elif counts.get("medium", 0) > 0:
        risk = "MEDIUM"

    return (
        f"This penetration test identified {total} findings across the target environment. "
        f"The overall risk rating is **{risk}**. "
        f"{crit} critical and {high} high severity issues require immediate attention. "
        f"{meta.chains_found} potential attack chains were identified that could lead to "
        f"significant compromise if exploited in combination."
    )


def _standard_methodology() -> str:
    return (
        "The assessment followed a structured methodology aligned with OWASP Testing Guide v4 "
        "and PTES (Penetration Testing Execution Standard):\n\n"
        "1. **Reconnaissance** — Passive and active information gathering including subdomain "
        "enumeration, DNS analysis, OSINT, and technology fingerprinting.\n"
        "2. **Scanning** — Port scanning, service enumeration, vulnerability scanning with "
        "multiple tools (Nuclei, Nikto, ffuf), and WAF detection.\n"
        "3. **Correlation** — Automated deduplication, CVSS/CWE enrichment, OWASP mapping, "
        "and attack chain analysis using graph-based pathfinding.\n"
        "4. **Exploitation** — Targeted exploitation of confirmed vulnerabilities with "
        "scope-enforced, audit-logged execution.\n"
        "5. **Reporting** — Automated generation of findings with remediation guidance, "
        "risk ratings, and executive summary."
    )

"""Markdown report renderer."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from nexus.reporter.generator import ReportData


def render_markdown(data: ReportData) -> str:
    """Render a full penetration test report as Markdown."""
    lines: list[str] = []
    meta = data.meta
    w = lines.append

    w(f"# {meta.title}")
    w("")
    w(f"**Author:** {meta.author}  ")
    w(f"**Client:** {meta.client or 'N/A'}  ")
    w(f"**Date:** {meta.date.strftime('%Y-%m-%d')}  ")
    w(f"**Engagement ID:** {meta.engagement_id}  ")
    w("")

    # Table of Contents
    w("## Table of Contents")
    w("")
    w("1. [Executive Summary](#executive-summary)")
    w("2. [Methodology](#methodology)")
    w("3. [Findings Summary](#findings-summary)")
    w("4. [Detailed Findings](#detailed-findings)")
    w("5. [Attack Chains](#attack-chains)")
    w("6. [Discovered Credentials](#discovered-credentials)")
    w("7. [Targets](#targets)")
    w("")

    # Executive Summary
    w("## Executive Summary")
    w("")
    w(data.executive_summary)
    w("")

    # Severity summary table
    w("### Risk Overview")
    w("")
    w("| Severity | Count |")
    w("|----------|-------|")
    w(f"| Critical | {meta.critical_count} |")
    w(f"| High     | {meta.high_count} |")
    w(f"| Medium   | {meta.medium_count} |")
    w(f"| Low      | {meta.low_count} |")
    w(f"| Info     | {meta.info_count} |")
    w(f"| **Total** | **{meta.total_findings}** |")
    w("")

    # Methodology
    w("## Methodology")
    w("")
    w(data.methodology)
    w("")

    # Findings Summary
    w("## Findings Summary")
    w("")
    if data.findings:
        w("| # | Severity | Title | Host | CWE |")
        w("|---|----------|-------|------|-----|")
        for i, f in enumerate(data.findings, 1):
            sev = f.get("severity", "info")
            if hasattr(sev, "value"):
                sev = sev.value
            title = f.get("title", "Unknown")
            host = f.get("host", "")
            cwe = f.get("cwe_id", "")
            sev_badge = _severity_badge(sev)
            w(f"| {i} | {sev_badge} | {title} | {host} | {cwe} |")
        w("")
    else:
        w("No findings to report.")
        w("")

    # Detailed Findings
    w("## Detailed Findings")
    w("")
    for i, f in enumerate(data.findings, 1):
        sev = f.get("severity", "info")
        if hasattr(sev, "value"):
            sev = sev.value
        w(f"### {i}. {f.get('title', 'Unknown')}")
        w("")
        w(f"**Severity:** {_severity_badge(sev)}  ")
        w(f"**Host:** {f.get('host', 'N/A')}  ")
        if f.get("port"):
            w(f"**Port:** {f['port']}  ")
        if f.get("cwe_id"):
            w(f"**CWE:** {f['cwe_id']}  ")
        if f.get("cve_ids"):
            cves = f["cve_ids"]
            if isinstance(cves, list):
                w(f"**CVEs:** {', '.join(cves)}  ")
        if f.get("cvss_score"):
            w(f"**CVSS:** {f['cvss_score']}  ")
        if f.get("owasp_category"):
            w(f"**OWASP:** {f['owasp_category']}  ")
        w(f"**Tool:** {f.get('tool_source', 'N/A')}  ")
        w("")
        w("**Description:**")
        w("")
        w(f.get("description", "No description available."))
        w("")
        if f.get("evidence"):
            w("**Evidence:**")
            w("")
            w("```")
            w(f["evidence"][:2000])
            w("```")
            w("")
        if f.get("remediation"):
            w("**Remediation:**")
            w("")
            w(f["remediation"])
            w("")
        w("---")
        w("")

    # Attack Chains
    w("## Attack Chains")
    w("")
    if data.chains:
        for i, c in enumerate(data.chains, 1):
            w(f"### Chain {i}: {c.get('name', 'Unnamed')}")
            w("")
            w(f"**Confidence:** {c.get('confidence', 0):.0%}  ")
            w(f"**Impact:** {c.get('impact', 'unknown')}  ")
            w("")
            w(c.get("description", ""))
            w("")
            steps = c.get("steps", [])
            if steps:
                for j, s in enumerate(steps, 1):
                    action = s.get("action", "")
                    tool = s.get("tool", "")
                    w(f"{j}. **{action}** (via {tool})")
                w("")
    else:
        w("No attack chains identified.")
        w("")

    # Credentials
    w("## Discovered Credentials")
    w("")
    if data.credentials:
        w("| Host | Port | Service | Username | Source |")
        w("|------|------|---------|----------|--------|")
        for c in data.credentials:
            w(f"| {c.get('host', '')} | {c.get('port', '')} | {c.get('service', '')} | {c.get('username', '')} | {c.get('source', '')} |")
        w("")
        w("> **Note:** Passwords are redacted from this report for security.")
        w("")
    else:
        w("No credentials discovered.")
        w("")

    # Targets
    w("## Targets")
    w("")
    if data.targets:
        w("| Host | IP | Live | OS | Tech Stack | WAF |")
        w("|------|-----|------|-----|------------|-----|")
        for t in data.targets:
            tech = t.get("tech_stack", [])
            if isinstance(tech, list):
                tech = ", ".join(tech[:5])
            w(f"| {t.get('host', '')} | {t.get('ip', '')} | {t.get('is_live', '')} | {t.get('os_guess', '')} | {tech} | {t.get('waf_detected', '')} |")
        w("")
    else:
        w("No targets enumerated.")
        w("")

    # Footer
    w("---")
    w("")
    w(f"*Report generated by NEXUS — Network EXploration & Unified Security*  ")
    w(f"*{meta.date.strftime('%Y-%m-%d %H:%M UTC')}*")

    return "\n".join(lines)


def _severity_badge(severity: str) -> str:
    """Return a markdown badge/emoji for severity."""
    badges = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🔵 LOW",
        "info": "⚪ INFO",
    }
    return badges.get(severity.lower() if isinstance(severity, str) else "info", severity)

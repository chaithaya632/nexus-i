"""Markdown report renderer."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nexus.correlator.prioritize import build_remediation_plan

if TYPE_CHECKING:
    from nexus.reporter.generator import ReportData


def _enum_str(val: Any, default: str = "") -> str:
    if val is None:
        return default
    return str(val.value if hasattr(val, "value") else val)


def _md_cell(val: Any) -> str:
    """Escape pipe characters and collapse newlines for Markdown table cells."""
    s = _enum_str(val, "")
    return s.replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


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
            sev = _enum_str(f.get("severity"), "info")
            title = _md_cell(f.get("title") or "Unknown")
            host = _md_cell(f.get("host", ""))
            cwe = _md_cell(f.get("cwe_id", ""))
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
        sev = _enum_str(f.get("severity"), "info")
        w(f"### {i}. {f.get('title', 'Unknown')}")
        w("")
        w(f"**Severity:** {_severity_badge(sev)}  ")
        w(f"**Host:** {f.get('host', 'N/A')}  ")
        if f.get("port") is not None:
            w(f"**Port:** {f['port']}  ")
        if f.get("cwe_id"):
            w(f"**CWE:** {f['cwe_id']}  ")
        if f.get("cve_ids"):
            cves = f["cve_ids"]
            if isinstance(cves, list):
                w(f"**CVEs:** {', '.join(cves)}  ")
        if f.get("cvss_score") is not None:
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
            impact = _enum_str(c.get("impact"), "unknown").upper()
            w(f"### Chain {i}: {c.get('name', 'Unnamed')}")
            w("")
            w(f"**Confidence:** {c.get('confidence', 0):.0%}  ")
            w(f"**Impact:** {impact}  ")
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
            port_val = "" if c.get("port") is None else c.get("port")
            w(
                f"| {_md_cell(c.get('host', ''))} | {_md_cell(port_val)} "
                f"| {_md_cell(c.get('service', ''))} | {_md_cell(c.get('username', ''))} "
                f"| {_md_cell(c.get('source', ''))} |"
            )
        w("")
        w("> **Note:** Passwords and hashes are redacted from this report for security.")
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
                tech = ", ".join(str(x) for x in tech[:5])
            w(
                f"| {_md_cell(t.get('host', ''))} | {_md_cell(t.get('ip', ''))} "
                f"| {_md_cell(t.get('is_live', ''))} | {_md_cell(t.get('os_guess', ''))} "
                f"| {_md_cell(tech)} | {_md_cell(t.get('waf_detected', ''))} |"
            )
        w("")
    else:
        w("No targets enumerated.")
        w("")

    # Prioritized Remediation Backlog
    plan = build_remediation_plan(data.findings, data.chains, top_n=10)
    if plan["top_items"]:
        w("## Prioritized Remediation Backlog")
        w("")
        w(
            f"- **Actionable Findings:** {plan['total_actionable']} | "
            f"**CISA KEV Flagged:** {plan['kev_flagged']} | "
            f"**Chain-Linked:** {plan['chain_linked']} | "
            f"**Avg Confidence:** {plan['average_confidence']}%"
        )
        w("")
        w("| Priority | Confidence | KEV | Severity | Finding | OWASP / CWE |")
        w("| :---: | :---: | :---: | :--- | :--- | :--- |")
        for item in plan["top_items"]:
            kev_flag = "YES" if item["is_kev"] else "-"
            cat = item["owasp_category"] or item["cwe_id"] or "-"
            w(
                f"| {item['priority_score']}/100 | {item['confidence_score']}% | {kev_flag} "
                f"| {_md_cell(str(item['severity']).upper())} | {_md_cell(item['title'])} | {_md_cell(cat)} |"
            )
        w("")

    # Footer
    w("---")
    w("")
    w("*Report generated by NEXUS — Network EXploration & Unified Security*  ")
    w(f"*{meta.date.strftime('%Y-%m-%d %H:%M UTC')}*")

    return "\n".join(lines)


def _severity_badge(severity: Any) -> str:
    """Return a markdown badge/emoji for severity."""
    sev = _enum_str(severity, "info").lower()
    badges = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🔵 LOW",
        "info": "⚪ INFO",
    }
    return badges.get(sev, sev.upper())

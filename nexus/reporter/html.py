"""HTML report renderer — self-contained single-file report."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from nexus.reporter.generator import ReportData


_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}


def render_html(data: ReportData) -> str:
    """Render a self-contained HTML penetration test report."""
    meta = data.meta

    findings_rows = ""
    for i, f in enumerate(data.findings, 1):
        sev = f.get("severity", "info")
        if hasattr(sev, "value"):
            sev = sev.value
        color = _SEVERITY_COLORS.get(sev, "#6b7280")
        cves = f.get("cve_ids", [])
        if isinstance(cves, list):
            cves = ", ".join(cves)
        findings_rows += f"""
        <tr>
            <td>{i}</td>
            <td><span class="sev-badge" style="background:{color}">{sev.upper()}</span></td>
            <td>{_esc(f.get('title', ''))}</td>
            <td>{_esc(f.get('host', ''))}</td>
            <td>{f.get('port', '')}</td>
            <td>{_esc(f.get('cwe_id', ''))}</td>
            <td>{_esc(str(cves))}</td>
        </tr>"""

    finding_details = ""
    for i, f in enumerate(data.findings, 1):
        sev = f.get("severity", "info")
        if hasattr(sev, "value"):
            sev = sev.value
        color = _SEVERITY_COLORS.get(sev, "#6b7280")
        evidence = f.get("evidence", "")
        remediation = f.get("remediation", "")

        finding_details += f"""
        <div class="finding-card">
            <h3>{i}. {_esc(f.get('title', ''))}</h3>
            <div class="finding-meta">
                <span class="sev-badge" style="background:{color}">{sev.upper()}</span>
                <span>Host: {_esc(f.get('host', ''))}</span>
                {f'<span>Port: {f["port"]}</span>' if f.get('port') else ''}
                {f'<span>CWE: {_esc(f.get("cwe_id", ""))}</span>' if f.get('cwe_id') else ''}
                {f'<span>CVSS: {f["cvss_score"]}</span>' if f.get('cvss_score') else ''}
                <span>Tool: {_esc(f.get('tool_source', ''))}</span>
            </div>
            <p>{_esc(f.get('description', ''))}</p>
            {f'<div class="evidence"><h4>Evidence</h4><pre>{_esc(evidence[:2000])}</pre></div>' if evidence else ''}
            {f'<div class="remediation"><h4>Remediation</h4><p>{_esc(remediation)}</p></div>' if remediation else ''}
        </div>"""

    chains_html = ""
    if data.chains:
        for i, c in enumerate(data.chains, 1):
            steps_html = ""
            for j, s in enumerate(c.get("steps", []), 1):
                steps_html += f"<li><strong>{_esc(s.get('action', ''))}</strong> (via {_esc(s.get('tool', ''))})</li>"
            chains_html += f"""
            <div class="chain-card">
                <h3>Chain {i}: {_esc(c.get('name', ''))}</h3>
                <p>Confidence: {c.get('confidence', 0):.0%} | Impact: {c.get('impact', 'unknown')}</p>
                <p>{_esc(c.get('description', ''))}</p>
                <ol>{steps_html}</ol>
            </div>"""
    else:
        chains_html = "<p>No attack chains identified.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(meta.title)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6;color:#1f2937;background:#f9fafb;max-width:1200px;margin:0 auto;padding:2rem}}
h1{{color:#111827;border-bottom:3px solid #dc2626;padding-bottom:0.5rem;margin-bottom:1rem}}
h2{{color:#1f2937;margin:2rem 0 1rem;padding-bottom:0.3rem;border-bottom:1px solid #e5e7eb}}
h3{{color:#374151;margin:1rem 0 0.5rem}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}
th,td{{padding:0.5rem 0.75rem;border:1px solid #d1d5db;text-align:left;font-size:0.9rem}}
th{{background:#f3f4f6;font-weight:600}}
tr:nth-child(even){{background:#f9fafb}}
.sev-badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:700}}
.meta-info{{background:#f3f4f6;padding:1rem;border-radius:8px;margin:1rem 0}}
.meta-info span{{display:inline-block;margin-right:2rem}}
.risk-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:0.5rem;margin:1rem 0}}
.risk-box{{text-align:center;padding:1rem;border-radius:8px;color:#fff;font-weight:700}}
.finding-card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:1.5rem;margin:1rem 0;box-shadow:0 1px 3px rgba(0,0,0,0.1)}}
.finding-meta{{display:flex;gap:1rem;flex-wrap:wrap;margin:0.5rem 0;font-size:0.85rem;color:#6b7280}}
.evidence{{background:#f3f4f6;padding:1rem;border-radius:4px;margin:1rem 0}}
.evidence pre{{white-space:pre-wrap;word-break:break-all;font-size:0.8rem;max-height:300px;overflow-y:auto}}
.remediation{{background:#ecfdf5;border-left:4px solid #10b981;padding:1rem;margin:1rem 0;border-radius:0 4px 4px 0}}
.chain-card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:1.5rem;margin:1rem 0}}
.chain-card ol{{margin:0.5rem 0 0 1.5rem}}
footer{{margin-top:3rem;padding-top:1rem;border-top:1px solid #e5e7eb;text-align:center;color:#9ca3af;font-size:0.85rem}}
</style>
</head>
<body>
<h1>{_esc(meta.title)}</h1>
<div class="meta-info">
    <span><strong>Author:</strong> {_esc(meta.author)}</span>
    <span><strong>Client:</strong> {_esc(meta.client or 'N/A')}</span>
    <span><strong>Date:</strong> {meta.date.strftime('%Y-%m-%d')}</span>
    <span><strong>Engagement:</strong> {_esc(meta.engagement_id)}</span>
</div>

<h2>Executive Summary</h2>
<p>{_esc(data.executive_summary)}</p>

<div class="risk-grid">
    <div class="risk-box" style="background:#dc2626">Critical<br>{meta.critical_count}</div>
    <div class="risk-box" style="background:#ea580c">High<br>{meta.high_count}</div>
    <div class="risk-box" style="background:#ca8a04">Medium<br>{meta.medium_count}</div>
    <div class="risk-box" style="background:#2563eb">Low<br>{meta.low_count}</div>
    <div class="risk-box" style="background:#6b7280">Info<br>{meta.info_count}</div>
</div>

<h2>Methodology</h2>
<p>{_esc(data.methodology).replace(chr(10), '<br>')}</p>

<h2>Findings Summary</h2>
<table>
<tr><th>#</th><th>Severity</th><th>Title</th><th>Host</th><th>Port</th><th>CWE</th><th>CVEs</th></tr>
{findings_rows}
</table>

<h2>Detailed Findings</h2>
{finding_details}

<h2>Attack Chains</h2>
{chains_html}

<footer>
    <p>Report generated by <strong>NEXUS</strong> — Network EXploration &amp; Unified Security</p>
    <p>{meta.date.strftime('%Y-%m-%d %H:%M UTC')}</p>
</footer>
</body>
</html>"""


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

"""DOCX report renderer — generates Word documents via python-docx.

python-docx is an optional dependency. If not installed, DOCX generation
is skipped with a warning.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from nexus.reporter.generator import strip_markdown

if TYPE_CHECKING:
    from nexus.reporter.generator import ReportData

log = logging.getLogger("nexus.reporter.docx")


def _enum_str(val: Any, default: str = "") -> str:
    if val is None:
        return default
    return str(val.value if hasattr(val, "value") else val)


def render_docx(data: ReportData, output_path: str) -> None:
    """Render the report as a DOCX document.

    Requires: pip install python-docx
    """
    try:
        from docx import Document  # type: ignore[import-untyped]
        from docx.enum.text import WD_ALIGN_PARAGRAPH  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "python-docx is required for DOCX reports. "
            "Install it with: pip install python-docx"
        )

    meta = data.meta
    doc = Document()

    # Title
    title = doc.add_heading(meta.title, level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Meta info
    meta_para = doc.add_paragraph()
    meta_para.add_run(f"Author: {meta.author}\n").bold = True
    meta_para.add_run(f"Client: {meta.client or 'N/A'}\n")
    meta_para.add_run(f"Date: {meta.date.strftime('%Y-%m-%d')}\n")
    meta_para.add_run(f"Engagement ID: {meta.engagement_id}\n")

    # Executive Summary
    doc.add_heading("Executive Summary", level=1)
    doc.add_paragraph(strip_markdown(data.executive_summary))

    # Severity Summary Table
    doc.add_heading("Risk Overview", level=2)
    table = doc.add_table(rows=1, cols=2)
    table.style = "Table Grid"
    hdr = table.rows[0].cells
    hdr[0].text = "Severity"
    hdr[1].text = "Count"

    for sev, count in [
        ("Critical", meta.critical_count),
        ("High", meta.high_count),
        ("Medium", meta.medium_count),
        ("Low", meta.low_count),
        ("Info", meta.info_count),
    ]:
        row = table.add_row().cells
        row[0].text = sev
        row[1].text = str(count)

    total_row = table.add_row().cells
    total_row[0].text = "Total"
    run = total_row[0].paragraphs[0].runs[0]
    run.bold = True
    total_row[1].text = str(meta.total_findings)

    # Methodology
    doc.add_heading("Methodology", level=1)
    doc.add_paragraph(strip_markdown(data.methodology))

    # Findings Summary
    doc.add_heading("Findings Summary", level=1)
    if data.findings:
        ftable = doc.add_table(rows=1, cols=5)
        ftable.style = "Table Grid"
        fhdr = ftable.rows[0].cells
        for j, h in enumerate(["#", "Severity", "Title", "Host", "CWE"]):
            fhdr[j].text = h

        for i, f in enumerate(data.findings, 1):
            sev = _enum_str(f.get("severity"), "info")
            row = ftable.add_row().cells
            row[0].text = str(i)
            row[1].text = sev.upper()
            row[2].text = str(f.get("title") or "")[:60]
            row[3].text = str(f.get("host") or "")
            row[4].text = str(f.get("cwe_id") or "")
    else:
        doc.add_paragraph("No findings to report.")

    # Detailed Findings
    doc.add_heading("Detailed Findings", level=1)
    for i, f in enumerate(data.findings, 1):
        sev = _enum_str(f.get("severity"), "info")
        doc.add_heading(f"{i}. {f.get('title', '')}", level=2)
        p = doc.add_paragraph()
        p.add_run(f"Severity: {sev.upper()}\n").bold = True
        p.add_run(f"Host: {f.get('host', '')}\n")
        if f.get("port") is not None:
            p.add_run(f"Port: {f['port']}\n")
        if f.get("cwe_id"):
            p.add_run(f"CWE: {f['cwe_id']}\n")
        if f.get("cvss_score") is not None:
            p.add_run(f"CVSS: {f['cvss_score']}\n")
        if f.get("tool_source"):
            p.add_run(f"Tool: {f['tool_source']}\n")

        doc.add_paragraph(str(f.get("description") or ""))

        if f.get("evidence"):
            doc.add_heading("Evidence", level=3)
            doc.add_paragraph(str(f["evidence"])[:2000])

        if f.get("remediation"):
            doc.add_heading("Remediation", level=3)
            doc.add_paragraph(strip_markdown(str(f["remediation"])))

    # Attack Chains
    doc.add_heading("Attack Chains", level=1)
    if data.chains:
        for i, c in enumerate(data.chains, 1):
            impact = _enum_str(c.get("impact"), "unknown").upper()
            doc.add_heading(f"Chain {i}: {c.get('name', '')}", level=2)
            doc.add_paragraph(f"Confidence: {c.get('confidence', 0):.0%} | Impact: {impact}")
            if c.get("description"):
                doc.add_paragraph(str(c["description"]))
            for j, s in enumerate(c.get("steps", []), 1):
                doc.add_paragraph(
                    f"{j}. {s.get('action', '')} (via {s.get('tool', '')})",
                    style="List Number",
                )
    else:
        doc.add_paragraph("No attack chains identified.")

    # Discovered Credentials (Redacted)
    doc.add_heading("Discovered Credentials", level=1)
    if data.credentials:
        ctable = doc.add_table(rows=1, cols=5)
        ctable.style = "Table Grid"
        chdr = ctable.rows[0].cells
        for j, h in enumerate(["Host", "Port", "Service", "Username", "Source"]):
            chdr[j].text = h
        for c in data.credentials:
            row = ctable.add_row().cells
            row[0].text = str(c.get("host") or "")
            row[1].text = "" if c.get("port") is None else str(c.get("port"))
            row[2].text = str(c.get("service") or "")
            row[3].text = str(c.get("username") or "")
            row[4].text = str(c.get("source") or "")
        doc.add_paragraph("Note: Passwords and hashes are redacted from this report for security.")
    else:
        doc.add_paragraph("No credentials discovered.")

    # Targets
    doc.add_heading("Targets", level=1)
    if data.targets:
        ttable = doc.add_table(rows=1, cols=6)
        ttable.style = "Table Grid"
        thdr = ttable.rows[0].cells
        for j, h in enumerate(["Host", "IP", "Live", "OS", "Tech Stack", "WAF"]):
            thdr[j].text = h
        for t in data.targets:
            tech = t.get("tech_stack", [])
            if isinstance(tech, list):
                tech = ", ".join(str(x) for x in tech[:5])
            row = ttable.add_row().cells
            row[0].text = str(t.get("host") or "")
            row[1].text = str(t.get("ip") or "")
            row[2].text = str(t.get("is_live", ""))
            row[3].text = str(t.get("os_guess") or "")
            row[4].text = str(tech)
            row[5].text = str(t.get("waf_detected") or "")
    else:
        doc.add_paragraph("No targets enumerated.")

    # Footer
    doc.add_paragraph("")
    footer = doc.add_paragraph()
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer.add_run("Report generated by NEXUS — Network EXploration & Unified Security")
    run.italic = True

    doc.save(output_path)
    log.info("DOCX report written to %s", output_path)

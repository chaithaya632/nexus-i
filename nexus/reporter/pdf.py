"""PDF report renderer — generates PDF via WeasyPrint from HTML.

WeasyPrint is an optional dependency. If not installed, PDF generation
is skipped with a warning.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nexus.reporter.generator import ReportData

log = logging.getLogger("nexus.reporter.pdf")


def render_pdf(data: ReportData, output_path: str) -> None:
    """Render the report as PDF using WeasyPrint.

    Generates an HTML report first, then converts it to PDF.
    Requires: pip install weasyprint
    """
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "WeasyPrint is required for PDF reports. Install it with: pip install weasyprint"
        )

    from nexus.reporter.html import render_html

    html_content = render_html(data)
    HTML(string=html_content).write_pdf(output_path)
    log.info("PDF report written to %s", output_path)

"""Result importer — parse output from external tools into NEXUS Findings.

Supports:
  - Nessus (.nessus XML)
  - Burp Suite (XML export)
  - Generic CSV (host, port, severity, title, description)
"""

from __future__ import annotations

import csv
import io
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from nexus.db.models import Finding, Severity
from nexus.recon.runner import safe_parse_xml

log = logging.getLogger("nexus.scanner.importer")

MAX_IMPORT_BYTES = 50 * 1024 * 1024  # 50 MiB guard against oversized import files

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "4": Severity.CRITICAL,
    "high": Severity.HIGH,
    "3": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "2": Severity.MEDIUM,
    "low": Severity.LOW,
    "1": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "0": Severity.INFO,
    "none": Severity.INFO,
}


def import_file(path: str | Path, *, max_bytes: int = MAX_IMPORT_BYTES) -> list[Finding]:
    """Auto-detect format and import findings from a file."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Import file not found: {p}")

    file_size = p.stat().st_size
    if file_size > max_bytes:
        raise ValueError(
            f"Import file size ({file_size} bytes) exceeds limit ({max_bytes} bytes): {p}"
        )

    content = p.read_text(encoding="utf-8", errors="replace")
    suffix = p.suffix.lower()

    if suffix == ".nessus" or ("<NessusClientData_v2" in content[:500]):
        return import_nessus(content)
    elif suffix == ".xml" and "<issues" in content[:500]:
        return import_burp_xml(content)
    elif suffix == ".csv":
        return import_csv(content)
    else:
        # Try XML first, then CSV
        if content.strip().startswith("<"):
            try:
                return import_nessus(content)
            except Exception:
                try:
                    return import_burp_xml(content)
                except Exception:
                    pass
        return import_csv(content)


def import_nessus(xml_content: str) -> list[Finding]:
    """Parse Nessus .nessus XML into Findings."""
    findings: list[Finding] = []
    if len(xml_content) > MAX_IMPORT_BYTES:
        log.error("Nessus XML content exceeds %d byte limit", MAX_IMPORT_BYTES)
        return findings
    try:
        root = safe_parse_xml(xml_content)
    except ET.ParseError as e:
        log.error("Failed to parse Nessus XML: %s", e)
        return findings

    for report_host in root.findall(".//ReportHost"):
        host = report_host.get("name", "")

        for item in report_host.findall("ReportItem"):
            port = int(item.get("port", "0"))
            protocol = item.get("protocol", "tcp")
            plugin_name = item.get("pluginName", "Unknown")
            sev_str = item.get("severity", "0")

            severity = _SEV_MAP.get(sev_str, Severity.INFO)
            description = _text(item, "description")
            solution = _text(item, "solution")
            cvss_str = _text(item, "cvss3_base_score") or _text(item, "cvss_base_score")
            cvss_score = float(cvss_str) if cvss_str else None

            cve_ids = [el.text for el in item.findall("cve") if el.text]
            cwe_el = item.find("cwe")
            cwe_id = f"CWE-{cwe_el.text}" if cwe_el is not None and cwe_el.text else ""

            findings.append(
                Finding(
                    host=host,
                    port=port if port else None,
                    protocol=protocol,
                    title=f"[Nessus] {plugin_name}",
                    description=description[:2000],
                    severity=severity,
                    cvss_score=cvss_score,
                    cve_ids=cve_ids,
                    cwe_id=cwe_id,
                    tool_source="nessus",
                    remediation=solution[:1000] if solution else "",
                    evidence=_text(item, "plugin_output")[:2000],
                )
            )

    log.info("Imported %d findings from Nessus", len(findings))
    return findings


def import_burp_xml(xml_content: str) -> list[Finding]:
    """Parse Burp Suite XML export into Findings."""
    findings: list[Finding] = []
    if len(xml_content) > MAX_IMPORT_BYTES:
        log.error("Burp XML content exceeds %d byte limit", MAX_IMPORT_BYTES)
        return findings
    try:
        root = safe_parse_xml(xml_content)
    except ET.ParseError as e:
        log.error("Failed to parse Burp XML: %s", e)
        return findings

    for issue in root.findall(".//issue"):
        host_el = issue.find("host")
        host = host_el.text if host_el is not None and host_el.text else ""
        if host_el is not None:
            host = host_el.get("ip", host) if not host else host

        path_el = issue.find("path")
        path = path_el.text if path_el is not None else ""

        sev_el = issue.find("severity")
        sev_str = sev_el.text.lower() if sev_el is not None and sev_el.text else "info"
        severity = _SEV_MAP.get(sev_str, Severity.INFO)

        name_el = issue.find("name")
        name = name_el.text if name_el is not None and name_el.text else "Unknown"

        desc_el = issue.find("issueDetail")
        if desc_el is None:
            desc_el = issue.find("issueBackground")
        desc = desc_el.text if desc_el is not None and desc_el.text else ""

        rem_el = issue.find("remediationDetail")
        if rem_el is None:
            rem_el = issue.find("remediationBackground")
        rem = rem_el.text if rem_el is not None and rem_el.text else ""

        findings.append(
            Finding(
                host=host,
                protocol="http",
                title=f"[Burp] {name}",
                description=desc[:2000],
                severity=severity,
                tool_source="burp",
                remediation=rem[:1000],
                evidence=f"Path: {path}",
            )
        )

    log.info("Imported %d findings from Burp XML", len(findings))
    return findings


def import_csv(csv_content: str) -> list[Finding]:
    """Import findings from CSV with headers: host,port,severity,title,description."""
    findings: list[Finding] = []
    reader = csv.DictReader(io.StringIO(csv_content))

    for row in reader:
        host = row.get("host", row.get("ip", row.get("target", "")))
        port_str = row.get("port", "")
        port = int(port_str) if port_str and port_str.isdigit() else None

        sev_str = row.get("severity", "info").lower().strip()
        severity = _SEV_MAP.get(sev_str, Severity.INFO)

        title = row.get("title", row.get("name", row.get("vulnerability", "Imported finding")))
        desc = row.get("description", row.get("details", ""))

        findings.append(
            Finding(
                host=host,
                port=port,
                title=title,
                description=desc[:2000],
                severity=severity,
                tool_source="csv_import",
            )
        )

    log.info("Imported %d findings from CSV", len(findings))
    return findings


def _text(el: ET.Element, tag: str) -> str:
    child = el.find(tag)
    return child.text if child is not None and child.text else ""

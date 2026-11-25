"""Nuclei vulnerability scanner wrapper — parses JSONL output into Findings."""

from __future__ import annotations

import json
import logging

from nexus.db.models import Finding, Severity
from nexus.recon.runner import (
    ToolRunner,
    validate_cli_target,
    validate_extra_args,
    validate_headers,
)

log = logging.getLogger("nexus.scanner.nuclei")

# Map nuclei severity strings to NEXUS Severity enum
_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

# Stealth-aware concurrency and rate limits
_STEALTH_SETTINGS: dict[str, dict[str, int]] = {
    "loud": {"concurrency": 50, "rate_limit": 300, "bulk_size": 50},
    "normal": {"concurrency": 25, "rate_limit": 150, "bulk_size": 25},
    "quiet": {"concurrency": 10, "rate_limit": 50, "bulk_size": 10},
    "ghost": {"concurrency": 3, "rate_limit": 10, "bulk_size": 5},
}


async def nuclei_scan(
    targets: list[str],
    *,
    templates: list[str] | None = None,
    severity_filter: list[str] | None = None,
    stealth: str = "normal",
    headers: dict[str, str] | None = None,
    timeout: int = 900,
    extra_args: list[str] | None = None,
) -> list[Finding]:
    """Run nuclei against targets and return Findings.

    Args:
        targets: list of URLs or hosts to scan.
        templates: specific template dirs/files. None = all default templates.
        severity_filter: e.g. ["critical", "high", "medium"].
        stealth: stealth level for rate limiting.
        headers: optional custom HTTP headers (e.g. cookies, bearer tokens).
        timeout: max seconds for the entire scan.
        extra_args: additional nuclei CLI flags.
    """
    if not targets:
        return []

    clean_targets = [validate_cli_target(t, label="target") for t in targets]
    clean_headers = validate_headers(headers)
    safe_extra = validate_extra_args(extra_args)

    stdin_data = "\n".join(clean_targets)
    settings = _STEALTH_SETTINGS.get(stealth, _STEALTH_SETTINGS["normal"])

    args = [
        "-jsonl",
        "-silent",
        "-concurrency",
        str(settings["concurrency"]),
        "-rate-limit",
        str(settings["rate_limit"]),
        "-bulk-size",
        str(settings["bulk_size"]),
    ]

    if templates:
        for t in templates:
            args.extend(["-t", validate_cli_target(t, label="template", allow_spaces=True)])

    if severity_filter:
        clean_sevs = [validate_cli_target(s, label="severity") for s in severity_filter]
        args.extend(["-severity", ",".join(clean_sevs)])

    if clean_headers:
        for k, v in clean_headers.items():
            args.extend(["-H", f"{k}: {v}"])

    if safe_extra:
        args.extend(safe_extra)

    out = await ToolRunner.run("nuclei", args, timeout=timeout, stdin_data=stdin_data)

    findings: list[Finding] = []
    for line in out.lines:
        finding = _parse_nuclei_line(line)
        if finding:
            findings.append(finding)

    log.info("nuclei scan complete: %d findings from %d targets", len(findings), len(targets))
    return findings


def _parse_nuclei_line(line: str) -> Finding | None:
    """Parse a single nuclei JSONL record into a Finding."""
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None

    info = rec.get("info", {})
    severity_str = info.get("severity", "info").lower()
    severity = _SEV_MAP.get(severity_str, Severity.INFO)

    # Extract CVE IDs from classification
    classification = info.get("classification", {})
    cve_ids = classification.get("cve-id") or []
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]

    cwe_list = classification.get("cwe-id") or []
    if isinstance(cwe_list, str):
        cwe_list = [cwe_list]
    cwe_id = cwe_list[0] if cwe_list else ""
    # Normalize CWE-ID format: "CWE-79" or "79" → "CWE-79"
    if cwe_id and not cwe_id.upper().startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"

    # CVSS
    cvss = classification.get("cvss-score")
    cvss_score = float(cvss) if cvss else None

    # Build evidence from request/response
    request = rec.get("request", "")
    response = rec.get("response", "")
    matched_at = rec.get("matched-at", "")
    curl_command = rec.get("curl-command", "")

    evidence_parts = []
    if matched_at:
        evidence_parts.append(f"Matched at: {matched_at}")
    if curl_command:
        evidence_parts.append(f"Curl: {curl_command}")

    raw_port = rec.get("port")
    parsed_port: int | None = None
    if isinstance(raw_port, int):
        parsed_port = raw_port or None
    elif isinstance(raw_port, str) and raw_port.strip().isdigit():
        parsed_port = int(raw_port.strip()) or None

    return Finding(
        host=rec.get("host", ""),
        port=parsed_port,
        protocol=rec.get("type", "http"),
        title=f"[{rec.get('template-id', 'unknown')}] {info.get('name', 'Unknown')}",
        description=info.get("description", "") or info.get("name", ""),
        severity=severity,
        cvss_score=cvss_score,
        cve_ids=cve_ids,
        cwe_id=cwe_id,
        tool_source="nuclei",
        evidence="\n".join(evidence_parts),
        request=request[:2000] if request else "",
        response=response[:2000] if response else "",
    )

"""WordPress passive/read-only enumerator wrapper (`wpscan`)."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner, validate_cli_target, validate_headers
from nexus.scanner._http import parse_url_target

log = logging.getLogger("nexus.scanner.cms_scan")


def _parse_wpscan_json(raw_json: str, target_url: str) -> list[Finding]:
    """Parse WPScan `--format json` output into NEXUS Findings."""
    findings: list[Finding] = []
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return findings
    if not isinstance(data, dict):
        return findings

    host, port, proto = parse_url_target(target_url)

    # WordPress core version + vulnerabilities / insecure status
    ver = data.get("version") or {}
    if isinstance(ver, dict) and ver.get("number"):
        ver_num = str(ver["number"])
        status = str(ver.get("status", "")).lower()
        vulns = ver.get("vulnerabilities") or []
        if vulns:
            for v in vulns:
                cves = [
                    f"CVE-{c}" if not str(c).upper().startswith("CVE-") else str(c)
                    for c in ((v.get("references") or {}).get("cve") or [])
                ]
                findings.append(
                    Finding(
                        host=host,
                        port=port,
                        protocol=proto,
                        title=f"WordPress {ver_num}: {v.get('title', 'Core Vulnerability')}",
                        description=f"WordPress core {ver_num} reported vulnerability in {v.get('title', '')}.",
                        severity=Severity.HIGH,
                        cve_ids=cves,
                        tool_source="wpscan",
                        evidence=f"Version: {ver_num} ({status})",
                    )
                )
        elif status in ("insecure", "outdated"):
            findings.append(
                Finding(
                    host=host,
                    port=port,
                    protocol=proto,
                    title=f"WordPress Core {status.title()}: {ver_num}",
                    description=f"WPScan identified WordPress core {ver_num} flagged as '{status}'.",
                    severity=Severity.MEDIUM if status == "insecure" else Severity.LOW,
                    cwe_id="CWE-1104",
                    tool_source="wpscan",
                    evidence=f"Version: {ver_num} ({status})",
                )
            )

    # Enumerated plugins & plugin vulnerabilities
    plugins = data.get("plugins") or {}
    if isinstance(plugins, dict):
        for slug, pinfo in plugins.items():
            if not isinstance(pinfo, dict):
                continue
            pver = (
                (pinfo.get("version") or {}).get("number")
                if isinstance(pinfo.get("version"), dict)
                else ""
            ) or "unknown"
            vulns = pinfo.get("vulnerabilities") or []
            for v in vulns:
                cves = [
                    f"CVE-{c}" if not str(c).upper().startswith("CVE-") else str(c)
                    for c in ((v.get("references") or {}).get("cve") or [])
                ]
                findings.append(
                    Finding(
                        host=host,
                        port=port,
                        protocol=proto,
                        title=f"WordPress Plugin ({slug} {pver}): {v.get('title', 'Vulnerability')}",
                        description=f"Plugin '{slug}' version {pver} matched known vulnerability.",
                        severity=Severity.HIGH if cves else Severity.MEDIUM,
                        cve_ids=cves,
                        tool_source="wpscan",
                        evidence=f"Plugin: {slug}\nVersion: {pver}",
                    )
                )
            if not vulns and pinfo.get("outdated"):
                findings.append(
                    Finding(
                        host=host,
                        port=port,
                        protocol=proto,
                        title=f"Outdated WordPress Plugin: {slug} ({pver})",
                        description=f"WordPress plugin '{slug}' ({pver}) is outdated.",
                        severity=Severity.LOW,
                        cwe_id="CWE-1104",
                        tool_source="wpscan",
                        evidence=f"Plugin: {slug} ({pver}), latest: {pinfo.get('latest_version', 'unknown')}",
                    )
                )
            elif not vulns:
                findings.append(
                    Finding(
                        host=host,
                        port=port,
                        protocol=proto,
                        title=f"WordPress Plugin Detected: {slug} ({pver})",
                        description=f"WPScan passively enumerated plugin '{slug}' (version: {pver}).",
                        severity=Severity.INFO,
                        tool_source="wpscan",
                        evidence=f"Plugin: {slug} ({pver}), latest: {pinfo.get('latest_version', 'unknown')}",
                    )
                )
            if pinfo.get("directory_listing"):
                findings.append(
                    Finding(
                        host=host,
                        port=port,
                        protocol=proto,
                        title=f"WordPress Plugin Directory Listing Enabled: {slug}",
                        description=f"Plugin directory for '{slug}' allows directory browsing.",
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-548",
                        tool_source="wpscan",
                        evidence=f"Location: {pinfo.get('location', target_url)}",
                    )
                )

    # Interesting findings (xmlrpc, debug.log, backups, etc.)
    for item in data.get("interesting_findings") or []:
        if not isinstance(item, dict):
            continue
        itype = str(item.get("type", "")).lower()
        if itype in ("headers", "robots_txt"):
            continue
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol=proto,
                title=f"WordPress Exposure: {item.get('to_s') or item.get('url') or itype}",
                description=f"WPScan identified interesting endpoint ({itype}) at {item.get('url', target_url)}.",
                severity=Severity.LOW,
                cwe_id="CWE-200",
                tool_source="wpscan",
                evidence=str(item.get("url") or item.get("to_s") or "")[:300],
            )
        )

    # Enumerated usernames (information disclosure)
    users = data.get("users") or {}
    if isinstance(users, dict) and users:
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol=proto,
                title=f"WordPress User Enumeration ({len(users)} account(s))",
                description=f"WPScan passively enumerated {len(users)} WordPress account username(s).",
                severity=Severity.INFO,
                cwe_id="CWE-200",
                tool_source="wpscan",
                evidence="Usernames: " + ", ".join(list(users.keys())[:10]),
            )
        )

    return findings


async def wpscan_audit(
    target_url: str,
    *,
    stealth: str = "normal",
    headers: dict[str, str] | None = None,
    api_token: str | None = None,
    timeout: int = 180,
) -> list[Finding]:
    """Run read-only WPScan enumeration against a detected WordPress URL."""
    clean_url = validate_cli_target(target_url, label="target_url")
    clean_headers = validate_headers(headers)

    if not ToolRunner.is_available("wpscan"):
        return []

    raw_token = (
        api_token
        or os.environ.get("NEXUS_WPSCAN_API_TOKEN")
        or os.environ.get("WPSCAN_API_TOKEN")
        or ""
    ).strip()
    token = validate_cli_target(raw_token, label="api_token") if raw_token else ""

    with tempfile.TemporaryDirectory(prefix="nexus_wp_") as td:
        json_path = Path(td) / "wpscan.json"
        enum_scope = "vp,u" if token else "p,u"
        args = [
            "--url",
            clean_url,
            "--format",
            "json",
            "-o",
            str(json_path),
            "--enumerate",
            enum_scope,
            "--no-banner",
            "--no-update",
            "--disable-tls-checks",
        ]
        if token:
            args.extend(["--api-token", token])
        else:
            log.info(
                "No WPSCAN_API_TOKEN configured; using '--enumerate p,u' (plugins/users without WPVulnDB CVE lookup)"
            )

        if stealth in ("quiet", "ghost"):
            args.extend(["--stealthy", "--throttle", "500" if stealth == "quiet" else "1500"])
        else:
            args.extend(["--detection-mode", "passive"])

        if clean_headers:
            cookie = clean_headers.get("Cookie") or clean_headers.get("cookie")
            if cookie:
                args.extend(["--cookie-string", cookie])

        await ToolRunner.run("wpscan", args, timeout=timeout)
        if json_path.is_file():
            raw = json_path.read_text(encoding="utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {}
            aborted = parsed.get("scan_aborted") if isinstance(parsed, dict) else None
            if isinstance(aborted, str) and "database" in aborted.lower() and "--no-update" in args:
                # Fresh install without cached DB: retry once allowing WPScan DB initialization
                retry_args = [a for a in args if a != "--no-update"]
                await ToolRunner.run("wpscan", retry_args, timeout=timeout)
                if json_path.is_file():
                    raw = json_path.read_text(encoding="utf-8", errors="replace")
                    try:
                        parsed = json.loads(raw)
                    except json.JSONDecodeError:
                        parsed = {}
                    aborted = parsed.get("scan_aborted") if isinstance(parsed, dict) else None
            if aborted:
                log.warning("WPScan aborted for %s: %s", target_url, aborted)
                return []
            findings = _parse_wpscan_json(raw, target_url)
            log.info("WPScan found %d findings on %s", len(findings), target_url)
            return findings
    return []

"""OWASP ZAP Automation Framework wrapper — builds scoped YAML plans and parses JSON reports."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from nexus.core.scope import ScopeEnforcer
from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner, validate_cli_target
from nexus.scanner._http import parse_url_target

log = logging.getLogger("nexus.scanner.zap")

_ZAP_RISK_MAP: dict[str, Severity] = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


def build_zap_automation_plan(
    target_url: str,
    report_dir: str | Path,
    *,
    report_file: str = "zap_report.json",
    include_regexes: list[str] | None = None,
    exclude_regexes: list[str] | None = None,
    max_crawl_minutes: int = 5,
    active_scan: bool = False,
) -> dict[str, Any]:
    """Generate a scoped OWASP ZAP Automation Framework YAML dictionary."""
    clean_url = validate_cli_target(target_url, label="target_url")
    parsed = urlparse(clean_url)
    origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else clean_url
    includes = list(include_regexes or [f"^{re.escape(origin)}.*"])
    excludes = list(exclude_regexes or [])

    jobs: list[dict[str, Any]] = [
        {"type": "passiveScan-config", "parameters": {"maxAlertsPerRule": 10}},
        {
            "type": "spider",
            "parameters": {
                "context": "nexus-scope",
                "url": clean_url,
                "maxDuration": max(1, int(max_crawl_minutes)),
            },
        },
        {"type": "passiveScan-wait", "parameters": {"maxDuration": 5}},
    ]
    if active_scan:
        jobs.append(
            {
                "type": "activeScan",
                "parameters": {
                    "context": "nexus-scope",
                    "policy": "Default Policy",
                    "maxScanDurationInMins": max(1, int(max_crawl_minutes)),
                },
            }
        )
    jobs.append(
        {
            "type": "report",
            "parameters": {
                "template": "traditional-json",
                "reportDir": str(report_dir),
                "reportFile": report_file,
                "reportTitle": "NEXUS ZAP Scan",
            },
        }
    )

    return {
        "env": {
            "contexts": [
                {
                    "name": "nexus-scope",
                    "urls": [origin],
                    "includePaths": includes,
                    "excludePaths": excludes,
                }
            ],
            "parameters": {"failOnError": False, "progressToStdout": False},
        },
        "jobs": jobs,
    }


def parse_zap_json_report(raw_json: str, default_target: str = "") -> list[Finding]:
    """Parse OWASP ZAP traditional-json report output into Finding models."""
    import json

    if not raw_json or not raw_json.strip():
        return []
    try:
        payload = json.loads(raw_json)
    except ValueError as exc:
        log.warning("Failed to parse ZAP JSON report: %s", exc)
        return []

    findings: list[Finding] = []
    sites = payload.get("site") if isinstance(payload, dict) else []
    if isinstance(sites, dict):
        sites = [sites]
    if not isinstance(sites, list):
        return findings

    for site in sites:
        if not isinstance(site, dict):
            continue
        site_name = str(site.get("@name") or default_target or "")
        host, port, proto = parse_url_target(site_name) if site_name else ("", None, "http")
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            title = str(alert.get("name") or alert.get("alert") or "ZAP Alert").strip()
            risk_code = str(alert.get("riskcode") or "").strip().lower()
            risk_desc = (
                str(alert.get("riskdesc") or "").split()[0].lower() if alert.get("riskdesc") else ""
            )
            sev = _ZAP_RISK_MAP.get(risk_code) or _ZAP_RISK_MAP.get(risk_desc, Severity.INFO)

            cwe_raw = str(alert.get("cweid") or "").strip()
            cwe_id = f"CWE-{cwe_raw}" if cwe_raw.isdigit() and int(cwe_raw) > 0 else ""

            instances = alert.get("instances") or []
            sample_uri = ""
            if isinstance(instances, list) and instances and isinstance(instances[0], dict):
                sample_uri = str(instances[0].get("uri") or "")

            confidence_txt = str(alert.get("confidence") or "").lower()
            confirmed = confidence_txt in ("3", "high", "confirmed")

            ev_lines = [f"Site: {site_name}"]
            if sample_uri:
                ev_lines.append(f"URI: {sample_uri}")
            if alert.get("count"):
                ev_lines.append(f"Instances: {alert['count']}")

            findings.append(
                Finding(
                    host=host or default_target,
                    port=port,
                    protocol=proto,
                    title=title,
                    description=re.sub(r"<[^>]+>", "", str(alert.get("desc") or "")).strip()[:1500],
                    severity=sev,
                    cwe_id=cwe_id,
                    remediation=re.sub(r"<[^>]+>", "", str(alert.get("solution") or "")).strip()[
                        :1000
                    ],
                    tool_source="owasp_zap",
                    evidence="\n".join(ev_lines),
                    confirmed=confirmed,
                )
            )
    return findings


async def zap_scan(
    target_url: str,
    *,
    zap_path: str = "zap.sh",
    scope: ScopeEnforcer | None = None,
    active_scan: bool = False,
    max_crawl_minutes: int = 5,
    timeout: int = 300,
) -> list[Finding]:
    """Run OWASP ZAP Automation Framework in headless `-cmd -autorun` mode when available."""
    clean_url = validate_cli_target(target_url, label="target_url")
    host, port, _ = parse_url_target(clean_url)
    if scope is not None:
        scope.enforce(host, port)

    exe = (
        zap_path
        if ToolRunner.is_available(zap_path)
        else ("zaproxy" if ToolRunner.is_available("zaproxy") else "")
    )
    if not exe:
        log.warning(
            "OWASP ZAP (%s / zaproxy) not found — skipping ZAP scan for %s", zap_path, clean_url
        )
        return []

    plan_path = Path(ToolRunner.make_temp_path(".yaml"))
    out_dir = plan_path.parent
    report_name = f"zap_{plan_path.stem}.json"
    report_path = out_dir / report_name
    excludes = [
        f".*{re.escape(ex)}.*" for ex in (scope._scope.excluded_targets if scope else []) if ex
    ]

    plan = build_zap_automation_plan(
        clean_url,
        out_dir,
        report_file=report_name,
        exclude_regexes=excludes,
        max_crawl_minutes=max_crawl_minutes,
        active_scan=active_scan,
    )
    plan_path.write_text(yaml.safe_dump(plan, sort_keys=False), encoding="utf-8")

    try:
        out = await ToolRunner.run(exe, ["-cmd", "-autorun", str(plan_path)], timeout=timeout)
        if not out.ok:
            log.warning("ZAP autorun exited rc=%d: %s", out.returncode, out.stderr[:250])
        if report_path.is_file():
            raw = report_path.read_text(encoding="utf-8", errors="replace")
            return parse_zap_json_report(raw, default_target=host)
        return []
    finally:
        for p in (plan_path, report_path):
            try:
                if p.exists():
                    os.unlink(p)
            except OSError:
                pass

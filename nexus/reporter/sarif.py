"""SARIF v2.1.0 report renderer for GitHub/GitLab Code Scanning & CI/CD gates."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, TYPE_CHECKING

from nexus import __version__

if TYPE_CHECKING:
    from nexus.reporter.generator import ReportData

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_DEFAULT_SCORE: dict[str, str] = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}

_NON_ALNUM = re.compile(r"[^A-Za-z0-9_.-]+")


def _sev_str(sev: Any) -> str:
    return sev.value if hasattr(sev, "value") else str(sev or "info").lower()


def _rule_id_for(f: dict[str, Any]) -> str:
    cves = f.get("cve_ids") or []
    if cves:
        return str(cves[0]).upper()
    cwe = str(f.get("cwe_id") or "").strip().upper()
    tool = _NON_ALNUM.sub("-", str(f.get("tool_source") or "nexus").lower()).strip("-") or "nexus"
    if cwe:
        return f"NEXUS-{tool}-{cwe}"
    slug = hashlib.sha1(str(f.get("title", "finding")).encode("utf-8")).hexdigest()[:8].upper()
    return f"NEXUS-{tool}-{slug}"


def _artifact_uri(f: dict[str, Any]) -> str:
    host = str(f.get("host") or "target").strip()
    port = f.get("port")
    proto = str(f.get("protocol") or "").strip().lower()
    if proto in ("http", "https") and host:
        default_p = 443 if proto == "https" else 80
        suffix = f"-{port}" if port and port != default_p else ""
        return f"{proto}/{host}{suffix}"
    return f"{host}/{port}" if port else host


def render_sarif(data: ReportData, *, include_suppressed: bool = True) -> str:
    """Render engagement findings as OASIS SARIF v2.1.0 JSON."""
    raw_findings = data.findings
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in raw_findings:
        suppressed = bool(f.get("false_positive", False))
        if suppressed and not include_suppressed:
            continue

        sev = _sev_str(f.get("severity"))
        rule_id = _rule_id_for(f)
        title = str(f.get("title") or rule_id)
        desc = str(f.get("description") or title)
        remediation = str(f.get("remediation") or "Review finding details and apply vendor hardening/patches.")
        cvss = f.get("cvss_score")
        sec_score = f"{float(cvss):.1f}" if cvss is not None else _DEFAULT_SCORE.get(sev, "1.0")

        if rule_id not in rules_by_id:
            tags = ["security"]
            if f.get("cwe_id"):
                tags.append(str(f["cwe_id"]))
            if f.get("owasp_category"):
                tags.append(str(f["owasp_category"]))
            for cve in f.get("cve_ids") or []:
                tags.append(str(cve))
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": title[:160]},
                "fullDescription": {"text": desc[:1000]},
                "help": {"text": remediation[:2000]},
                "properties": {
                    "tags": list(dict.fromkeys(tags)),
                    "security-severity": sec_score,
                },
            }

        host = str(f.get("host") or "target")
        port = f.get("port")
        evidence = str(f.get("evidence") or "")
        msg_parts = [title]
        if desc and desc != title:
            msg_parts.append(desc[:400])
        if evidence:
            msg_parts.append(f"Evidence: {evidence[:400]}")

        fp_src = f"{host}|{port or 0}|{rule_id}|{title.strip().lower()}"
        fp_hash = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()[:32]

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": "\n".join(msg_parts)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _artifact_uri(f)},
                    },
                    "logicalLocations": [
                        {
                            "name": f"{host}:{port}" if port else host,
                            "kind": "endpoint",
                        }
                    ],
                }
            ],
            "partialFingerprints": {"primaryLocationLineHash": fp_hash},
        }
        if suppressed:
            result["suppressions"] = [
                {
                    "kind": "inSource",
                    "justification": "Suppressed via .nexusignore baseline rule",
                }
            ]
        results.append(result)

    sarif_doc = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "NEXUS",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/nexus-security/nexus",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)

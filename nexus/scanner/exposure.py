"""Signature-verified web artifact exposure auditor (avoids SPA catch-all false positives)."""

from __future__ import annotations

import json
import logging
import re
from typing import Callable

from nexus.db.models import Finding, Severity
from nexus.scanner._http import make_http_client, parse_url_target

log = logging.getLogger("nexus.scanner.exposure")

_ENV_LINE_RE = re.compile(r"^(?:[A-Z][A-Z0-9_]{2,32})=.*$", re.MULTILINE)


def _looks_like_html(body: str, content_type: str) -> bool:
    ct = content_type.lower()
    head = body.lstrip()[:200].lower()
    return "text/html" in ct or head.startswith(("<!doctype html", "<html", "<!--"))


def _verify_git_head(body: str, ct: str) -> str | None:
    if _looks_like_html(body, ct):
        return None
    if "ref: refs/" in body:
        return body.strip()[:200]
    return None


def _verify_dotenv(body: str, ct: str) -> str | None:
    if _looks_like_html(body, ct):
        return None
    matches = _ENV_LINE_RE.findall(body)
    if len(matches) >= 2:
        # Mask values so plaintext credentials are never stored in Finding evidence
        keys_only = [m.split("=", 1)[0] + "=***" for m in matches[:8]]
        return "Exposed env keys: " + ", ".join(keys_only)
    return None


def _verify_actuator_env(body: str, ct: str) -> str | None:
    if _looks_like_html(body, ct):
        return None
    if '"propertySources"' in body:
        # Mask property values so embedded credentials/secrets in Spring Actuator env never leak
        try:
            data = json.loads(body)
        except Exception:
            data = None
        if isinstance(data, dict) and isinstance(data.get("propertySources"), list):
            names = [
                str(ps.get("name", ""))
                for ps in data["propertySources"][:10]
                if isinstance(ps, dict) and ps.get("name")
            ]
            return "Exposed propertySources: " + (", ".join(names) or "present")
        return "Exposed Spring Actuator propertySources (values masked)"
    return None


def _verify_actuator_health(body: str, ct: str) -> str | None:
    if _looks_like_html(body, ct):
        return None
    if '"status"' in body and ("UP" in body or "DOWN" in body):
        return body.strip()[:200]
    return None


def _verify_metrics(body: str, ct: str) -> str | None:
    if _looks_like_html(body, ct):
        return None
    if "# HELP " in body and "# TYPE " in body:
        return "\n".join(body.splitlines()[:6])
    return None


def _verify_apache_status(body: str, _ct: str) -> str | None:
    low = body.lower()
    if "apache server status" in low and "server version:" in low and "requests currently being processed" in low:
        return "\n".join(line.strip() for line in body.splitlines() if "server version:" in line.lower())[:200] or "Apache server-status confirmed"
    return None


def _verify_phpinfo(body: str, _ct: str) -> str | None:
    low = body.lower()
    if "php version" in low and ("php license" in low or "configuration file (php.ini) path" in low):
        return "PHPInfo configuration disclosure confirmed"
    return None


# (path, title, severity, cwe_id, verifier_fn)
_EXPOSURE_PROBES: list[tuple[str, str, Severity, str, Callable[[str, str], str | None]]] = [
    ("/.git/HEAD", "Exposed Git Repository (/.git/HEAD)", Severity.HIGH, "CWE-538", _verify_git_head),
    ("/.env", "Exposed Environment File (/.env)", Severity.CRITICAL, "CWE-538", _verify_dotenv),
    ("/actuator/env", "Spring Boot Actuator Environment Exposed", Severity.HIGH, "CWE-200", _verify_actuator_env),
    ("/actuator/health", "Spring Boot Actuator Health Endpoint Exposed", Severity.LOW, "CWE-200", _verify_actuator_health),
    ("/metrics", "Prometheus Metrics Endpoint Exposed", Severity.LOW, "CWE-200", _verify_metrics),
    ("/server-status", "Apache mod_status Diagnostics Exposed", Severity.LOW, "CWE-200", _verify_apache_status),
    ("/phpinfo.php", "Exposed PHPInfo Diagnostic Page", Severity.MEDIUM, "CWE-200", _verify_phpinfo),
]


async def audit_exposed_artifacts(
    base_urls: list[str],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 6.0,
) -> list[Finding]:
    """Probe base URLs for exposed sensitive artifacts and confirm via response signatures."""
    if not base_urls:
        return []

    findings: list[Finding] = []
    seen_keys: set[tuple[str, int | None, str]] = set()
    roots = list(dict.fromkeys(u.rstrip("/") for u in base_urls))[:2]

    async with make_http_client(headers=headers, timeout=timeout) as client:
        for root in roots:
            host, port, proto = parse_url_target(root)
            for rel_path, title, sev, cwe_id, verifier in _EXPOSURE_PROBES:
                url = f"{root}{rel_path}"
                try:
                    resp = await client.get(url, follow_redirects=False)
                except Exception:
                    continue
                if resp.status_code != 200:
                    continue
                ctype = resp.headers.get("content-type", "")
                evidence = verifier(resp.text or "", ctype)
                if not evidence:
                    continue
                key = (host, port, title)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(Finding(
                    host=host,
                    port=port,
                    protocol=proto,
                    title=title,
                    description=(
                        f"Verified sensitive artifact exposure at {url} via content-signature inspection."
                    ),
                    severity=sev,
                    cwe_id=cwe_id,
                    tool_source="exposure_probe",
                    evidence=f"URL: {url}\n{evidence}",
                    confirmed=True,
                ))

    log.info("Exposure verification found %d confirmed artifact(s) across %d root(s)", len(findings), len(roots))
    return findings

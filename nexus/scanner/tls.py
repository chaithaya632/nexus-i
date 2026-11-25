"""TLS/SSL security configuration auditor — sslyze wrapper + Python ssl fallback."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner

log = logging.getLogger("nexus.scanner.tls")

_DEPRECATED_SSL_RESULTS = {
    "ssl_2_0_cipher_suites": ("SSLv2 Supported", Severity.CRITICAL),
    "ssl_3_0_cipher_suites": ("SSLv3 Supported (POODLE)", Severity.HIGH),
    "tls_1_0_cipher_suites": ("Deprecated TLS 1.0 Supported", Severity.MEDIUM),
    "tls_1_1_cipher_suites": ("Deprecated TLS 1.1 Supported", Severity.MEDIUM),
}


def _parse_sslyze_json(raw_json: str, host: str, port: int) -> list[Finding]:
    """Parse sslyze `--json_out` report into NEXUS Findings."""
    findings: list[Finding] = []
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return findings

    for srv in data.get("server_scan_results", []):
        scan_res = srv.get("scan_result") or {}

        # Deprecated protocols (SSLv2/v3, TLS 1.0/1.1)
        for key, (label, sev) in _DEPRECATED_SSL_RESULTS.items():
            suite_res = (scan_res.get(key) or {}).get("result") or {}
            accepted = suite_res.get("accepted_cipher_suites") or []
            if accepted:
                names = [c.get("cipher_suite", {}).get("name", "") for c in accepted[:5]]
                findings.append(Finding(
                    host=host,
                    port=port,
                    protocol="https",
                    title=f"TLS: {label}",
                    description=(
                        f"{host}:{port} accepts deprecated protocol {label} with "
                        f"{len(accepted)} cipher suite(s)."
                    ),
                    severity=sev,
                    cwe_id="CWE-326",
                    tool_source="sslyze",
                    evidence="Accepted suites: " + ", ".join(n for n in names if n),
                ))

        # Heartbleed
        hb = (scan_res.get("heartbleed") or {}).get("result") or {}
        if hb.get("is_vulnerable_to_heartbleed"):
            findings.append(Finding(
                host=host, port=port, protocol="https",
                title="TLS: OpenSSL Heartbleed (CVE-2014-0160)",
                description=f"{host}:{port} is vulnerable to Heartbleed memory disclosure.",
                severity=Severity.HIGH, cvss_score=7.5,
                cve_ids=["CVE-2014-0160"], cwe_id="CWE-126",
                tool_source="sslyze", confirmed=True,
            ))

        # Certificate expiration / trust issues
        certinfo = (scan_res.get("certificate_info") or {}).get("result") or {}
        for dep in certinfo.get("certificate_deployments", []):
            leaf = (dep.get("received_certificate_chain") or [{}])[0]
            not_after_str = leaf.get("not_valid_after")
            if not_after_str:
                try:
                    exp = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
                    days_left = (exp - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        findings.append(Finding(
                            host=host, port=port, protocol="https",
                            title="TLS: Expired SSL/TLS Certificate",
                            description=f"Certificate on {host}:{port} expired {abs(days_left)} day(s) ago.",
                            severity=Severity.HIGH, cwe_id="CWE-295",
                            tool_source="sslyze", evidence=f"Expired: {not_after_str}",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            host=host, port=port, protocol="https",
                            title="TLS: Certificate Expiring Soon",
                            description=f"Certificate on {host}:{port} expires in {days_left} day(s).",
                            severity=Severity.LOW, cwe_id="CWE-295",
                            tool_source="sslyze", evidence=f"Expires: {not_after_str}",
                        ))
                except ValueError:
                    pass

            for path_val in dep.get("path_validation_results", []):
                if path_val.get("was_validation_successful") is False:
                    err = path_val.get("validation_error") or "Untrusted certificate chain"
                    findings.append(Finding(
                        host=host, port=port, protocol="https",
                        title="TLS: Untrusted / Invalid Certificate Chain",
                        description=f"Certificate validation failed on {host}:{port}: {err}",
                        severity=Severity.MEDIUM, cwe_id="CWE-295",
                        tool_source="sslyze", evidence=f"TrustStore: {path_val.get('trust_store', {}).get('name', 'default')}",
                    ))
                    break

    return findings


def _stdlib_tls_probe(host: str, port: int, timeout: float = 8.0) -> list[Finding]:
    """Pure-Python TLS certificate and hostname check fallback (zero binary deps)."""
    findings: list[Finding] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                ver = ssock.version() or ""
                if ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(Finding(
                        host=host, port=port, protocol="https",
                        title=f"TLS: Deprecated Protocol Negotiated ({ver})",
                        description=f"{host}:{port} negotiated weak protocol {ver}.",
                        severity=Severity.MEDIUM, cwe_id="CWE-326",
                        tool_source="tls_probe", evidence=f"Negotiated: {ver}",
                    ))
                not_after = cert.get("notAfter")
                if not_after:
                    ts = ssl.cert_time_to_seconds(not_after)
                    days_left = int((ts - datetime.now(timezone.utc).timestamp()) // 86400)
                    if days_left < 30:
                        findings.append(Finding(
                            host=host, port=port, protocol="https",
                            title="TLS: Certificate Expiring Soon" if days_left >= 0 else "TLS: Expired Certificate",
                            description=f"Certificate on {host}:{port} notAfter={not_after}.",
                            severity=Severity.HIGH if days_left < 0 else Severity.LOW,
                            cwe_id="CWE-295", tool_source="tls_probe",
                            evidence=f"notAfter: {not_after}",
                        ))
    except ssl.SSLCertVerificationError as exc:
        findings.append(Finding(
            host=host, port=port, protocol="https",
            title="TLS: Certificate Verification Failed",
            description=f"TLS verification error on {host}:{port}: {exc}",
            severity=Severity.MEDIUM, cwe_id="CWE-295",
            tool_source="tls_probe", evidence=str(exc)[:500],
        ))
    except (OSError, ssl.SSLError) as exc:
        log.debug("TLS probe skipped/failed for %s:%d: %s", host, port, exc)
    return findings


async def audit_tls(
    host: str,
    port: int = 443,
    *,
    timeout: int = 120,
) -> list[Finding]:
    """Audit TLS/SSL configuration using sslyze (if present) or Python stdlib fallback."""
    if ToolRunner.is_available("sslyze"):
        with tempfile.TemporaryDirectory(prefix="nexus_tls_") as td:
            json_path = Path(td) / "sslyze.json"
            args = [
                "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
                "--certinfo", "--heartbleed", "--quiet",
                "--json_out", str(json_path),
                f"{host}:{port}",
            ]
            out = await ToolRunner.run("sslyze", args, timeout=timeout)
            if json_path.is_file():
                raw = json_path.read_text(encoding="utf-8", errors="replace")
                findings = _parse_sslyze_json(raw, host, port)
                log.info("sslyze found %d TLS issues on %s:%d", len(findings), host, port)
                return findings
            log.debug("sslyze produced no JSON output (rc=%d), falling back to stdlib", out.returncode)

    return await asyncio.to_thread(_stdlib_tls_probe, host, port)

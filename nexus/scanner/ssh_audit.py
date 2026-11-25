"""SSH configuration auditor — ssh-audit JSON wrapper + nmap ssh2-enum-algos fallback."""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner, safe_parse_xml, validate_cli_target, validate_port

log = logging.getLogger("nexus.scanner.ssh_audit")

_WEAK_SSH_ALGOS = (
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "ssh-dss",
    "arcfour",
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "hmac-md5",
    "hmac-sha1",
)


def _parse_ssh_audit_json(raw_json: str, host: str, port: int) -> list[Finding]:
    """Parse `ssh-audit -j` output for weak algorithms and CVEs."""
    findings: list[Finding] = []
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return findings

    if not isinstance(data, dict):
        return findings

    banner = (data.get("banner") or {}).get("raw", "")
    weak_notes: list[str] = []
    for section in ("kex", "key", "enc", "mac"):
        for item in data.get(section, []) or []:
            if not isinstance(item, dict):
                continue
            notes = item.get("notes") or {}
            if notes.get("fail") or notes.get("warn"):
                algo = item.get("algorithm", "")
                if algo:
                    weak_notes.append(f"{section}:{algo}")

    if weak_notes:
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol="ssh",
                title=f"SSH: {len(weak_notes)} Weak/Deprecated Cryptographic Algorithms",
                description=f"SSH service on {host}:{port} supports weak KEX, cipher, key, or MAC algorithms.",
                severity=Severity.MEDIUM,
                cwe_id="CWE-326",
                tool_source="ssh-audit",
                evidence=(f"Banner: {banner}\n" if banner else "")
                + "Weak: "
                + ", ".join(weak_notes[:20]),
            )
        )

    for cve in data.get("cves", []) or []:
        if not isinstance(cve, dict):
            continue
        cve_name = cve.get("name", "")
        cvss = float(cve.get("cvssv2", 0.0) or 0.0)
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol="ssh",
                title=f"SSH: {cve_name} — {cve.get('description', '')[:60]}",
                description=cve.get("description", ""),
                severity=Severity.HIGH if cvss >= 7.0 else Severity.MEDIUM,
                cvss_score=cvss or None,
                cve_ids=[cve_name] if cve_name else [],
                cwe_id="CWE-326",
                tool_source="ssh-audit",
            )
        )

    return findings


def _parse_nmap_ssh_xml(xml_text: str, host: str, port: int) -> list[Finding]:
    """Parse nmap `ssh2-enum-algos` and `ssh-auth-methods` XML script output."""
    findings: list[Finding] = []
    try:
        root = safe_parse_xml(xml_text)
    except ET.ParseError:
        return findings

    weak_found: list[str] = []
    auth_methods: list[str] = []
    for script in root.findall(".//script"):
        sid = script.get("id", "")
        out_text = script.get("output", "")
        if sid == "ssh2-enum-algos":
            lower = out_text.lower()
            for algo in _WEAK_SSH_ALGOS:
                if algo in lower:
                    weak_found.append(algo)
        elif sid == "ssh-auth-methods":
            if "password" in out_text.lower():
                auth_methods.append("password")

    if weak_found:
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol="ssh",
                title=f"SSH: Weak Cryptographic Algorithms ({len(weak_found)})",
                description=f"SSH service on {host}:{port} offers deprecated algorithms: {', '.join(weak_found)}.",
                severity=Severity.MEDIUM,
                cwe_id="CWE-326",
                tool_source="nmap_ssh",
                evidence="\n".join(weak_found),
            )
        )

    if "password" in auth_methods:
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol="ssh",
                title="SSH: Password Authentication Enabled",
                description=f"SSH on {host}:{port} permits password authentication instead of key-only auth.",
                severity=Severity.LOW,
                cwe_id="CWE-287",
                tool_source="nmap_ssh",
                evidence="Supported auth method: password",
            )
        )

    return findings


async def audit_ssh(
    host: str,
    port: int = 22,
    *,
    timeout: int = 60,
) -> list[Finding]:
    """Audit SSH configuration via `ssh-audit -j` or `nmap` SSH NSE scripts."""
    clean_host = validate_cli_target(host, label="host")
    port_num = validate_port(port)
    if ToolRunner.is_available("ssh-audit"):
        out = await ToolRunner.run(
            "ssh-audit", ["-j", "-p", str(port_num), clean_host], timeout=timeout
        )
        if out.stdout.strip():
            findings = _parse_ssh_audit_json(out.stdout, clean_host, port_num)
            log.info("ssh-audit found %d issues on %s:%d", len(findings), clean_host, port_num)
            return findings

    if ToolRunner.is_available("nmap"):
        xml_path = ToolRunner.make_temp_path(".xml")
        try:
            args = [
                "-p",
                str(port_num),
                "--script",
                "ssh2-enum-algos,ssh-auth-methods",
                "-oX",
                xml_path,
                clean_host,
            ]
            await ToolRunner.run("nmap", args, timeout=timeout)
            p = Path(xml_path)
            if p.is_file():
                xml_text = p.read_text(encoding="utf-8", errors="replace")
                return _parse_nmap_ssh_xml(xml_text, clean_host, port_num)
        finally:
            Path(xml_path).unlink(missing_ok=True)

    return []

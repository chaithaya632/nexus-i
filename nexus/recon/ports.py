"""Nmap port-scanner wrapper — parses XML output into Port and Target models."""

from __future__ import annotations

import ipaddress
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from nexus.db.models import Finding, Port, Severity, Target
from nexus.recon.runner import (
    ToolRunner,
    safe_parse_xml,
    validate_cli_target,
    validate_extra_args,
)

log = logging.getLogger("nexus.recon.ports")

# Stealth-aware scan profiles keyed by stealth level.
SCAN_PROFILES: dict[str, list[str]] = {
    "loud": ["-sV", "-sC", "-O", "--version-all", "-T4"],
    "normal": ["-sV", "-sC", "-T3"],
    "quiet": ["-sV", "-T2", "--max-retries", "1"],
    "ghost": ["-sS", "-T1", "--max-retries", "1", "-Pn", "--data-length", "24"],
}

DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,"
    "2375,2379,3306,3389,5000,5432,5900,6379,8000,8080,8443,8500,"
    "8888,9000,9200,11211,27017"
)


def _extract_nmap_target(target: str) -> str:
    """Validate and extract a host/IP/CIDR suitable for nmap CLI invocation."""
    raw = validate_cli_target(target, label="target")
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass
    try:
        ipaddress.ip_network(raw, strict=False)
        return raw
    except ValueError:
        pass

    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").strip()
    elif raw.startswith("["):
        parsed = urlparse(f"http://{raw}")
        host = (parsed.hostname or "").strip()
    else:
        head = raw.split("/", 1)[0]
        if head.count(":") == 1:
            host = head.split(":", 1)[0]
        else:
            host = head
    return validate_cli_target(host, label="target")


async def nmap_scan(
    target: str,
    *,
    ports: str = DEFAULT_PORTS,
    stealth: str = "normal",
    timeout: int = 600,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Run nmap and return parsed results.

    Returns:
        {
            "targets": [Target, ...],
            "ports": [Port, ...],
            "findings": [Finding, ...],
            "raw_xml": str,
        }
    """
    clean_target = _extract_nmap_target(target)
    clean_ports = validate_cli_target(ports, label="ports")
    safe_extra = validate_extra_args(extra_args)

    if not ToolRunner.is_available("nmap"):
        log.warning("nmap not found — skipping port scan for %s", clean_target)
        return {"targets": [], "ports": [], "findings": [], "raw_xml": ""}

    xml_path = ToolRunner.make_temp_path(".xml")
    profile = list(SCAN_PROFILES.get(stealth, SCAN_PROFILES["normal"]))

    args = [*profile, "-p", clean_ports, "-oX", xml_path, *safe_extra, clean_target]

    try:
        out = await ToolRunner.run("nmap", args, timeout=timeout)

        # Fallback if non-root container lacks raw-socket capabilities for -O / -sS
        if not out.ok and "requires root privileges" in out.stderr.lower():
            fallback_profile = [("-sT" if a == "-sS" else a) for a in profile if a != "-O"]
            if not any(a.startswith("-s") for a in fallback_profile):
                fallback_profile.insert(0, "-sT")
            log.info(
                "nmap lacks root caps; retrying with unprivileged profile: %s", fallback_profile
            )
            retry_args = [
                *fallback_profile,
                "-p",
                clean_ports,
                "-oX",
                xml_path,
                *safe_extra,
                clean_target,
            ]
            out = await ToolRunner.run("nmap", retry_args, timeout=timeout)

        if out.returncode == -1:
            log.warning("nmap timed out for %s after %ds", clean_target, timeout)
            return {"targets": [], "ports": [], "findings": [], "raw_xml": ""}

        if not out.ok and out.returncode != 1:
            log.warning("nmap returned rc=%d: %s", out.returncode, out.stderr[:200])

        try:
            xml_text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            log.error("nmap XML output not found at %s", xml_path)
            return {"targets": [], "ports": [], "findings": [], "raw_xml": ""}
    finally:
        Path(xml_path).unlink(missing_ok=True)

    return _parse_nmap_xml(xml_text, clean_target)


def _parse_nmap_xml(xml_text: str, default_host: str = "") -> dict[str, Any]:
    """Parse nmap XML output into NEXUS models."""
    targets: list[Target] = []
    ports: list[Port] = []
    findings: list[Finding] = []

    try:
        root = safe_parse_xml(xml_text)
    except ET.ParseError as e:
        log.error("Failed to parse nmap XML: %s", e)
        return {"targets": targets, "ports": ports, "findings": findings, "raw_xml": xml_text}

    for host_el in root.findall(".//host"):
        # Address
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        ip = addr_el.get("addr", "") if addr_el is not None else ""

        # Hostname
        hostname = ""
        hn_el = host_el.find(".//hostname")
        if hn_el is not None:
            hostname = hn_el.get("name", "")

        # Status
        status_el = host_el.find("status")
        is_up = status_el is not None and status_el.get("state") == "up"

        # OS guess
        os_guess = ""
        os_match = host_el.find(".//osmatch")
        if os_match is not None:
            os_guess = os_match.get("name", "")

        tgt = Target(
            host=hostname or ip,
            ip=ip,
            is_live=is_up,
            os_guess=os_guess,
        )
        targets.append(tgt)

        # Ports
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            if state not in ("open", "open|filtered"):
                continue

            portnum = int(port_el.get("portid", "0"))
            proto = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            service = svc_el.get("name", "") if svc_el is not None else ""
            version = ""
            if svc_el is not None:
                parts = [
                    svc_el.get("product", ""),
                    svc_el.get("version", ""),
                    svc_el.get("extrainfo", ""),
                ]
                version = " ".join(p for p in parts if p).strip()

            p = Port(
                target_id=tgt.id,
                port=portnum,
                protocol=proto,
                state=state,
                service=service,
                version=version,
            )
            ports.append(p)

            # Create an INFO finding for every open port
            findings.append(
                Finding(
                    host=tgt.host or ip,
                    port=portnum,
                    protocol=proto,
                    title=f"Open port {portnum}/{proto} — {service}"
                    if service
                    else f"Open port {portnum}/{proto}",
                    description=f"Service: {version}"
                    if version
                    else f"Open {service or proto} port detected.",
                    severity=Severity.INFO,
                    tool_source="nmap",
                )
            )

            # Port-level NSE script output findings (preserve port/protocol context)
            for script_el in port_el.findall("script"):
                script_id = script_el.get("id", "")
                script_output = script_el.get("output", "")
                if "VULNERABLE" in script_output.upper() or "vuln" in script_id.lower():
                    findings.append(
                        Finding(
                            host=tgt.host or ip,
                            port=portnum,
                            protocol=proto,
                            title=f"Nmap script: {script_id}",
                            description=script_output[:500],
                            severity=Severity.MEDIUM,
                            tool_source="nmap",
                            evidence=script_output[:2000],
                        )
                    )

        # Host-level NSE script output findings (<hostscript><script .../></hostscript>)
        for script_el in host_el.findall("hostscript/script"):
            script_id = script_el.get("id", "")
            script_output = script_el.get("output", "")
            if "VULNERABLE" in script_output.upper() or "vuln" in script_id.lower():
                findings.append(
                    Finding(
                        host=tgt.host or ip,
                        title=f"Nmap script: {script_id}",
                        description=script_output[:500],
                        severity=Severity.MEDIUM,
                        tool_source="nmap",
                        evidence=script_output[:2000],
                    )
                )

    return {
        "targets": targets,
        "ports": ports,
        "findings": findings,
        "raw_xml": xml_text,
    }

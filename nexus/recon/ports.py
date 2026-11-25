"""Nmap port-scanner wrapper — parses XML output into Port and Target models."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from nexus.db.models import Finding, Port, Severity, Target
from nexus.recon.runner import ToolRunner

log = logging.getLogger("nexus.recon.ports")

# Stealth-aware scan profiles keyed by stealth level.
SCAN_PROFILES: dict[str, list[str]] = {
    "loud": ["-sV", "-sC", "-O", "--version-all", "-T4"],
    "normal": ["-sV", "-sC", "-T3"],
    "quiet": ["-sV", "-T2", "--max-retries", "1"],
    "ghost": ["-sS", "-T1", "--max-retries", "1", "-Pn", "--data-length", "24"],
}

DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017"


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
    # Strip URL scheme / path if caller passes a URL
    clean_target = target.strip()
    if "://" in clean_target:
        clean_target = clean_target.split("://", 1)[1]
    clean_target = clean_target.split("/")[0].split(":")[0] or target.strip()

    xml_path = ToolRunner.make_temp_path(".xml")
    profile = list(SCAN_PROFILES.get(stealth, SCAN_PROFILES["normal"]))

    args = [*profile, "-p", ports, "-oX", xml_path, clean_target]
    if extra_args:
        args.extend(extra_args)

    try:
        out = await ToolRunner.run("nmap", args, timeout=timeout)

        # Fallback if non-root container lacks raw-socket capabilities for -O / -sS
        if not out.ok and "requires root privileges" in out.stderr.lower():
            fallback_profile = [
                ("-sT" if a == "-sS" else a)
                for a in profile
                if a != "-O"
            ]
            if not any(a.startswith("-s") for a in fallback_profile):
                fallback_profile.insert(0, "-sT")
            log.info("nmap lacks root caps; retrying with unprivileged profile: %s", fallback_profile)
            retry_args = [*fallback_profile, "-p", ports, "-oX", xml_path, clean_target]
            if extra_args:
                retry_args.extend(extra_args)
            out = await ToolRunner.run("nmap", retry_args, timeout=timeout)

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
        root = ET.fromstring(xml_text)
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
            findings.append(Finding(
                host=tgt.host or ip,
                port=portnum,
                protocol=proto,
                title=f"Open port {portnum}/{proto} — {service}" if service else f"Open port {portnum}/{proto}",
                description=f"Service: {version}" if version else f"Open {service or proto} port detected.",
                severity=Severity.INFO,
                tool_source="nmap",
            ))

        # Script output findings (vuln scripts)
        for script_el in host_el.findall(".//script"):
            script_id = script_el.get("id", "")
            script_output = script_el.get("output", "")
            if "VULNERABLE" in script_output.upper() or "vuln" in script_id.lower():
                findings.append(Finding(
                    host=tgt.host or ip,
                    title=f"Nmap script: {script_id}",
                    description=script_output[:500],
                    severity=Severity.MEDIUM,
                    tool_source="nmap",
                    evidence=script_output[:2000],
                ))

    return {
        "targets": targets,
        "ports": ports,
        "findings": findings,
        "raw_xml": xml_text,
    }

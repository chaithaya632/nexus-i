"""Nmap port-scanner wrapper — parses XML output into Port and Target models."""

from __future__ import annotations

import ipaddress
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from nexus.db.models import Finding, Port, Severity, Target
from nexus.recon.runner import (
    ToolOutput,
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

_NO_PING_FLAGS = frozenset({"-Pn", "-PN", "-P0"})
_SLOW_CONNECT_FLAGS = ["-sT", "-Pn", "-sV", "-T2", "--max-retries", "2"]
_CONNECT_INCOMPATIBLE_FLAGS = frozenset(
    {
        "-sS",
        "-sT",
        "-sA",
        "-sF",
        "-sN",
        "-sX",
        "-sW",
        "-sM",
        "-sU",
        "-sY",
        "-sZ",
        "-sO",
        "-sL",
        "-sn",
        "-sP",
        "-sV",
        "-O",
        "--osscan-limit",
        "--osscan-guess",
        "-Pn",
        "-PN",
        "-P0",
        "-f",
        "-ff",
        "--badsum",
        "-T0",
        "-T1",
        "-T2",
        "-T3",
        "-T4",
        "-T5",
    }
)
_CONNECT_INCOMPATIBLE_VALUE_FLAGS = frozenset(
    {
        "-sI",
        "-b",
        "-D",
        "-S",
        "-T",
        "--scanflags",
        "--ttl",
        "--spoof-mac",
        "--mtu",
        "--data-length",
        "--max-retries",
        "--min-rate",
        "--max-rate",
        "--min-parallelism",
        "--max-parallelism",
        "--scan-delay",
        "--max-scan-delay",
        "--min-hostgroup",
        "--max-hostgroup",
        "--initial-rtt-timeout",
        "--min-rtt-timeout",
        "--max-rtt-timeout",
    }
)

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


def _has_no_ping_flag(flags: list[str]) -> bool:
    """Return True if host-discovery skip flags (-Pn/-PN/-P0) are present."""
    return any(flag in _NO_PING_FLAGS for flag in flags)


def _build_nmap_args(
    profile_flags: list[str],
    clean_ports: str,
    xml_path: str,
    safe_extra: list[str],
    clean_target: str,
) -> list[str]:
    """Assemble validated nmap CLI arguments."""
    return [*profile_flags, "-p", clean_ports, "-oX", xml_path, *safe_extra, "--", clean_target]


def _compatible_connect_extra(safe_extra: list[str]) -> list[str]:
    """Filter extra CLI args that conflict with a slowed -sT -Pn -T2 fallback scan."""
    filtered: list[str] = []
    idx = 0
    while idx < len(safe_extra):
        arg = safe_extra[idx]
        flag = arg.split("=", 1)[0]
        if flag in _CONNECT_INCOMPATIBLE_FLAGS:
            idx += 1
            continue
        if flag in _CONNECT_INCOMPATIBLE_VALUE_FLAGS:
            if (
                "=" not in arg
                and idx + 1 < len(safe_extra)
                and not safe_extra[idx + 1].startswith("-")
            ):
                idx += 2
            else:
                idx += 1
            continue
        filtered.append(arg)
        idx += 1
    return filtered


def _read_nmap_xml(xml_path: str) -> tuple[str | None, ET.Element | None]:
    """Read and safely parse nmap XML output if available and well-formed."""
    try:
        xml_text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None, None
    if not xml_text.strip():
        return xml_text, None
    try:
        return xml_text, safe_parse_xml(xml_text)
    except ET.ParseError:
        return xml_text, None


def _count_port_states(root: ET.Element) -> dict[str, int]:
    """Count port states across <port> and <extraports> elements in nmap XML."""
    counts: dict[str, int] = {}
    for port_el in root.findall(".//port"):
        state_el = port_el.find("state")
        state = state_el.get("state", "unknown") if state_el is not None else "unknown"
        counts[state] = counts.get(state, 0) + 1
    for extra_el in root.findall(".//extraports"):
        state = extra_el.get("state", "")
        if not state:
            continue
        try:
            count = max(0, int(extra_el.get("count", "0")))
        except ValueError:
            count = 0
        if count:
            counts[state] = counts.get(state, 0) + count
    return counts


def _is_all_filtered(counts: dict[str, int]) -> bool:
    """Return True when only filtered ports exist (0 open, open|filtered, or closed)."""
    return (
        counts.get("filtered", 0) > 0
        and counts.get("open", 0) == 0
        and counts.get("open|filtered", 0) == 0
        and counts.get("closed", 0) == 0
    )


_ZERO_HOSTS_UP_RE = re.compile(r"(?<!\d)0 hosts? up\b")


def _output_shows_host_down(out: ToolOutput) -> bool:
    """Return True when nmap stdout/stderr indicates ping probes saw host down."""
    combined = f"{out.stderr or ''}\n{out.stdout or ''}".lower()
    return "host seems down" in combined or bool(_ZERO_HOSTS_UP_RE.search(combined))


def _xml_shows_host_down(root: ET.Element) -> bool:
    """Return True when XML runstats report 0 hosts up with no <status state='up'/>."""
    hosts_el = root.find(".//runstats/hosts")
    if hosts_el is None or hosts_el.get("up") != "0":
        return False
    return root.find(".//status[@state='up']") is None


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
    for arg in safe_extra:
        if arg == "--" or arg.startswith("-o") or arg.lower().startswith("-il"):
            raise ValueError(f"Disallowed extra nmap CLI argument: {arg}")

    if not ToolRunner.is_available("nmap"):
        log.warning("nmap not found — skipping port scan for %s", clean_target)
        return {"targets": [], "ports": [], "findings": [], "raw_xml": ""}

    xml_path = ToolRunner.make_temp_path(".xml")
    current_flags = list(SCAN_PROFILES.get(stealth, SCAN_PROFILES["normal"]))
    if "/" not in clean_target and not _has_no_ping_flag([*current_flags, *safe_extra]):
        current_flags.append("-Pn")

    current_args = _build_nmap_args(current_flags, clean_ports, xml_path, safe_extra, clean_target)

    try:
        out = await ToolRunner.run("nmap", current_args, timeout=timeout)

        # Fallback if non-root container lacks raw-socket capabilities for -O / -sS
        if not out.ok and "requires root privileges" in out.stderr.lower():
            fallback_profile = [("-sT" if a == "-sS" else a) for a in current_flags if a != "-O"]
            safe_extra = [("-sT" if a == "-sS" else a) for a in safe_extra]
            if not any(a.startswith("-s") for a in fallback_profile):
                fallback_profile.insert(0, "-sT")
            log.info(
                "nmap lacks root caps; retrying with unprivileged profile: %s", fallback_profile
            )
            current_flags = fallback_profile
            current_args = _build_nmap_args(
                current_flags, clean_ports, xml_path, safe_extra, clean_target
            )
            Path(xml_path).write_text("", encoding="utf-8")
            out = await ToolRunner.run("nmap", current_args, timeout=timeout)

        if out.returncode == -1:
            log.warning("nmap timed out for %s after %ds", clean_target, timeout)
            return {"targets": [], "ports": [], "findings": [], "raw_xml": ""}

        xml_text, root = _read_nmap_xml(xml_path)
        firewall_retry_args: list[str] | None = None
        if not _has_no_ping_flag(current_args) and (
            _output_shows_host_down(out) or (root is not None and _xml_shows_host_down(root))
        ):
            log.info(
                "nmap reported host down / 0 hosts up for %s; retrying with -Pn",
                clean_target,
            )
            firewall_retry_args = _build_nmap_args(
                [*current_flags, "-Pn"], clean_ports, xml_path, safe_extra, clean_target
            )
        elif root is not None and _is_all_filtered(_count_port_states(root)):
            log.info(
                "nmap returned only filtered ports for %s; retrying once with slowed -sT -Pn -T2 scan",
                clean_target,
            )
            firewall_retry_args = _build_nmap_args(
                list(_SLOW_CONNECT_FLAGS),
                clean_ports,
                xml_path,
                _compatible_connect_extra(safe_extra),
                clean_target,
            )

        if firewall_retry_args is not None:
            Path(xml_path).write_text("", encoding="utf-8")
            out = await ToolRunner.run("nmap", firewall_retry_args, timeout=timeout)
            if out.returncode == -1:
                log.warning("nmap timed out for %s after %ds", clean_target, timeout)
                return {"targets": [], "ports": [], "findings": [], "raw_xml": ""}
            xml_text, root = _read_nmap_xml(xml_path)

        if not out.ok and out.returncode != 1:
            log.warning("nmap returned rc=%d: %s", out.returncode, out.stderr[:200])

        if xml_text is None:
            log.error("nmap XML output not found at %s", xml_path)
            return {"targets": [], "ports": [], "findings": [], "raw_xml": ""}

        if root is not None:
            final_counts = _count_port_states(root)
            if _is_all_filtered(final_counts):
                log.warning(
                    "nmap for %s still returned only filtered ports (%d filtered, "
                    "0 open/open|filtered); leaving ports empty",
                    clean_target,
                    final_counts["filtered"],
                )
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

"""OSINT wrapper — theHarvester for email/domain OSINT gathering."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from nexus.db.models import Finding, Severity, Target
from nexus.recon.runner import ToolRunner

log = logging.getLogger("nexus.recon.osint")

# Default passive data sources validated against theHarvester 4.11+
DEFAULT_SOURCES = "certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,otx,rapiddns,subdomaincenter,urlscan,waybackarchive,yahoo"


def _harvester_bin() -> str | None:
    if ToolRunner.is_available("theHarvester"):
        return "theHarvester"
    if ToolRunner.is_available("theharvester"):
        return "theharvester"
    return None


def _split_host_ip(entry: str) -> tuple[str, str]:
    """Split 'sub.example.com:1.2.3.4' into (host, ip) and ignore wildcards."""
    val = entry.lower().strip()
    if val.startswith("*."):
        return "", ""
    if ":" in val:
        host_part, ip_part = val.split(":", 1)
        return host_part.strip(), ip_part.strip()
    return val, ""


async def theharvester_gather(
    domain: str,
    *,
    sources: str = DEFAULT_SOURCES,
    limit: int = 500,
    timeout: int = 180,
) -> dict[str, Any]:
    """Run theHarvester and parse results.

    Returns:
        {
            "domain": str,
            "emails": [str, ...],
            "hosts": [str, ...],
            "ips": [str, ...],
            "host_ips": {host: ip, ...},
        }
    """
    tool_bin = _harvester_bin() or "theHarvester"
    json_path = ToolRunner.make_temp_path(".json")

    args = [
        "-d", domain,
        "-b", sources,
        "-l", str(limit),
        "-f", json_path,
    ]

    out = await ToolRunner.run(tool_bin, args, timeout=timeout)

    emails: list[str] = []
    raw_hosts: list[str] = []
    ips: list[str] = []

    # Parse JSON output file
    try:
        raw = Path(json_path).read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
        emails = data.get("emails", []) or []
        raw_hosts = data.get("hosts", []) or []
        ips = data.get("ips", []) or []
    except (FileNotFoundError, json.JSONDecodeError):
        # Fallback: parse stdout
        emails, raw_hosts, ips = _parse_harvester_stdout(out.stdout)
    finally:
        Path(json_path).unlink(missing_ok=True)
        # theHarvester also creates .xml — clean up
        xml_path = json_path.replace(".json", ".xml")
        Path(xml_path).unlink(missing_ok=True)

    # Clean & deduplicate (strip host:ip suffixes and wildcards)
    clean_emails = sorted(set(e.lower().strip() for e in emails if e and "@" in e))
    host_ips: dict[str, str] = {}
    ip_set: set[str] = {i.strip() for i in ips if i}
    for h_raw in raw_hosts:
        if not h_raw or "." not in h_raw:
            continue
        host, ip = _split_host_ip(h_raw)
        if host and "." in host:
            host_ips.setdefault(host, ip)
            if ip:
                ip_set.add(ip)

    clean_hosts = sorted(host_ips.keys())
    clean_ips = sorted(ip_set)

    log.info(
        "theHarvester for %s: %d emails, %d hosts, %d IPs",
        domain, len(clean_emails), len(clean_hosts), len(clean_ips),
    )
    return {
        "domain": domain,
        "emails": clean_emails,
        "hosts": clean_hosts,
        "ips": clean_ips,
        "host_ips": host_ips,
    }


def _parse_harvester_stdout(stdout: str) -> tuple[list[str], list[str], list[str]]:
    """Fallback parser for theHarvester's text output."""
    emails: list[str] = []
    hosts: list[str] = []
    ips: list[str] = []

    email_re = re.compile(r"[\w.+-]+@[\w.-]+\.[\w]+")
    ip_re = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    for line in stdout.splitlines():
        line = line.strip()
        found_emails = email_re.findall(line)
        emails.extend(found_emails)
        found_ips = ip_re.findall(line)
        ips.extend(found_ips)
        # Hostnames are lines with dots that aren't IPs or emails
        if "." in line and "@" not in line and not ip_re.match(line):
            # Crude: if the line looks like a domain
            if re.match(r"^[\w.-]+\.\w{2,}$", line):
                hosts.append(line)

    return emails, hosts, ips


async def gather_osint(
    domain: str,
    *,
    timeout: int = 180,
) -> tuple[list[Target], list[Finding]]:
    """Run OSINT gathering and return targets + findings.

    Findings are created for discovered email addresses (useful for
    credential attacks and social engineering awareness).
    """
    import ipaddress

    targets: list[Target] = []
    findings: list[Finding] = []

    # OSINT isn't applicable to raw IP addresses or localhost
    domain_clean = domain.strip().lower()
    if domain_clean in ("localhost", "127.0.0.1", "::1"):
        return targets, findings
    try:
        ipaddress.ip_address(domain_clean)
        return targets, findings
    except ValueError:
        pass

    if not _harvester_bin():
        log.warning("theHarvester not found — skipping OSINT gathering")
        return targets, findings

    result = await theharvester_gather(domain_clean, timeout=timeout)

    # Create Target records for discovered hosts
    host_ips = result.get("host_ips", {})
    for host in result["hosts"]:
        targets.append(Target(host=host, ip=host_ips.get(host, "")))

    # Create a finding for discovered emails
    emails = result["emails"]
    if emails:
        findings.append(Finding(
            host=domain,
            title=f"OSINT: {len(emails)} email addresses discovered",
            description=(
                f"Passive OSINT enumeration discovered {len(emails)} email "
                f"addresses associated with {domain}.  These can be used for "
                f"targeted phishing, credential stuffing, or password spraying."
            ),
            severity=Severity.LOW,
            tool_source="theHarvester",
            evidence="\n".join(emails[:50]),  # cap evidence at 50
        ))

    return targets, findings

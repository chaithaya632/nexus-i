"""DNS enumeration wrapper — dnsx for DNS brute-forcing and zone checks."""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any

from nexus.db.models import Finding, Severity, Target
from nexus.recon.runner import ToolRunner

log = logging.getLogger("nexus.recon.dns")

# Common DNS record types to query
RECORD_TYPES = ["a", "aaaa", "cname", "mx", "ns", "txt", "soa", "ptr"]


async def dnsx_resolve(
    domains: list[str],
    *,
    record_types: list[str] | None = None,
    timeout: int = 120,
    threads: int = 25,
) -> list[dict[str, Any]]:
    """Resolve domains with dnsx and return JSON records."""
    if not domains:
        return []

    stdin_data = "\n".join(domains)
    types = record_types or ["a", "aaaa", "cname"]

    args = ["-json", "-silent", "-threads", str(threads)]
    for rt in types:
        args.append(f"-{rt}")

    out = await ToolRunner.run("dnsx", args, timeout=timeout, stdin_data=stdin_data)

    results: list[dict[str, Any]] = []
    for line in out.lines:
        try:
            rec = json.loads(line)
            results.append(rec)
        except json.JSONDecodeError:
            continue

    log.info("dnsx resolved %d domains → %d records", len(domains), len(results))
    return results


async def dns_zone_transfer(
    domain: str,
    nameserver: str = "",
    *,
    timeout: int = 30,
) -> Finding | None:
    """Attempt a DNS zone transfer using dig.

    A successful zone transfer is a MEDIUM finding — it leaks the full DNS zone.
    """
    if not ToolRunner.is_available("dig"):
        log.warning("dig not found — skipping zone transfer check")
        return None

    ns = nameserver or domain
    args = ["axfr", domain, f"@{ns}"]
    out = await ToolRunner.run("dig", args, timeout=timeout)

    # Zone transfer succeeded if we get actual records (not just SOA or error)
    lines = [l for l in out.lines if not l.startswith(";") and l.strip()]
    record_count = len(lines)

    if record_count > 2:  # SOA + at least some real records
        return Finding(
            host=domain,
            title=f"DNS Zone Transfer Allowed ({domain})",
            description=(
                f"The nameserver {ns} allows zone transfer (AXFR) for {domain}. "
                f"Retrieved {record_count} DNS records.  This exposes the full DNS "
                f"zone to any attacker."
            ),
            severity=Severity.MEDIUM,
            cwe_id="CWE-200",
            tool_source="dig",
            evidence="\n".join(lines[:50]),  # first 50 records as evidence
        )

    return None


async def enumerate_dns(
    targets: list[Target],
    *,
    timeout: int = 180,
) -> tuple[list[Target], list[Finding]]:
    """Run DNS enumeration on all targets.

    Returns enriched targets (with IPs from DNS) and any DNS findings.
    """
    findings: list[Finding] = []
    domains = [t.host for t in targets if t.host and not t.ip]

    # Resolve A/AAAA/CNAME via dnsx
    if domains and ToolRunner.is_available("dnsx"):
        records = await dnsx_resolve(domains, timeout=timeout)
        ip_map: dict[str, str] = {}
        for rec in records:
            host = rec.get("host", "").lower()
            a_records = rec.get("a", [])
            if a_records:
                ip_map[host] = a_records[0]

        for t in targets:
            if not t.ip and t.host.lower() in ip_map:
                t.ip = ip_map[t.host.lower()]
    elif domains:
        log.warning("dnsx not found — skipping DNS resolution")

    # Zone transfer check on unique root domains (skip raw IPs & localhost)
    seen_domains: set[str] = set()
    for t in targets:
        host_clean = t.host.strip().lower()
        if not host_clean or host_clean == "localhost":
            continue
        try:
            ipaddress.ip_address(host_clean)
            continue
        except ValueError:
            pass
        parts = host_clean.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
            seen_domains.add(root)

    for domain in seen_domains:
        finding = await dns_zone_transfer(domain, timeout=30)
        if finding:
            findings.append(finding)

    return targets, findings

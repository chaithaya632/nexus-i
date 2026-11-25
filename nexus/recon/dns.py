"""DNS enumeration wrapper — dnsx for DNS brute-forcing and zone checks."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
from typing import Any

from nexus.db.models import Finding, Severity, Target
from nexus.recon.runner import ToolRunner, validate_cli_target

log = logging.getLogger("nexus.recon.dns")

# Common DNS record types to query
RECORD_TYPES = ["a", "aaaa", "cname", "mx", "ns", "txt", "soa", "ptr"]
_DEFAULT_FORWARD_TYPES = ["a", "aaaa", "cname", "mx", "ns", "txt"]

_MULTI_PART_TLDS = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "net.uk",
        "me.uk",
        "co.jp",
        "ne.jp",
        "or.jp",
        "ac.jp",
        "go.jp",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "com.br",
        "net.br",
        "org.br",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "co.in",
        "net.in",
        "org.in",
        "gov.in",
        "ac.in",
        "co.nz",
        "net.nz",
        "org.nz",
        "co.za",
        "org.za",
        "net.za",
        "com.sg",
        "com.hk",
        "com.tw",
        "com.mx",
        "com.ar",
        "co.kr",
        "com.tr",
        "com.ua",
        "com.pl",
    }
)


def _extract_root_domain(host: str) -> str:
    """Extract registrable root domain, handling common multi-part public suffixes."""
    clean = host.strip().lower().rstrip(".")
    parts = [p for p in clean.split(".") if p]
    if len(parts) < 2:
        return ""
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_PART_TLDS:
        if len(parts) < 3:
            return ""
        return ".".join(parts[-3:])
    return last_two


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

    clean_domains = [validate_cli_target(d, label="domain") for d in domains]
    stdin_data = "\n".join(clean_domains)
    allowed = set(RECORD_TYPES)
    raw_types = record_types or _DEFAULT_FORWARD_TYPES
    types = [rt.lower().strip() for rt in raw_types if rt.lower().strip() in allowed]
    if not types:
        types = list(_DEFAULT_FORWARD_TYPES)

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

    log.info("dnsx resolved %d domains → %d records", len(clean_domains), len(results))
    return results


def _resolve_host_sync(host: str) -> str:
    """Resolve a hostname to its first IPv4 (preferred) or IPv6 address via stdlib."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return ""
    ipv6_fallback = ""
    for family, _type, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0] if sockaddr else ""
        if family == socket.AF_INET and addr:
            return addr
        if family == socket.AF_INET6 and addr and not ipv6_fallback:
            ipv6_fallback = addr
    return ipv6_fallback


async def _resolve_authoritative_ns(domain: str, *, timeout: int = 15) -> list[str]:
    """Discover authoritative nameservers for *domain* via `dig +short NS`."""
    if not ToolRunner.is_available("dig"):
        return []
    clean_domain = validate_cli_target(domain, label="domain")
    out = await ToolRunner.run("dig", ["+short", "NS", clean_domain], timeout=timeout)
    nameservers: list[str] = []
    for line in out.lines:
        ns = line.strip().rstrip(".")
        if ns and not ns.startswith(";") and not ns.startswith("-"):
            try:
                nameservers.append(validate_cli_target(ns, label="nameserver"))
            except ValueError:
                continue
    return list(dict.fromkeys(nameservers))


async def dns_zone_transfer(
    domain: str,
    nameserver: str = "",
    *,
    timeout: int = 30,
) -> Finding | None:
    """Attempt a DNS zone transfer using dig against authoritative nameservers.

    A successful zone transfer is a MEDIUM finding — it leaks the full DNS zone.
    """
    clean_domain = validate_cli_target(domain, label="domain")
    if not ToolRunner.is_available("dig"):
        log.warning("dig not found — skipping zone transfer check")
        return None

    candidates: list[str]
    if nameserver:
        candidates = [validate_cli_target(nameserver, label="nameserver")]
    else:
        candidates = await _resolve_authoritative_ns(clean_domain, timeout=min(timeout, 15))
        if not candidates:
            log.debug("No authoritative NS resolved for %s — skipping AXFR check", clean_domain)
            return None

    for ns in candidates[:3]:
        args = ["axfr", clean_domain, f"@{ns}"]
        out = await ToolRunner.run("dig", args, timeout=timeout)

        # Zone transfer succeeded if we get actual records (not just SOA or error)
        lines = [line for line in out.lines if not line.startswith(";") and line.strip()]
        record_count = len(lines)

        if record_count > 2:  # SOA + at least some real records
            return Finding(
                host=clean_domain,
                title=f"DNS Zone Transfer Allowed ({clean_domain})",
                description=(
                    f"The nameserver {ns} allows zone transfer (AXFR) for {clean_domain}. "
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
    ns_map: dict[str, list[str]] = {}

    # Resolve A/AAAA/CNAME/MX/NS/TXT via dnsx, or stdlib socket.getaddrinfo fallback
    if domains and ToolRunner.is_available("dnsx"):
        records = await dnsx_resolve(domains, timeout=timeout)
        ip_map: dict[str, str] = {}
        for rec in records:
            host = (rec.get("host") or "").lower().strip()
            if not host:
                continue
            a_records = rec.get("a") or []
            aaaa_records = rec.get("aaaa") or []
            if a_records:
                ip_map[host] = a_records[0]
            elif aaaa_records:
                ip_map[host] = aaaa_records[0]

            ns_records = [str(n).rstrip(".") for n in (rec.get("ns") or []) if n]
            if ns_records:
                root = _extract_root_domain(host) or host
                ns_map.setdefault(root, [])
                for ns_val in ns_records:
                    if ns_val not in ns_map[root]:
                        ns_map[root].append(ns_val)

            detail_parts: list[str] = []
            for rtype in ("cname", "mx", "ns", "txt"):
                vals = rec.get(rtype) or []
                if vals:
                    detail_parts.append(f"{rtype.upper()}: {', '.join(str(v) for v in vals[:5])}")
            if detail_parts:
                findings.append(
                    Finding(
                        host=host,
                        title=f"DNS Records Enumerated ({host})",
                        description=f"DNS enumeration returned structured records for {host}.",
                        severity=Severity.INFO,
                        tool_source="dnsx",
                        evidence="\n".join(detail_parts),
                    )
                )

        for t in targets:
            if not t.ip and t.host.lower() in ip_map:
                t.ip = ip_map[t.host.lower()]
    elif domains:
        log.info("dnsx not found — falling back to Python socket.getaddrinfo resolution")
        for t in targets:
            if not t.ip and t.host:
                try:
                    clean_h = validate_cli_target(t.host, label="domain")
                    resolved_ip = await asyncio.to_thread(_resolve_host_sync, clean_h)
                    if resolved_ip:
                        t.ip = resolved_ip
                except ValueError:
                    continue

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
        root = _extract_root_domain(host_clean)
        if root:
            seen_domains.add(root)

    for domain in seen_domains:
        auth_ns = (ns_map.get(domain) or [""])[0]
        finding = await dns_zone_transfer(domain, nameserver=auth_ns, timeout=30)
        if finding:
            findings.append(finding)

    return targets, findings

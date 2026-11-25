"""Subdomain enumeration wrappers — subfinder + amass."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from typing import Any

from nexus.db.models import Target
from nexus.recon.runner import ToolRunner

log = logging.getLogger("nexus.recon.subdomains")

# Strict hostname regex — rejects progress bars, ANSI artifacts, arrows, etc.
_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _extract_valid_host(raw_line: str, domain: str) -> str:
    """Clean a candidate line and return a valid hostname belonging to *domain*, else ''."""
    cleaned = _ANSI_RE.sub("", raw_line).strip().lower()
    if not cleaned or "%" in cleaned or "[" in cleaned or "p/s" in cleaned:
        return ""
    # Amass v5 may output: "sub.example.com (FQDN) --> node --> ..."
    candidate = cleaned.split()[0].lstrip("*.").rstrip(".")
    domain_l = domain.lower().lstrip("*.").rstrip(".")
    if not _HOST_RE.match(candidate):
        return ""
    if candidate != domain_l and not candidate.endswith(f".{domain_l}"):
        return ""
    return candidate


async def subfinder_enum(
    domain: str,
    *,
    timeout: int = 120,
    silent: bool = True,
) -> list[Target]:
    """Run subfinder and return discovered subdomains as Target models."""
    # Ensure ToolRunner timeout allows subfinder -max-time (minutes) to flush before SIGKILL
    max_mins = max(1, min((timeout - 15) // 60, 5)) if timeout >= 75 else 1
    effective_timeout = max(timeout, max_mins * 60 + 15) if timeout >= 60 else timeout
    args = ["-d", domain, "-json", "-max-time", str(max_mins)]
    if silent:
        args.append("-silent")

    out = await ToolRunner.run("subfinder", args, timeout=effective_timeout)
    targets: list[Target] = []
    seen: set[str] = set()

    for line in out.lines:
        rec: dict[str, Any] | None = None
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                rec = parsed
                host = _extract_valid_host(parsed.get("host", ""), domain)
            else:
                host = ""
        except (json.JSONDecodeError, AttributeError):
            # Plain-text fallback (one domain per line)
            host = _extract_valid_host(line, domain)

        if host and host not in seen:
            seen.add(host)
            ip_val = rec.get("ip", "") if isinstance(rec, dict) else ""
            targets.append(Target(host=host, ip=ip_val))

    log.info("subfinder found %d subdomains for %s", len(targets), domain)
    return targets


async def amass_enum(
    domain: str,
    *,
    timeout: int = 90,
    passive_only: bool = True,
) -> list[Target]:
    """Run amass enum and return discovered subdomains.

    Uses passive mode by default to stay stealthy and bounds runtime via -timeout.
    """
    # Skip amass for local/IP targets — passive OSINT isn't meaningful
    try:
        ipaddress.ip_address(domain.strip())
        return []
    except ValueError:
        pass

    mins = max(1, timeout // 60)
    args = ["enum", "-silent", "-nocolor", "-timeout", str(mins)]
    if passive_only:
        args.append("-passive")
    args.extend(["-d", domain])

    out = await ToolRunner.run("amass", args, timeout=timeout)
    targets: list[Target] = []
    seen: set[str] = set()

    for line in out.lines:
        host = _extract_valid_host(line, domain)
        if host and host not in seen:
            seen.add(host)
            targets.append(Target(host=host))

    log.info("amass found %d subdomains for %s", len(targets), domain)
    return targets


async def enumerate_subdomains(
    domain: str,
    *,
    use_amass: bool = True,
    passive_only: bool = True,
    timeout: int = 120,
) -> list[Target]:
    """Merge results from all available subdomain tools.

    Deduplicates by hostname.  Falls back gracefully if a tool is missing.
    Skips public passive subdomain lookup for raw IP addresses / localhost.
    """
    domain_clean = domain.strip().lower()
    is_local_or_ip = domain_clean in ("localhost", "127.0.0.1", "::1")
    if not is_local_or_ip:
        try:
            ipaddress.ip_address(domain_clean)
            is_local_or_ip = True
        except ValueError:
            pass

    if is_local_or_ip:
        return [Target(host=domain_clean, ip=domain_clean if "." in domain_clean or ":" in domain_clean else "")]

    merged: dict[str, Target] = {}

    # subfinder (fast, usually available)
    if ToolRunner.is_available("subfinder"):
        for t in await subfinder_enum(domain_clean, timeout=min(timeout, 120)):
            merged.setdefault(t.host, t)
    else:
        log.warning("subfinder not found — skipping")

    # amass (slower, bounded so engagements don't stall on amass engine)
    if use_amass and ToolRunner.is_available("amass"):
        for t in await amass_enum(domain_clean, timeout=min(timeout, 60), passive_only=passive_only):
            merged.setdefault(t.host, t)
    elif use_amass:
        log.warning("amass not found — skipping")

    # Always include the root domain
    if domain_clean not in merged:
        merged[domain_clean] = Target(host=domain_clean)

    result = list(merged.values())
    log.info("Total unique subdomains for %s: %d", domain_clean, len(result))
    return result

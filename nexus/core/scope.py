"""Scope enforcer — the non-bypassable security boundary of NEXUS."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized engagement scope."""


def _compile_domain_pattern(domain: str) -> re.Pattern[str]:
    """Compile an exact or wildcard domain entry into a case-insensitive regex."""
    cleaned = domain.strip().rstrip(".").lower()
    if cleaned == "*":
        return re.compile(r"^.+$", re.IGNORECASE)
    if cleaned.startswith("*."):
        # Wildcard: *.example.com matches sub.example.com and example.com
        base = re.escape(cleaned[2:])
        return re.compile(rf"^(.+\.)?{base}$", re.IGNORECASE)
    return re.compile(rf"^{re.escape(cleaned)}$", re.IGNORECASE)


def _canonicalize_ip(value: str) -> str | None:
    """Return canonical IPv4/IPv6 string if *value* is a valid IP, else None."""
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


@dataclass
class Scope:
    """Parsed engagement scope from scope.yaml."""

    allowed_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    allowed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    allowed_ports: list[int] | None = None  # None means all ports allowed
    notes: str = ""


class ScopeEnforcer:
    """Guards every tool/exploit execution against the authorized scope.

    Usage:
        enforcer = ScopeEnforcer.from_file("scope.yaml")
        enforcer.enforce("10.0.0.5")       # OK
        enforcer.enforce("evil.com")        # raises ScopeViolation
    """

    def __init__(self, scope: Scope) -> None:
        self._scope = scope
        self._domain_patterns: list[re.Pattern[str]] = [
            _compile_domain_pattern(d) for d in scope.allowed_domains if d and d.strip()
        ]

        self._ip_set: set[str] = set()
        for ip_str in scope.allowed_ips:
            if not ip_str or not ip_str.strip():
                continue
            canon = _canonicalize_ip(ip_str)
            self._ip_set.add(canon if canon is not None else ip_str.strip().lower())

        self._networks = list(scope.allowed_cidrs)
        self._excluded: set[str] = set()
        self._excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded_domain_patterns: list[re.Pattern[str]] = []

        for ex in scope.excluded_targets:
            if not ex or not ex.strip():
                continue
            ex_clean = ex.strip()
            if "/" in ex_clean:
                try:
                    self._excluded_networks.append(ipaddress.ip_network(ex_clean, strict=False))
                    continue
                except ValueError:
                    pass
            canon = _canonicalize_ip(ex_clean)
            if canon is not None:
                self._excluded.add(canon)
            else:
                dom = ex_clean.rstrip(".").lower()
                self._excluded.add(dom)
                if dom == "*" or dom.startswith("*."):
                    self._excluded_domain_patterns.append(_compile_domain_pattern(dom))

    @classmethod
    def from_file(cls, path: str | Path) -> ScopeEnforcer:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Scope file not found: {p}")
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("scope.yaml must be a YAML mapping")

        cidrs = [
            ipaddress.ip_network(cidr_str, strict=False)
            for cidr_str in (raw.get("allowed_cidrs") or [])
        ]

        scope = Scope(
            allowed_domains=list(raw.get("allowed_domains") or []),
            allowed_ips=list(raw.get("allowed_ips") or []),
            allowed_cidrs=cidrs,
            excluded_targets=list(raw.get("excluded_targets") or []),
            allowed_ports=raw.get("allowed_ports"),
            notes=raw.get("notes") or "",
        )
        return cls(scope)

    @classmethod
    def for_target(cls, target: str) -> ScopeEnforcer:
        """Build a strict single-target ScopeEnforcer from a URL, IP, CIDR, or domain."""
        raw = target.strip()
        if not raw:
            raise ValueError("Target cannot be empty")
        if raw in ("*", "0.0.0.0/0", "::/0"):
            raise ValueError(f"Wildcard target {target!r} is not allowed in for_target()")

        # 1. CIDR notation (e.g. 10.0.0.0/24)
        if "/" in raw and "://" not in raw:
            try:
                net = ipaddress.ip_network(raw, strict=False)
                if net.prefixlen == 0:
                    raise ValueError(f"Overbroad CIDR {target!r} is not allowed in for_target()")
                return cls(Scope(allowed_cidrs=[net]))
            except ValueError as exc:
                if "Overbroad CIDR" in str(exc):
                    raise

        # 2. Bare IPv4 or IPv6 (with optional brackets)
        canon = _canonicalize_ip(raw)
        if canon is not None:
            return cls(Scope(allowed_ips=[canon]))

        # 3. URL or host[:port][/path]
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        host = (parsed.hostname or "").strip().rstrip(".").lower()
        if not host:
            raise ValueError(f"Could not extract host from target: {target!r}")
        if host == "*" or host.startswith("*."):
            raise ValueError(f"Wildcard host {target!r} is not allowed in for_target()")

        host_ip = _canonicalize_ip(host)
        if host_ip is not None:
            return cls(Scope(allowed_ips=[host_ip]))

        return cls(Scope(allowed_domains=[f"*.{host}"]))

    @classmethod
    def allow_all(cls) -> ScopeEnforcer:
        """Create a permissive enforcer (for testing / unrestricted mode)."""
        return cls(
            Scope(
                allowed_domains=["*"],
                allowed_cidrs=[
                    ipaddress.ip_network("0.0.0.0/0"),
                    ipaddress.ip_network("::/0"),
                ],
            )
        )

    @staticmethod
    def _normalize_target_host(target: str) -> str:
        """Normalize URL, host:port, [IPv6]:port, or domain into a bare host/IP string."""
        raw = target.strip()
        if not raw:
            return ""
        if "://" in raw:
            parsed = urlparse(raw)
            return (parsed.hostname or "").strip().strip("[]").rstrip(".").lower()
        if raw.startswith("["):
            parsed = urlparse(f"http://{raw}")
            return (parsed.hostname or "").strip().strip("[]").rstrip(".").lower()
        try:
            ipaddress.ip_address(raw)
            return raw.lower()
        except ValueError:
            pass
        if "/" in raw:
            try:
                ipaddress.ip_network(raw, strict=False)
                return raw.lower()
            except ValueError:
                raw = raw.split("/", 1)[0]
        head = raw.split("?", 1)[0].split("#", 1)[0]
        if head.count(":") == 1:
            host_part, port_part = head.split(":", 1)
            if port_part.isdigit():
                head = host_part
        return head.strip().rstrip(".").lower()

    def _is_excluded(
        self, raw_target: str, addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    ) -> bool:
        if addr is not None:
            if str(addr) in self._excluded:
                return True
            return any(addr in net for net in self._excluded_networks)

        dom = raw_target.rstrip(".").lower()
        if dom in self._excluded:
            return True
        return any(pat.match(dom) for pat in self._excluded_domain_patterns)

    def _resolved_ips_excluded(self, host: str) -> bool:
        """Resolve *host* via DNS and verify no returned IP hits excluded IPs/CIDRs."""
        if not host or (not self._excluded and not self._excluded_networks):
            return False
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError:
            return False
        for info in infos:
            ip_raw = info[4][0].split("%", 1)[0]
            try:
                resolved_addr = ipaddress.ip_address(ip_raw)
            except ValueError:
                continue
            if self._is_excluded(str(resolved_addr), resolved_addr):
                return True
        return False

    def is_in_scope(self, target: str, *, check_dns: bool = False) -> bool:
        """Check whether a target (URL, domain, IP, or CIDR) is in scope."""
        raw_target = self._normalize_target_host(target)
        if not raw_target:
            return False

        addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        try:
            addr = ipaddress.ip_address(raw_target.strip("[]"))
        except ValueError:
            addr = None

        # Exclusion list always takes priority
        if self._is_excluded(raw_target, addr):
            return False

        if addr is not None:
            if str(addr) in self._ip_set:
                return True
            if any(addr in net for net in self._networks):
                return True
            # Allow explicit wildcard domain ("*") only if configured
            return any(
                pat.pattern == r"^.+$" and pat.match(str(addr)) for pat in self._domain_patterns
            )

        target_domain = raw_target.rstrip(".").lower()
        if not target_domain:
            return False

        if check_dns and self._resolved_ips_excluded(target_domain):
            return False

        for pat in self._domain_patterns:
            if pat.match(target_domain):
                return True

        return False

    def is_port_allowed(self, port: int) -> bool:
        if self._scope.allowed_ports is None:
            return True
        return port in self._scope.allowed_ports

    def enforce(self, target: str, port: int | None = None, *, check_dns: bool = False) -> None:
        """Raise ScopeViolation if target is out of scope. Call before EVERY action."""
        if not self.is_in_scope(target, check_dns=check_dns):
            raise ScopeViolation(
                f"SCOPE VIOLATION: Target '{target}' is NOT in the authorized scope. "
                f"Add it to scope.yaml to proceed."
            )
        if port is not None and not self.is_port_allowed(port):
            raise ScopeViolation(
                f"SCOPE VIOLATION: Port {port} is NOT in the authorized port list."
            )

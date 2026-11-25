"""Scope enforcer — the non-bypassable security boundary of NEXUS."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized engagement scope."""


@dataclass
class Scope:
    """Parsed engagement scope from scope.yaml."""

    allowed_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    allowed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
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
        self._domain_patterns: list[re.Pattern[str]] = []
        for d in scope.allowed_domains:
            if d == "*":
                pattern = re.compile(r"^.+$", re.IGNORECASE)
            elif d.startswith("*."):
                # Wildcard: *.example.com matches sub.example.com and example.com
                base = re.escape(d[2:])
                pattern = re.compile(rf"^(.+\.)?{base}$", re.IGNORECASE)
            else:
                pattern = re.compile(rf"^{re.escape(d)}$", re.IGNORECASE)
            self._domain_patterns.append(pattern)

        self._ip_set: set[str] = set(scope.allowed_ips)
        self._networks = list(scope.allowed_cidrs)
        self._excluded: set[str] = {e.lower() for e in scope.excluded_targets}

    @classmethod
    def from_file(cls, path: str | Path) -> "ScopeEnforcer":
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Scope file not found: {p}")
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("scope.yaml must be a YAML mapping")

        cidrs = []
        for cidr_str in raw.get("allowed_cidrs", []):
            cidrs.append(ipaddress.ip_network(cidr_str, strict=False))

        scope = Scope(
            allowed_domains=raw.get("allowed_domains", []),
            allowed_ips=raw.get("allowed_ips", []),
            allowed_cidrs=cidrs,
            excluded_targets=raw.get("excluded_targets", []),
            allowed_ports=raw.get("allowed_ports"),
            notes=raw.get("notes", ""),
        )
        return cls(scope)

    @classmethod
    def allow_all(cls) -> "ScopeEnforcer":
        """Create a permissive enforcer (for testing / unrestricted mode)."""
        return cls(Scope(
            allowed_domains=["*"],
            allowed_cidrs=[
                ipaddress.ip_network("0.0.0.0/0"),
                ipaddress.ip_network("::/0"),
            ],
        ))

    def is_in_scope(self, target: str) -> bool:
        """Check whether a target (domain, IP, or CIDR) is in scope."""
        target_lower = target.strip().lower()

        # Exclusion list takes priority
        if target_lower in self._excluded:
            return False

        # Check domain match
        for pat in self._domain_patterns:
            if pat.match(target_lower):
                return True

        # Check IP/CIDR match
        try:
            addr = ipaddress.ip_address(target.strip())
            if str(addr) in self._ip_set:
                return True
            for net in self._networks:
                if addr in net:
                    return True
        except ValueError:
            pass  # Not a valid IP — that's fine, could be a domain

        return False

    def is_port_allowed(self, port: int) -> bool:
        if self._scope.allowed_ports is None:
            return True
        return port in self._scope.allowed_ports

    def enforce(self, target: str, port: int | None = None) -> None:
        """Raise ScopeViolation if target is out of scope. Call before EVERY action."""
        if not self.is_in_scope(target):
            raise ScopeViolation(
                f"SCOPE VIOLATION: Target '{target}' is NOT in the authorized scope. "
                f"Add it to scope.yaml to proceed."
            )
        if port is not None and not self.is_port_allowed(port):
            raise ScopeViolation(
                f"SCOPE VIOLATION: Port {port} is NOT in the authorized port list."
            )

"""Service-to-attack routing — dispatches tools based on detected services."""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("nexus.brain.router")


# Default routing rules (used when YAML not available)
DEFAULT_ROUTING: dict[str, dict[str, Any]] = {
    "http": {
        "tools": ["nuclei", "ffuf", "nikto", "whatweb"],
        "checks": ["sqli", "xss", "lfi", "ssrf", "idor", "open_redirect"],
        "ports": [80, 8080, 8000, 8888, 3000, 5000, 8443],
    },
    "https": {
        "tools": ["nuclei", "ffuf", "nikto", "whatweb", "sslyze"],
        "checks": ["sqli", "xss", "lfi", "ssrf", "ssl_config", "hsts"],
        "ports": [443, 8443, 4443],
    },
    "ssh": {
        "tools": ["nmap_ssh_audit", "hydra"],
        "checks": ["weak_creds", "old_algorithms", "cve_scan"],
        "ports": [22, 2222],
    },
    "smb": {
        "tools": ["crackmapexec", "enum4linux", "smbclient"],
        "checks": ["null_session", "shares", "ms17_010", "printspooler"],
        "ports": [445, 139],
    },
    "ftp": {
        "tools": ["hydra", "nmap"],
        "checks": ["anonymous_login", "writable_dirs", "bounce_attack"],
        "ports": [21],
    },
    "mysql": {
        "tools": ["hydra", "nmap"],
        "checks": ["default_creds", "remote_access", "udf_exploit"],
        "ports": [3306],
    },
    "mssql": {
        "tools": ["hydra", "nmap", "crackmapexec"],
        "checks": ["default_creds", "xp_cmdshell", "linked_servers"],
        "ports": [1433],
    },
    "postgresql": {
        "tools": ["hydra", "nmap"],
        "checks": ["default_creds", "remote_access"],
        "ports": [5432],
    },
    "rdp": {
        "tools": ["hydra", "nmap"],
        "checks": ["weak_creds", "bluekeep", "nla_bypass"],
        "ports": [3389],
    },
    "smtp": {
        "tools": ["smtp-user-enum", "swaks"],
        "checks": ["open_relay", "user_enum", "spoofing"],
        "ports": [25, 587, 465],
    },
    "dns": {
        "tools": ["dig", "dnsrecon", "dnsx"],
        "checks": ["zone_transfer", "subdomain_takeover"],
        "ports": [53],
    },
    "snmp": {
        "tools": ["snmpwalk", "onesixtyone"],
        "checks": ["default_community", "info_disclosure"],
        "ports": [161],
    },
    "ldap": {
        "tools": ["ldapsearch", "nmap"],
        "checks": ["anonymous_bind", "user_enum"],
        "ports": [389, 636],
    },
    "redis": {
        "tools": ["redis-cli", "nmap"],
        "checks": ["no_auth", "rce_via_config"],
        "ports": [6379],
    },
    "mongodb": {
        "tools": ["mongosh", "nmap"],
        "checks": ["no_auth", "info_disclosure"],
        "ports": [27017],
    },
}


class ServiceRouter:
    """Routes detected services to appropriate scanning tools and checks."""

    def __init__(self) -> None:
        self._routing: dict[str, dict[str, Any]] = copy.deepcopy(DEFAULT_ROUTING)

    def load_from_directory(self, knowledge_dir: Path) -> None:
        """Load custom routing rules from YAML."""
        routing_dir = knowledge_dir / "routing"
        if not routing_dir.is_dir():
            return
        for yaml_file in sorted(routing_dir.glob("*.yaml")):
            try:
                raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError) as exc:
                log.warning("Failed to load routing file %s: %s", yaml_file, exc)
                continue
            if isinstance(raw, dict):
                for svc, data in raw.items():
                    if isinstance(data, dict):
                        self._routing[str(svc).lower().strip()] = copy.deepcopy(data)

    def route(self, service_name: str) -> dict[str, Any]:
        """Get tools and checks for a service, preferring exact then longest match."""
        key = (service_name or "").lower().strip()
        if not key:
            return {"tools": ["nmap", "nuclei"], "checks": ["cve_scan"]}
        # Direct match
        if key in self._routing:
            return copy.deepcopy(self._routing[key])
        # Partial match — prefer longest matching service key (e.g. 'https' over 'http')
        candidates = [
            (svc, data)
            for svc, data in self._routing.items()
            if svc in key or key in svc
        ]
        if candidates:
            _, best_data = max(candidates, key=lambda item: len(item[0]))
            return copy.deepcopy(best_data)
        return {"tools": ["nmap", "nuclei"], "checks": ["cve_scan"]}

    def identify_service_by_port(self, port: int) -> list[str]:
        """Identify likely services for a port number."""
        services = []
        for svc, data in self._routing.items():
            if port in data.get("ports", []):
                services.append(svc)
        return services

    def get_all_services(self) -> list[str]:
        return sorted(self._routing.keys())

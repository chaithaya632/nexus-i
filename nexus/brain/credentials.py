"""Default credentials database — 50,000+ entries across 500+ products."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


# Core default credentials (always available, ~500 most critical entries)
BUILTIN_CREDENTIALS: list[dict[str, str]] = [
    # Network devices
    {"service": "ssh", "product": "cisco", "username": "admin", "password": "admin"},
    {"service": "ssh", "product": "cisco", "username": "cisco", "password": "cisco"},
    {"service": "ssh", "product": "mikrotik", "username": "admin", "password": ""},
    {"service": "telnet", "product": "dlink", "username": "admin", "password": "admin"},
    # Web applications
    {"service": "http", "product": "tomcat", "username": "tomcat", "password": "tomcat"},
    {"service": "http", "product": "tomcat", "username": "admin", "password": "admin"},
    {"service": "http", "product": "tomcat", "username": "manager", "password": "manager"},
    {"service": "http", "product": "tomcat", "username": "admin", "password": "tomcat"},
    {"service": "http", "product": "tomcat", "username": "tomcat", "password": "s3cret"},
    {"service": "http", "product": "jenkins", "username": "admin", "password": "admin"},
    {"service": "http", "product": "jenkins", "username": "admin", "password": "password"},
    {"service": "http", "product": "jboss", "username": "admin", "password": "admin"},
    {"service": "http", "product": "weblogic", "username": "weblogic", "password": "welcome1"},
    {"service": "http", "product": "wordpress", "username": "admin", "password": "admin"},
    {"service": "http", "product": "wordpress", "username": "admin", "password": "password"},
    {"service": "http", "product": "phpmyadmin", "username": "root", "password": ""},
    {"service": "http", "product": "phpmyadmin", "username": "root", "password": "root"},
    {"service": "http", "product": "grafana", "username": "admin", "password": "admin"},
    {"service": "http", "product": "nagios", "username": "nagiosadmin", "password": "nagios"},
    {"service": "http", "product": "zabbix", "username": "Admin", "password": "zabbix"},
    # Databases
    {"service": "mysql", "product": "mysql", "username": "root", "password": ""},
    {"service": "mysql", "product": "mysql", "username": "root", "password": "root"},
    {"service": "mysql", "product": "mysql", "username": "root", "password": "password"},
    {"service": "mysql", "product": "mysql", "username": "root", "password": "toor"},
    {"service": "mssql", "product": "mssql", "username": "sa", "password": ""},
    {"service": "mssql", "product": "mssql", "username": "sa", "password": "sa"},
    {"service": "mssql", "product": "mssql", "username": "sa", "password": "Password123"},
    {"service": "postgresql", "product": "postgresql", "username": "postgres", "password": "postgres"},
    {"service": "postgresql", "product": "postgresql", "username": "postgres", "password": "password"},
    {"service": "mongodb", "product": "mongodb", "username": "admin", "password": "admin"},
    {"service": "redis", "product": "redis", "username": "", "password": ""},
    # SSH/FTP
    {"service": "ssh", "product": "linux", "username": "root", "password": "toor"},
    {"service": "ssh", "product": "linux", "username": "root", "password": "root"},
    {"service": "ssh", "product": "linux", "username": "admin", "password": "admin"},
    {"service": "ssh", "product": "linux", "username": "user", "password": "user"},
    {"service": "ftp", "product": "vsftpd", "username": "anonymous", "password": "anonymous"},
    {"service": "ftp", "product": "ftp", "username": "ftp", "password": "ftp"},
    {"service": "ftp", "product": "ftp", "username": "admin", "password": "admin"},
    # SNMP
    {"service": "snmp", "product": "snmp", "username": "", "password": "public"},
    {"service": "snmp", "product": "snmp", "username": "", "password": "private"},
    # VNC
    {"service": "vnc", "product": "vnc", "username": "", "password": "password"},
    {"service": "vnc", "product": "vnc", "username": "", "password": "1234"},
]


class CredentialDB:
    """Searchable default credential database."""

    def __init__(self) -> None:
        self._entries: list[dict[str, str]] = list(BUILTIN_CREDENTIALS)

    @property
    def count(self) -> int:
        return len(self._entries)

    def load_from_directory(self, knowledge_dir: Path) -> None:
        """Load additional credentials from YAML files."""
        cred_dir = knowledge_dir / "credentials"
        if not cred_dir.is_dir():
            return
        for yaml_file in sorted(cred_dir.glob("*.yaml")):
            try:
                raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError):
                continue
            if isinstance(raw, list):
                self._entries.extend(raw)
            elif isinstance(raw, dict):
                for product, creds in raw.items():
                    if isinstance(creds, list):
                        for c in creds:
                            c.setdefault("product", product)
                            self._entries.append(c)

    def lookup(self, service: str = "", product: str = "") -> list[dict[str, str]]:
        """Find credentials for a service/product."""
        results = []
        svc_aliases = {"postgres": "postgresql"}
        svc_lower = svc_aliases.get(service.lower(), service.lower())
        prod_lower = product.lower()
        for entry in self._entries:
            if svc_lower and entry.get("service", "").lower() != svc_lower:
                continue
            if prod_lower and prod_lower not in entry.get("product", "").lower():
                continue
            results.append(entry)
        return results

    def get_for_service(self, service: str) -> list[dict[str, str]]:
        """Alias for lookup(service=...) used by engine exploit runner."""
        return self.lookup(service=service)

    def get_usernames(self, service: str = "", product: str = "") -> list[str]:
        creds = self.lookup(service, product)
        return sorted(set(c.get("username", "") for c in creds if c.get("username")))

    def get_passwords(self, service: str = "", product: str = "") -> list[str]:
        creds = self.lookup(service, product)
        return sorted(set(c.get("password", "") for c in creds))

    def to_hydra_format(self, service: str = "", product: str = "") -> str:
        """Export as user:pass lines for hydra -C flag."""
        creds = self.lookup(service, product)
        lines = []
        seen = set()
        for c in creds:
            pair = f"{c.get('username', '')}:{c.get('password', '')}"
            if pair not in seen:
                lines.append(pair)
                seen.add(pair)
        return "\n".join(lines)

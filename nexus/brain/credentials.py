"""Default credentials database — built-in core entries with YAML extensibility."""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("nexus.brain.credentials")


# Core default credentials (always available built-in entries)
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
    {
        "service": "postgresql",
        "product": "postgresql",
        "username": "postgres",
        "password": "postgres",
    },
    {
        "service": "postgresql",
        "product": "postgresql",
        "username": "postgres",
        "password": "password",
    },
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
        self._entries: list[dict[str, str]] = copy.deepcopy(BUILTIN_CREDENTIALS)

    @property
    def count(self) -> int:
        return len(self._entries)

    @staticmethod
    def _normalize_entry(raw_entry: Any, default_product: str = "") -> dict[str, str] | None:
        if not isinstance(raw_entry, dict):
            return None
        if "username" not in raw_entry and "password" not in raw_entry:
            return None
        return {
            "service": str(raw_entry.get("service") or "").strip(),
            "product": str(raw_entry.get("product") or default_product).strip(),
            "username": str(
                raw_entry.get("username") if raw_entry.get("username") is not None else ""
            ),
            "password": str(
                raw_entry.get("password") if raw_entry.get("password") is not None else ""
            ),
        }

    def load_from_directory(self, knowledge_dir: Path) -> None:
        """Load additional credentials from YAML files."""
        cred_dir = knowledge_dir / "credentials"
        if not cred_dir.is_dir():
            return
        for yaml_file in sorted(cred_dir.glob("*.yaml")):
            try:
                raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError) as exc:
                log.warning("Failed to load credentials file %s: %s", yaml_file, exc)
                continue
            if isinstance(raw, list):
                for item in raw:
                    norm = self._normalize_entry(item)
                    if norm is not None:
                        self._entries.append(norm)
                    else:
                        log.warning("Skipping invalid credential entry in %s", yaml_file)
            elif isinstance(raw, dict):
                for product, creds in raw.items():
                    if isinstance(creds, list):
                        for item in creds:
                            norm = self._normalize_entry(item, default_product=str(product))
                            if norm is not None:
                                self._entries.append(norm)
                            else:
                                log.warning(
                                    "Skipping invalid credential entry for %s in %s",
                                    product,
                                    yaml_file,
                                )

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
        """Export as user:pass lines for hydra -C flag (skipping empty user/pass pairs)."""
        creds = self.lookup(service, product)
        lines = []
        seen = set()
        for c in creds:
            user = c.get("username", "")
            pw = c.get("password", "")
            if not user or not pw:
                continue
            pair = f"{user}:{pw}"
            if pair not in seen:
                lines.append(pair)
                seen.add(pair)
        return "\n".join(lines)

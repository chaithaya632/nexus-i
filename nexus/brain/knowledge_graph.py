"""CVE Knowledge Graph — 10,000+ service→vulnerability→exploit mappings."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ExploitInfo:
    module: str
    tool: str = ""
    description: str = ""
    reliability: str = "medium"  # low, medium, high


@dataclass
class VulnEntry:
    cve: str
    severity: str = "medium"
    cvss: float = 0.0
    vuln_type: str = ""  # rce, sqli, xss, lfi, auth_bypass, etc.
    description: str = ""
    affected_versions: str = ""
    exploits: list[ExploitInfo] = field(default_factory=list)
    chain_to: list[str] = field(default_factory=list)  # Next attack steps
    remediation: str = ""


@dataclass
class ServiceKnowledge:
    name: str
    fingerprints: list[str] = field(default_factory=list)
    default_ports: list[int] = field(default_factory=list)
    vulns: list[VulnEntry] = field(default_factory=list)
    always_check: list[str] = field(default_factory=list)


class KnowledgeGraph:
    """In-memory CVE knowledge graph loaded from YAML files.

    Provides fast lookups: service → vulnerabilities → exploits → chains.
    """

    def __init__(self) -> None:
        self._services: dict[str, ServiceKnowledge] = {}
        self._cve_index: dict[str, tuple[str, VulnEntry]] = {}  # CVE → (service, entry)
        self._fingerprint_index: dict[str, str] = {}  # fingerprint → service name

    @property
    def service_count(self) -> int:
        return len(self._services)

    @property
    def cve_count(self) -> int:
        return len(self._cve_index)

    @property
    def fingerprint_count(self) -> int:
        return len(self._fingerprint_index)

    def load_from_directory(self, knowledge_dir: Path) -> None:
        """Load all YAML knowledge files from the cves/ subdirectory."""
        cve_dir = knowledge_dir / "cves"
        if not cve_dir.is_dir():
            return
        for yaml_file in sorted(cve_dir.glob("*.yaml")):
            self._load_file(yaml_file)

    def _load_file(self, path: Path) -> None:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            return
        if not isinstance(raw, dict):
            return

        # Format 1: Flat CVE map (used in nexus/brain/knowledge/cves/*.yaml)
        if isinstance(raw.get("cves"), dict):
            self._load_flat_cves(raw["cves"])
            return

        # Format 2: Service-keyed map with version_vulns
        for service_key, service_data in raw.items():
            if not isinstance(service_data, dict):
                continue
            sk = self._services.get(service_key) or ServiceKnowledge(name=service_key)
            for fp in service_data.get("fingerprints", []):
                if fp not in sk.fingerprints:
                    sk.fingerprints.append(fp)
            for port in service_data.get("default_ports", []):
                if port not in sk.default_ports:
                    sk.default_ports.append(port)
            for chk in service_data.get("always_check", []):
                if chk not in sk.always_check:
                    sk.always_check.append(chk)

            for version_range, vuln_list in service_data.get("version_vulns", {}).items():
                if not isinstance(vuln_list, list):
                    continue
                for v in vuln_list:
                    exploits = self._parse_exploits(v.get("exploits", []))
                    entry = VulnEntry(
                        cve=v.get("cve", ""),
                        severity=v.get("severity", "medium"),
                        cvss=float(v.get("cvss", 0.0)),
                        vuln_type=v.get("type", ""),
                        description=v.get("description", ""),
                        affected_versions=version_range,
                        exploits=exploits,
                        chain_to=v.get("chain_to", []),
                        remediation=v.get("remediation", ""),
                    )
                    sk.vulns.append(entry)
                    if entry.cve:
                        self._cve_index[entry.cve.upper()] = (service_key, entry)

            self._services[service_key] = sk
            for fp in sk.fingerprints:
                self._fingerprint_index[fp.lower()] = service_key

    def _load_flat_cves(self, cves_map: dict[str, Any]) -> None:
        """Load the `cves: {CVE-ID: {...}}` YAML schema."""
        for cve_id, cve_data in cves_map.items():
            if not isinstance(cve_data, dict):
                continue
            products = cve_data.get("products", []) or ["generic"]
            fingerprints = cve_data.get("fingerprints", []) or []
            exploit_tools = cve_data.get("exploit_tools", []) or []
            exploits = [
                ExploitInfo(module=t, tool=t)
                for t in exploit_tools
                if isinstance(t, str)
            ]
            # Derive service key from primary product prefix (e.g. "apache-httpd-2.4" -> "apache-httpd")
            primary_service = str(products[0])
            entry = VulnEntry(
                cve=cve_id.upper(),
                severity=cve_data.get("severity", "medium"),
                cvss=float(cve_data.get("cvss", 0.0)),
                vuln_type=cve_data.get("cwe", cve_data.get("type", "")),
                description=cve_data.get("description", ""),
                affected_versions=", ".join(str(p) for p in products),
                exploits=exploits,
                chain_to=cve_data.get("chain_to", []),
                remediation=cve_data.get("remediation", ""),
            )
            self._cve_index[entry.cve] = (primary_service, entry)

            sk = self._services.get(primary_service)
            if sk is None:
                sk = ServiceKnowledge(name=primary_service)
                self._services[primary_service] = sk
            sk.vulns.append(entry)
            for fp in fingerprints:
                if fp not in sk.fingerprints:
                    sk.fingerprints.append(fp)
                self._fingerprint_index[fp.lower()] = primary_service

    @staticmethod
    def _parse_exploits(raw_exploits: list[Any]) -> list[ExploitInfo]:
        exploits: list[ExploitInfo] = []
        for e in raw_exploits:
            if isinstance(e, str):
                exploits.append(ExploitInfo(module=e))
            elif isinstance(e, dict):
                exploits.append(ExploitInfo(**e))
        return exploits

    def lookup_service(self, name: str) -> ServiceKnowledge | None:
        return self._services.get(name) or self._services.get(name.lower().replace(" ", "_"))

    def lookup_cve(self, cve_id: str) -> tuple[str, VulnEntry] | None:
        return self._cve_index.get(cve_id.upper())

    def has_cve(self, cve_id: str) -> bool:
        """Return True if the CVE exists in the loaded knowledge graph."""
        return cve_id.upper() in self._cve_index

    def identify_service(self, banner: str) -> str | None:
        """Match a banner/header string to a known service."""
        banner_lower = banner.lower()
        for fp, svc in self._fingerprint_index.items():
            if fp in banner_lower:
                return svc
        return None

    def get_vulns_for_service(self, service_name: str, version: str = "") -> list[VulnEntry]:
        """Get vulnerabilities for a service, optionally filtered by version."""
        sk = self.lookup_service(service_name)
        if not sk:
            return []
        if not version:
            return sk.vulns
        # Filter by version range (simple string contains for now)
        return [v for v in sk.vulns if not v.affected_versions or version in v.affected_versions]

    def search(self, query: str) -> list[tuple[str, VulnEntry]]:
        """Search CVEs by keyword across all fields."""
        q = query.lower()
        results = []
        for svc_name, sk in self._services.items():
            for v in sk.vulns:
                if (q in v.cve.lower() or q in v.description.lower() or
                        q in v.vuln_type.lower() or q in svc_name.lower()):
                    results.append((svc_name, v))
        return results

    def stats(self) -> dict[str, int]:
        total_exploits = sum(
            len(v.exploits) for sk in self._services.values() for v in sk.vulns
        )
        return {
            "services": self.service_count,
            "cves": self.cve_count,
            "fingerprints": self.fingerprint_count,
            "exploits": total_exploits,
        }

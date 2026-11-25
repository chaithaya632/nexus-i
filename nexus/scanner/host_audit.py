"""Authorized credentialed SSH / local Linux OS package & patch posture auditor."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from pathlib import Path

from nexus.brain.knowledge_graph import KnowledgeGraph
from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner

log = logging.getLogger("nexus.scanner.host_audit")

_SAFE_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_EPOCH_RE = re.compile(r"^\d+:")

# Map common Debian/Ubuntu/RHEL/Alpine package names -> (service_hint, banner_product)
_PKG_MAP: dict[str, tuple[str, str]] = {
    "openssh-server": ("ssh", "OpenSSH"),
    "openssh-client": ("ssh", "OpenSSH"),
    "openssh-clients": ("ssh", "OpenSSH"),
    "openssh": ("ssh", "OpenSSH"),
    "openssl": ("ssl", "OpenSSL"),
    "libssl3": ("ssl", "OpenSSL"),
    "libssl1.1": ("ssl", "OpenSSL"),
    "apache2": ("http", "Apache"),
    "apache2-bin": ("http", "Apache"),
    "httpd": ("http", "Apache"),
    "nginx": ("http", "nginx"),
    "nginx-core": ("http", "nginx"),
    "nginx-full": ("http", "nginx"),
    "mysql-server": ("mysql", "MySQL"),
    "mariadb-server": ("mariadb", "MariaDB"),
    "redis-server": ("redis", "Redis"),
    "redis": ("redis", "Redis"),
    "docker-ce": ("docker", "Docker"),
    "docker.io": ("docker", "Docker"),
    "exim4": ("smtp", "Exim"),
    "exim4-base": ("smtp", "Exim"),
    "exim": ("smtp", "Exim"),
    "samba": ("smb", "Samba"),
    "libc6": ("glibc", "glibc"),
    "glibc": ("glibc", "glibc"),
    "sudo": ("sudo", "sudo"),
    "proftpd-basic": ("ftp", "ProFTPD"),
    "proftpd": ("ftp", "ProFTPD"),
    "vsftpd": ("ftp", "vsftpd"),
    "grafana": ("grafana", "Grafana"),
    "jenkins": ("jenkins", "Jenkins"),
    "gitlab-ce": ("gitlab", "GitLab"),
    "gitlab-ee": ("gitlab", "GitLab"),
    "haproxy": ("http", "HAProxy"),
}

_SEV_STR = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def normalize_pkg_version(raw: str) -> str:
    """Strip distro epochs and packaging suffixes into an upstream version string."""
    s = _EPOCH_RE.sub("", (raw or "").strip())
    # Split off Debian/RPM revision suffix ('2.4.68-2', '3.0.2-0ubuntu1', '1.1.1t-0+deb11u2')
    base = re.split(r"[-+~]", s, maxsplit=1)[0]
    # Strip trailing distro/portable build tags like 'p2' in OpenSSH '10.6p2',
    # while preserving OpenSSL patch letters such as '1.1.1t' or '1.0.2zf'.
    base = re.sub(
        r"(?<=\d)(?:p\d+|(?:ubuntu|deb|el|fc|dfsg|ds)\d*)$", "", base, flags=re.IGNORECASE
    )
    return base.strip()


_normalize_pkg_version = normalize_pkg_version


def _resolve_pkg_service(pkg_name: str) -> tuple[str, str] | None:
    name = pkg_name.lower().strip()
    if name in _PKG_MAP:
        return _PKG_MAP[name]
    if re.match(r"^postgresql-\d+$", name):
        return ("postgresql", "PostgreSQL")
    if re.match(r"^php\d+\.\d+(?:-(?:fpm|cli|cgi|common))?$", name):
        return ("http", "PHP")
    return None


def parse_package_lines(stdout: str) -> list[tuple[str, str]]:
    """Parse `name<TAB>version` lines from `dpkg-query` or `rpm -qa` output."""
    pkgs: list[tuple[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        name, ver = line.split("\t", 1)
        clean_name = name.strip().split(":", 1)[0]  # strip :amd64 multi-arch suffix
        clean_ver = ver.strip()
        if clean_name and clean_ver:
            pkgs.append((clean_name, clean_ver))
    return pkgs


def correlate_installed_packages(
    packages: Iterable[tuple[str, str]],
    knowledge: KnowledgeGraph,
    *,
    host: str = "localhost",
) -> list[Finding]:
    """Correlate installed OS packages against KnowledgeGraph version-bounded CVEs."""
    findings: list[Finding] = []
    seen_pkg_cves: set[tuple[str, str]] = set()

    for pkg_name, raw_ver in packages:
        mapped = _resolve_pkg_service(pkg_name)
        if not mapped:
            continue
        svc_hint, banner_prod = mapped
        clean_ver = normalize_pkg_version(raw_ver)
        # Skip distro wrapper/meta-packages lacking major.minor upstream version (e.g. '2:99', '18+293')
        if not clean_ver or "." not in clean_ver:
            continue
        banner = f"{banner_prod}/{clean_ver}"
        for svc_name, entry in knowledge.match_banner_vulns(svc_hint, banner):
            dedup_key = (pkg_name, entry.cve)
            if dedup_key in seen_pkg_cves:
                continue
            seen_pkg_cves.add(dedup_key)
            findings.append(
                Finding(
                    host=host,
                    port=None,
                    protocol="ssh" if host not in ("localhost", "127.0.0.1", "::1") else "local",
                    title=f"{entry.cve}: Vulnerable Installed Package ({pkg_name} {raw_ver})",
                    description=(
                        f"Credentialed package check found {pkg_name} ({raw_ver}) on {host}, "
                        f"matching {entry.cve} ({entry.description or svc_name}; affected: {entry.affected_versions})."
                    ),
                    severity=_SEV_STR.get(entry.severity.lower(), Severity.MEDIUM),
                    cvss_score=float(entry.cvss or 0.0),
                    cve_ids=[entry.cve],
                    cwe_id=entry.vuln_type if entry.vuln_type.startswith("CWE-") else "CWE-1104",
                    tool_source="host_pkg_audit",
                    evidence=f"Package: {pkg_name}\nInstalled: {raw_ver}\nNormalized: {banner}",
                    remediation=entry.remediation,
                    confirmed=True,
                )
            )
    return findings


async def audit_host_packages(
    host: str,
    *,
    knowledge: KnowledgeGraph | None,
    ssh_user: str | None = None,
    ssh_key_path: str | Path | None = None,
    ssh_port: int = 22,
    local: bool = False,
    timeout: int = 25,
) -> list[Finding]:
    """Run read-only OS package inventory check locally or over explicit authorized SSH."""
    if knowledge is None:
        return []

    raw_output = ""
    if local:
        if ToolRunner.is_available("dpkg-query"):
            out = await ToolRunner.run(
                "dpkg-query", ["-W", "-f", "${Package}\t${Version}\n"], timeout=timeout
            )
            raw_output = out.stdout
        elif ToolRunner.is_available("rpm"):
            out = await ToolRunner.run(
                "rpm", ["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=timeout
            )
            raw_output = out.stdout
    elif ssh_user and ssh_key_path:
        clean_host = (host or "").strip()
        if not clean_host or clean_host.startswith("-") or any(c.isspace() for c in clean_host):
            log.warning("Unsafe host value rejected for SSH host audit: %r", host)
            return []
        if not _SAFE_USER_RE.match(ssh_user.strip()):
            log.warning("Invalid SSH username format rejected for host audit: %r", ssh_user)
            return []
        try:
            port_num = int(ssh_port)
        except (TypeError, ValueError):
            log.warning("Invalid SSH port rejected for host audit: %r", ssh_port)
            return []
        if not (1 <= port_num <= 65535):
            log.warning("Out-of-range SSH port %d rejected for host audit", port_num)
            return []
        key = Path(ssh_key_path)
        if not key.is_file() or not ToolRunner.is_available("ssh"):
            log.warning(
                "SSH key %s or 'ssh' client unavailable; skipping credentialed host audit", key
            )
            return []
        remote_cmd = (
            "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null || "
            "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null"
        )
        args = [
            "-i",
            str(key),
            "-p",
            str(port_num),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
            "--",
            f"{ssh_user.strip()}@{clean_host}",
            remote_cmd,
        ]
        out = await ToolRunner.run("ssh", args, timeout=timeout)
        raw_output = out.stdout

    if not raw_output.strip():
        return []

    packages = parse_package_lines(raw_output)
    findings = correlate_installed_packages(packages, knowledge, host=host)
    log.info(
        "Host package audit on %s: inspected %d packages -> %d CVE match(es)",
        host,
        len(packages),
        len(findings),
    )
    return findings

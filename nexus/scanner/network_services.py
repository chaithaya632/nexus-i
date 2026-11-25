"""Read-only network & datastore misconfiguration auditors (SMB, FTP, Redis, Elasticsearch)."""

from __future__ import annotations

import asyncio
import ftplib
import logging
import socket
import xml.etree.ElementTree as ET
from pathlib import Path

from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner
from nexus.scanner._http import make_http_client

log = logging.getLogger("nexus.scanner.network_services")


def _probe_redis_sync(host: str, port: int, timeout: float = 5.0) -> list[Finding]:
    """Send a single read-only PING to detect unauthenticated Redis exposure."""
    findings: list[Finding] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            resp = sock.recv(256).decode("utf-8", errors="replace").strip()
            if resp.startswith("+PONG"):
                findings.append(Finding(
                    host=host,
                    port=port,
                    protocol="redis",
                    title="Redis: Unauthenticated Access Enabled",
                    description=f"Redis service on {host}:{port} responds to PING (+PONG) without AUTH.",
                    severity=Severity.HIGH,
                    cwe_id="CWE-306",
                    tool_source="redis_probe",
                    evidence="Command: PING -> Response: +PONG",
                    confirmed=True,
                ))
    except OSError as exc:
        log.debug("Redis probe failed for %s:%d: %s", host, port, exc)
    return findings


async def audit_redis(host: str, port: int = 6379, *, timeout: float = 5.0) -> list[Finding]:
    """Audit Redis port for unauthenticated access (read-only PING check)."""
    return await asyncio.to_thread(_probe_redis_sync, host, port, timeout)


def _probe_ftp_anon_sync(host: str, port: int, timeout: float = 6.0) -> list[Finding]:
    """Read-only check whether anonymous FTP login is permitted."""
    findings: list[Finding] = []
    ftp = ftplib.FTP()
    try:
        banner = ftp.connect(host, port, timeout=timeout)
        resp = ftp.login("anonymous", "nexus-audit@local.invalid")
        if resp.startswith("230"):
            findings.append(Finding(
                host=host,
                port=port,
                protocol="ftp",
                title="FTP: Anonymous Login Allowed",
                description=f"FTP service on {host}:{port} accepts anonymous authentication.",
                severity=Severity.MEDIUM,
                cwe_id="CWE-287",
                tool_source="ftp_probe",
                evidence=f"Banner: {banner[:200]}\nLogin response: {resp[:200]}",
                confirmed=True,
            ))
    except (ftplib.all_errors, OSError) as exc:
        log.debug("FTP anonymous check failed/denied for %s:%d: %s", host, port, exc)
    finally:
        try:
            ftp.close()
        except Exception:
            pass
    return findings


def _parse_nmap_ftp_xml(xml_text: str, host: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings
    for script in root.findall(".//script"):
        if script.get("id") == "ftp-anon":
            out = script.get("output", "")
            if "anonymous ftp login allowed" in out.lower():
                findings.append(Finding(
                    host=host,
                    port=port,
                    protocol="ftp",
                    title="FTP: Anonymous Login Allowed",
                    description=f"FTP service on {host}:{port} permits anonymous access.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-287",
                    tool_source="nmap_ftp",
                    evidence=out[:500],
                    confirmed=True,
                ))
    return findings


async def audit_ftp(host: str, port: int = 21, *, timeout: int = 30) -> list[Finding]:
    """Audit FTP service for anonymous authentication using pure-Python probe or nmap."""
    findings = await asyncio.to_thread(_probe_ftp_anon_sync, host, port, min(float(timeout), 8.0))
    if findings:
        return findings
    if ToolRunner.is_available("nmap"):
        xml_path = ToolRunner.make_temp_path(".xml")
        try:
            await ToolRunner.run(
                "nmap", ["-p", str(port), "--script", "ftp-anon", "-oX", xml_path, host], timeout=timeout
            )
            p = Path(xml_path)
            if p.is_file():
                return _parse_nmap_ftp_xml(p.read_text(encoding="utf-8", errors="replace"), host, port)
        finally:
            Path(xml_path).unlink(missing_ok=True)
    return []


def _parse_nmap_smb_xml(xml_text: str, host: str, port: int) -> list[Finding]:
    """Parse nmap `smb2-security-mode,smb-protocols` XML output for signing/SMBv1 issues."""
    findings: list[Finding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for script in root.findall(".//script"):
        sid = script.get("id", "")
        out = script.get("output", "")
        lower = out.lower()
        if sid in ("smb2-security-mode", "smb-security-mode"):
            if "message signing enabled but not required" in lower or "message signing disabled" in lower:
                findings.append(Finding(
                    host=host,
                    port=port,
                    protocol="smb",
                    title="SMB: Message Signing Disabled or Not Required",
                    description=f"SMB service on {host}:{port} does not enforce SMB packet signing (enables relay attacks).",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-300",
                    tool_source="nmap_smb",
                    evidence=out.strip()[:500],
                    confirmed=True,
                ))
        elif sid == "smb-protocols":
            if "nt lm 0.12" in lower or "smbv1" in lower or "2.0.2" in lower and "nt lm 0.12" in lower:
                findings.append(Finding(
                    host=host,
                    port=port,
                    protocol="smb",
                    title="SMB: Legacy SMBv1 Dialect Enabled",
                    description=f"SMB service on {host}:{port} negotiates deprecated SMBv1 (NT LM 0.12).",
                    severity=Severity.HIGH,
                    cwe_id="CWE-326",
                    tool_source="nmap_smb",
                    evidence=out.strip()[:500],
                    confirmed=True,
                ))
    return findings


def _parse_nxc_smb_output(output: str, host: str, port: int) -> list[Finding]:
    """Parse `nxc smb <host>` status line (signing:False, SMBv1:True)."""
    findings: list[Finding] = []
    lower = output.lower()
    if "signing:false" in lower:
        findings.append(Finding(
            host=host,
            port=port,
            protocol="smb",
            title="SMB: Message Signing Disabled or Not Required",
            description=f"SMB service on {host}:{port} does not require SMB signing.",
            severity=Severity.MEDIUM,
            cwe_id="CWE-300",
            tool_source="netexec",
            evidence=output.strip()[:500],
            confirmed=True,
        ))
    if "smbv1:true" in lower:
        findings.append(Finding(
            host=host,
            port=port,
            protocol="smb",
            title="SMB: Legacy SMBv1 Dialect Enabled",
            description=f"SMB service on {host}:{port} enables SMBv1.",
            severity=Severity.HIGH,
            cwe_id="CWE-326",
            tool_source="netexec",
            evidence=output.strip()[:500],
            confirmed=True,
        ))
    return findings


async def audit_smb(host: str, port: int = 445, *, timeout: int = 45) -> list[Finding]:
    """Audit SMB signing enforcement & SMBv1 dialect via NetExec or nmap NSE."""
    nxc_bin = "nxc" if ToolRunner.is_available("nxc") else ("netexec" if ToolRunner.is_available("netexec") else None)
    if nxc_bin:
        out = await ToolRunner.run(nxc_bin, ["smb", host, "--port", str(port)], timeout=timeout)
        findings = _parse_nxc_smb_output(out.stdout + "\n" + out.stderr, host, port)
        if findings:
            return findings

    if ToolRunner.is_available("nmap"):
        xml_path = ToolRunner.make_temp_path(".xml")
        try:
            await ToolRunner.run(
                "nmap",
                ["-p", str(port), "--script", "smb2-security-mode,smb-protocols", "-oX", xml_path, host],
                timeout=timeout,
            )
            p = Path(xml_path)
            if p.is_file():
                return _parse_nmap_smb_xml(p.read_text(encoding="utf-8", errors="replace"), host, port)
        finally:
            Path(xml_path).unlink(missing_ok=True)
    return []


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


async def audit_elasticsearch(host: str, port: int = 9200, *, timeout: float = 6.0) -> list[Finding]:
    """Read-only HTTP check for unauthenticated Elasticsearch cluster API exposure."""
    url = f"http://{_url_host(host)}:{port}/"
    try:
        async with make_http_client(timeout=timeout) as client:
            resp = await client.get(url, follow_redirects=False)
            if resp.status_code == 200 and "cluster_name" in resp.text and "tagline" in resp.text:
                return [
                    Finding(
                        host=host,
                        port=port,
                        protocol="http",
                        title="Elasticsearch: Unauthenticated Cluster API Exposed",
                        description=f"Elasticsearch node at {url} exposes cluster metadata without authentication.",
                        severity=Severity.HIGH,
                        cwe_id="CWE-306",
                        tool_source="es_probe",
                        evidence=resp.text[:400],
                        confirmed=True,
                    )
                ]
    except Exception as exc:
        log.debug("Elasticsearch probe skipped/failed for %s:%d: %s", host, port, exc)
    return []


async def audit_docker_api(host: str, port: int = 2375, *, timeout: float = 6.0) -> list[Finding]:
    """Read-only HTTP check for unauthenticated Docker Engine REST API (TCP 2375)."""
    url = f"http://{_url_host(host)}:{port}/version"
    try:
        async with make_http_client(timeout=timeout) as client:
            resp = await client.get(url, follow_redirects=False)
            if resp.status_code == 200 and "ApiVersion" in resp.text and ("Os" in resp.text or "Components" in resp.text):
                return [
                    Finding(
                        host=host,
                        port=port,
                        protocol="http",
                        title="Docker: Unauthenticated Engine API Exposed",
                        description=f"Docker daemon REST API at {url} responds without TLS client authentication.",
                        severity=Severity.CRITICAL,
                        cwe_id="CWE-306",
                        tool_source="docker_probe",
                        evidence=resp.text[:400],
                        confirmed=True,
                    )
                ]
    except Exception as exc:
        log.debug("Docker API probe skipped/failed for %s:%d: %s", host, port, exc)
    return []


def _probe_memcached_sync(host: str, port: int, timeout: float = 5.0) -> list[Finding]:
    """Send a single read-only `version` command to check unauthenticated Memcached exposure."""
    findings: list[Finding] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"version\r\n")
            resp = sock.recv(256).decode("utf-8", errors="replace").strip()
            if resp.startswith("VERSION "):
                findings.append(Finding(
                    host=host,
                    port=port,
                    protocol="memcached",
                    title="Memcached: Unauthenticated Cache Exposed",
                    description=f"Memcached on {host}:{port} discloses version and accepts unauthenticated commands.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-306",
                    tool_source="memcached_probe",
                    evidence=f"Command: version -> {resp[:200]}",
                    confirmed=True,
                ))
    except OSError as exc:
        log.debug("Memcached probe failed for %s:%d: %s", host, port, exc)
    return findings


async def audit_memcached(host: str, port: int = 11211, *, timeout: float = 5.0) -> list[Finding]:
    """Audit Memcached port for unauthenticated exposure."""
    return await asyncio.to_thread(_probe_memcached_sync, host, port, timeout)


async def audit_network_service(host: str, port: int, service: str = "") -> list[Finding]:
    """Dispatch defensive posture audit for non-HTTP network/datastore ports."""
    svc = service.lower().strip()
    if port == 6379 or "redis" in svc:
        return await audit_redis(host, port)
    if port == 21 or svc == "ftp":
        return await audit_ftp(host, port)
    if port in (445, 139) or "smb" in svc or "microsoft-ds" in svc or "netbios-ssn" in svc:
        return await audit_smb(host, port)
    if port == 9200 or "elastic" in svc:
        return await audit_elasticsearch(host, port)
    if port == 2375 or "docker" in svc:
        return await audit_docker_api(host, port)
    if port == 11211 or "memcache" in svc:
        return await audit_memcached(host, port)
    return []

"""Read-only network & datastore misconfiguration auditors (SMB, FTP, Redis, Elasticsearch)."""

from __future__ import annotations

import asyncio
import ftplib
import logging
import socket
import ssl
import struct
import xml.etree.ElementTree as ET
from pathlib import Path

from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner, safe_parse_xml, validate_cli_target, validate_port
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
                findings.append(
                    Finding(
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
                    )
                )
    except OSError as exc:
        log.debug("Redis probe failed for %s:%d: %s", host, port, exc)
    return findings


async def audit_redis(host: str, port: int = 6379, *, timeout: float = 5.0) -> list[Finding]:
    """Audit Redis port for unauthenticated access (read-only PING check)."""
    return await asyncio.to_thread(_probe_redis_sync, host, port, timeout)


def _probe_ftp_anon_sync(host: str, port: int, timeout: float = 6.0) -> tuple[list[Finding], bool]:
    """Read-only check whether anonymous FTP login is permitted; returns (findings, checked_cleanly)."""
    findings: list[Finding] = []
    checked = False
    ftp = ftplib.FTP()
    try:
        banner = ftp.connect(host, port, timeout=timeout)
        checked = True
        resp = ftp.login("anonymous", "nexus-audit@local.invalid")
        if resp.startswith("230"):
            findings.append(
                Finding(
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
                )
            )
    except ftplib.error_perm as exc:
        checked = True
        log.debug("FTP anonymous login denied for %s:%d: %s", host, port, exc)
    except (ftplib.all_errors, OSError) as exc:
        log.debug("FTP anonymous check failed for %s:%d: %s", host, port, exc)
    finally:
        try:
            ftp.close()
        except Exception:
            pass
    return findings, checked


def _parse_nmap_ftp_xml(xml_text: str, host: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    try:
        root = safe_parse_xml(xml_text)
    except ET.ParseError:
        return findings
    for script in root.findall(".//script"):
        if script.get("id") == "ftp-anon":
            out = script.get("output", "")
            if "anonymous ftp login allowed" in out.lower():
                findings.append(
                    Finding(
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
                    )
                )
    return findings


async def audit_ftp(host: str, port: int = 21, *, timeout: int = 30) -> list[Finding]:
    """Audit FTP service for anonymous authentication using pure-Python probe or nmap."""
    clean_host = validate_cli_target(host, label="host")
    port_num = validate_port(port)
    findings, checked = await asyncio.to_thread(
        _probe_ftp_anon_sync, clean_host, port_num, min(float(timeout), 8.0)
    )
    if findings or checked:
        return findings
    if ToolRunner.is_available("nmap"):
        xml_path = ToolRunner.make_temp_path(".xml")
        try:
            await ToolRunner.run(
                "nmap",
                ["-p", str(port_num), "--script", "ftp-anon", "-oX", xml_path, clean_host],
                timeout=timeout,
            )
            p = Path(xml_path)
            if p.is_file():
                return _parse_nmap_ftp_xml(
                    p.read_text(encoding="utf-8", errors="replace"), clean_host, port_num
                )
        finally:
            Path(xml_path).unlink(missing_ok=True)
    return []


def _parse_nmap_smb_xml(xml_text: str, host: str, port: int) -> list[Finding]:
    """Parse nmap `smb2-security-mode,smb-protocols` XML output for signing/SMBv1 issues."""
    findings: list[Finding] = []
    try:
        root = safe_parse_xml(xml_text)
    except ET.ParseError:
        return findings

    for script in root.findall(".//script"):
        sid = script.get("id", "")
        out = script.get("output", "")
        lower = out.lower()
        if sid in ("smb2-security-mode", "smb-security-mode"):
            if (
                "message signing enabled but not required" in lower
                or "message signing disabled" in lower
            ):
                findings.append(
                    Finding(
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
                    )
                )
        elif sid == "smb-protocols":
            if "nt lm 0.12" in lower or "smbv1" in lower:
                findings.append(
                    Finding(
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
                    )
                )
    return findings


def _parse_nxc_smb_output(output: str, host: str, port: int) -> list[Finding]:
    """Parse `nxc smb <host>` status line (signing:False, SMBv1:True)."""
    findings: list[Finding] = []
    lower = output.lower()
    if "signing:false" in lower:
        findings.append(
            Finding(
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
            )
        )
    if "smbv1:true" in lower:
        findings.append(
            Finding(
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
            )
        )
    return findings


async def audit_smb(host: str, port: int = 445, *, timeout: int = 45) -> list[Finding]:
    """Audit SMB signing enforcement & SMBv1 dialect via NetExec or nmap NSE."""
    clean_host = validate_cli_target(host, label="host")
    port_num = validate_port(port)
    nxc_bin = (
        "nxc"
        if ToolRunner.is_available("nxc")
        else ("netexec" if ToolRunner.is_available("netexec") else None)
    )
    if nxc_bin:
        out = await ToolRunner.run(
            nxc_bin, ["smb", clean_host, "--port", str(port_num)], timeout=timeout
        )
        combined = out.stdout + "\n" + out.stderr
        findings = _parse_nxc_smb_output(combined, clean_host, port_num)
        if findings or out.ok or "signing:" in combined.lower():
            return findings

    if ToolRunner.is_available("nmap"):
        xml_path = ToolRunner.make_temp_path(".xml")
        try:
            await ToolRunner.run(
                "nmap",
                [
                    "-p",
                    str(port_num),
                    "--script",
                    "smb2-security-mode,smb-protocols",
                    "-oX",
                    xml_path,
                    clean_host,
                ],
                timeout=timeout,
            )
            p = Path(xml_path)
            if p.is_file():
                return _parse_nmap_smb_xml(
                    p.read_text(encoding="utf-8", errors="replace"), clean_host, port_num
                )
        finally:
            Path(xml_path).unlink(missing_ok=True)
    return []


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


async def audit_elasticsearch(
    host: str, port: int = 9200, *, timeout: float = 6.0
) -> list[Finding]:
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
            if (
                resp.status_code == 200
                and "ApiVersion" in resp.text
                and ("Os" in resp.text or "Components" in resp.text)
            ):
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
                findings.append(
                    Finding(
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
                    )
                )
    except OSError as exc:
        log.debug("Memcached probe failed for %s:%d: %s", host, port, exc)
    return findings


async def audit_memcached(host: str, port: int = 11211, *, timeout: float = 5.0) -> list[Finding]:
    """Audit Memcached port for unauthenticated exposure."""
    return await asyncio.to_thread(_probe_memcached_sync, host, port, timeout)


def _probe_mongodb_sync(host: str, port: int, timeout: float = 5.0) -> list[Finding]:
    """Send read-only BSON OP_MSG (2013) (`isMaster: 1`) to test unauthenticated MongoDB exposure."""
    # BSON doc: {"isMaster": 1, "$db": "admin"}
    doc_body = (
        b"\x10isMaster\x00"
        + struct.pack("<i", 1)
        + b"\x02$db\x00"
        + struct.pack("<i", 6)
        + b"admin\x00"
    )
    bson_doc = struct.pack("<i", 4 + len(doc_body) + 1) + doc_body + b"\x00"
    # OP_MSG (2013): flagBits(uint32=0) + section kind 0 (\x00) + BSON body
    payload = struct.pack("<I", 0) + b"\x00" + bson_doc
    header = struct.pack("<iiii", 16 + len(payload), 1, 0, 2013)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(header + payload)
            raw = sock.recv(1024)
            low = raw.lower()
            if (
                len(raw) > 20
                and (b"ismaster" in low or b"iswritableprimary" in low)
                and (b"maxbsonobjectsize" in low or b"ok" in low)
            ):
                return [
                    Finding(
                        host=host,
                        port=port,
                        protocol="mongodb",
                        title="MongoDB: Unauthenticated Instance Exposed",
                        description=f"MongoDB on {host}:{port} responds to OP_MSG isMaster metadata queries without authentication.",
                        severity=Severity.HIGH,
                        cwe_id="CWE-306",
                        tool_source="mongodb_probe",
                        confirmed=True,
                        evidence="OP_MSG (2013) admin.$cmd isMaster succeeded without auth",
                    )
                ]
    except OSError as exc:
        log.debug("MongoDB probe failed for %s:%d: %s", host, port, exc)
    return []


async def audit_mongodb(host: str, port: int = 27017, *, timeout: float = 5.0) -> list[Finding]:
    """Audit MongoDB port for unauthenticated exposure."""
    return await asyncio.to_thread(_probe_mongodb_sync, host, port, timeout)


def _inspect_pg_auth_response(resp: bytes, host: str, port: int) -> list[Finding]:
    """Inspect a PostgreSQL StartupMessage response for trust/cleartext auth."""
    if len(resp) >= 9 and resp[:1] == b"R":
        auth_type = struct.unpack("!i", resp[5:9])[0]
        if auth_type == 0:
            return [
                Finding(
                    host=host,
                    port=port,
                    protocol="postgresql",
                    title="PostgreSQL: Passwordless Trust Authentication Enabled",
                    description=f"PostgreSQL on {host}:{port} returned AuthenticationOk (0) without credentials.",
                    severity=Severity.CRITICAL,
                    cwe_id="CWE-306",
                    tool_source="postgres_probe",
                    confirmed=True,
                    evidence="StartupMessage(user=postgres) -> AuthenticationOk (code=0)",
                )
            ]
        if auth_type == 3:
            return [
                Finding(
                    host=host,
                    port=port,
                    protocol="postgresql",
                    title="PostgreSQL: Cleartext Password Authentication Advertised",
                    description=f"PostgreSQL on {host}:{port} requests AuthenticationCleartextPassword (3).",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-523",
                    tool_source="postgres_probe",
                    confirmed=True,
                    evidence="StartupMessage -> AuthenticationCleartextPassword (code=3)",
                )
            ]
    return []


def _probe_postgresql_sync(host: str, port: int, timeout: float = 5.0) -> list[Finding]:
    """Inspect PostgreSQL SSLRequest + StartupMessage auth mode (over TLS when 'S' accepted)."""
    findings: list[Finding] = []
    params = b"user\x00postgres\x00database\x00postgres\x00\x00"
    startup_msg = struct.pack("!II", 8 + len(params), 196608) + params  # Protocol 3.0
    ssl_resp = b""

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack("!II", 8, 80877103))  # SSLRequest
            ssl_resp = sock.recv(8)
            if ssl_resp == b"N":
                findings.append(
                    Finding(
                        host=host,
                        port=port,
                        protocol="postgresql",
                        title="PostgreSQL: SSL/TLS Negotiation Declined",
                        description=f"PostgreSQL on {host}:{port} rejected SSLRequest ('N'), allowing plaintext connections.",
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-319",
                        tool_source="postgres_probe",
                        confirmed=True,
                        evidence="PostgreSQL SSLRequest response: N",
                    )
                )
            elif ssl_resp == b"S":
                # Server accepted SSL: upgrade this socket to TLS so SSL-required pg_hba configs still probe auth mode
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.sendall(startup_msg)
                    resp = ssock.recv(256)
                    findings.extend(_inspect_pg_auth_response(resp, host, port))
                return findings
    except (OSError, ssl.SSLError) as exc:
        log.debug("PostgreSQL SSL probe failed for %s:%d: %s", host, port, exc)
        return findings

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(startup_msg)
            resp = sock.recv(256)
            findings.extend(_inspect_pg_auth_response(resp, host, port))
    except OSError as exc:
        log.debug("PostgreSQL auth probe failed for %s:%d: %s", host, port, exc)
    return findings


async def audit_postgresql(host: str, port: int = 5432, *, timeout: float = 5.0) -> list[Finding]:
    """Audit PostgreSQL port for TLS support and trust/cleartext auth policy."""
    return await asyncio.to_thread(_probe_postgresql_sync, host, port, timeout)


def _probe_mysql_sync(host: str, port: int, timeout: float = 5.0) -> list[Finding]:
    """Read MySQL v10 initial greeting packet to inspect version disclosure and CLIENT_SSL flag."""
    findings: list[Finding] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            pkt = sock.recv(512)
            if len(pkt) < 15 or pkt[4] != 0x0A:
                return findings
            nul_idx = pkt.find(b"\x00", 5)
            if nul_idx == -1 or nul_idx + 17 > len(pkt):
                return findings
            ver = pkt[5:nul_idx].decode("utf-8", errors="replace")
            # Initial handshake: seq(4) + proto(1) + ver\0 + conn_id(4) + scramble1(8) + filler(1) + cap_low(2)
            cap_offset = nul_idx + 1 + 4 + 8 + 1
            if cap_offset + 2 <= len(pkt):
                cap_low = struct.unpack("<H", pkt[cap_offset : cap_offset + 2])[0]
                if not (cap_low & 0x0800):  # CLIENT_SSL
                    findings.append(
                        Finding(
                            host=host,
                            port=port,
                            protocol="mysql",
                            title="MySQL: Server TLS (CLIENT_SSL) Capability Disabled",
                            description=f"MySQL ({ver}) on {host}:{port} does not advertise CLIENT_SSL support.",
                            severity=Severity.MEDIUM,
                            cwe_id="CWE-319",
                            tool_source="mysql_probe",
                            confirmed=True,
                            evidence=f"Server version: {ver}, cap_low=0x{cap_low:04x}",
                        )
                    )
    except OSError as exc:
        log.debug("MySQL probe failed for %s:%d: %s", host, port, exc)
    return findings


async def audit_mysql(host: str, port: int = 3306, *, timeout: float = 5.0) -> list[Finding]:
    """Audit MySQL/MariaDB handshake for TLS capability."""
    return await asyncio.to_thread(_probe_mysql_sync, host, port, timeout)


def _probe_smtp_sync(host: str, port: int, timeout: float = 5.0) -> list[Finding]:
    """Send read-only EHLO to check STARTTLS support and VRFY advertisement."""
    findings: list[Finding] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(512).decode("utf-8", errors="replace")
            if not banner.startswith("220"):
                return findings
            sock.sendall(b"EHLO nexus-audit.local\r\n")
            ehlo = sock.recv(1024).decode("utf-8", errors="replace")
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
            up = ehlo.upper()
            if "250" in up and "STARTTLS" not in up:
                findings.append(
                    Finding(
                        host=host,
                        port=port,
                        protocol="smtp",
                        title="SMTP: STARTTLS Not Advertised",
                        description=f"SMTP service on {host}:{port} did not advertise STARTTLS in EHLO capabilities.",
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-319",
                        tool_source="smtp_probe",
                        confirmed=True,
                        evidence=ehlo.strip()[:300],
                    )
                )
            if "250-VRFY" in up or "250 VRFY" in up:
                findings.append(
                    Finding(
                        host=host,
                        port=port,
                        protocol="smtp",
                        title="SMTP: VRFY Command Enabled",
                        description=f"SMTP service on {host}:{port} advertises the VRFY command.",
                        severity=Severity.LOW,
                        cwe_id="CWE-200",
                        tool_source="smtp_probe",
                        confirmed=True,
                        evidence=ehlo.strip()[:300],
                    )
                )
    except OSError as exc:
        log.debug("SMTP probe failed for %s:%d: %s", host, port, exc)
    return findings


async def audit_smtp(host: str, port: int = 25, *, timeout: float = 5.0) -> list[Finding]:
    """Audit SMTP service for STARTTLS and VRFY capability exposure."""
    return await asyncio.to_thread(_probe_smtp_sync, host, port, timeout)


async def audit_cloud_control_plane(
    host: str, port: int, service: str = "", *, timeout: float = 6.0
) -> list[Finding]:
    """Read-only HTTP checks for unauthenticated Etcd, Consul, and Kubelet APIs."""
    uhost = _url_host(host)
    svc = service.lower().strip()
    is_consul = False
    if port == 2379 or "etcd" in svc:
        url = f"http://{uhost}:{port}/version"
        title, sev, src, sig = (
            "Etcd: Unauthenticated Version/API Exposed",
            Severity.CRITICAL,
            "etcd_probe",
            ("etcdserver",),
        )
    elif port == 8500 or "consul" in svc:
        url = f"http://{uhost}:{port}/v1/status/leader"
        title, sev, src, sig = (
            "HashiCorp Consul: Unauthenticated HTTP API Exposed",
            Severity.HIGH,
            "consul_probe",
            (":",),
        )
        is_consul = True
    elif port == 10255:
        url = f"http://{uhost}:{port}/pods"
        title, sev, src, sig = (
            "Kubernetes: Unauthenticated Kubelet Read-Only Port (10255)",
            Severity.HIGH,
            "kubelet_probe",
            ('"kind"', '"PodList"'),
        )
    elif port == 10250 or "kubelet" in svc:
        url = f"https://{uhost}:{port}/runningpods/"
        title, sev, src, sig = (
            "Kubernetes: Unauthenticated Kubelet API (10250)",
            Severity.CRITICAL,
            "kubelet_probe",
            ('"kind"', '"PodList"'),
        )
    else:
        return []

    try:
        async with make_http_client(timeout=timeout) as client:
            resp = await client.get(url, follow_redirects=False)
            ctype = (resp.headers.get("content-type") or "").lower()
            txt = resp.text or ""
            stripped = txt.strip()
            consul_ok = (not is_consul) or (
                stripped.startswith('"')
                and stripped.endswith('"')
                and len(stripped) <= 64
                and ":" in stripped
            )
            if (
                resp.status_code == 200
                and "text/html" not in ctype
                and consul_ok
                and all(s in txt for s in sig)
            ):
                return [
                    Finding(
                        host=host,
                        port=port,
                        protocol="https" if port == 10250 else "http",
                        title=title,
                        description=f"Control-plane endpoint {url} responded without authentication.",
                        severity=sev,
                        cwe_id="CWE-306",
                        tool_source=src,
                        confirmed=True,
                        evidence=txt[:300],
                    )
                ]
    except Exception as exc:
        log.debug("Cloud control-plane probe skipped/failed for %s:%d: %s", host, port, exc)
    return []


async def audit_network_service(host: str, port: int, service: str = "") -> list[Finding]:
    """Dispatch defensive posture audit for non-HTTP network/datastore/control-plane ports."""
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
    if port == 27017 or "mongo" in svc:
        return await audit_mongodb(host, port)
    if port == 5432 or "postgres" in svc:
        return await audit_postgresql(host, port)
    if port == 3306 or "mysql" in svc or "mariadb" in svc:
        return await audit_mysql(host, port)
    if port in (25, 587) or "smtp" in svc:
        return await audit_smtp(host, port)
    if port in (2379, 8500, 10250, 10255) or any(t in svc for t in ("etcd", "consul", "kubelet")):
        return await audit_cloud_control_plane(host, port, service=svc)
    return []

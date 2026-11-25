"""Unit and live loopback tests for non-destructive network/datastore auditors."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from nexus.db.models import Severity
from nexus.recon.runner import ToolOutput
from nexus.scanner.network_services import (
    _parse_nmap_ftp_xml,
    _parse_nmap_smb_xml,
    _parse_nxc_smb_output,
    audit_docker_api,
    audit_elasticsearch,
    audit_ftp,
    audit_memcached,
    audit_network_service,
    audit_redis,
    audit_smb,
)


def _start_tcp_responder(reply_bytes: bytes) -> tuple[socket.socket, int, threading.Thread]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def _serve() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            with conn:
                conn.settimeout(1.0)
                try:
                    conn.recv(256)
                    conn.sendall(reply_bytes)
                except OSError:
                    pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return srv, port, t


class TestRedisAndElasticsearchProbes:
    @pytest.mark.asyncio
    async def test_audit_redis_flags_pong_and_skips_auth_required(self) -> None:
        srv_open, p_open, _ = _start_tcp_responder(b"+PONG\r\n")
        srv_auth, p_auth, _ = _start_tcp_responder(b"-NOAUTH Authentication required.\r\n")
        try:
            open_findings = await audit_redis("127.0.0.1", p_open, timeout=2.0)
            auth_findings = await audit_redis("127.0.0.1", p_auth, timeout=2.0)
        finally:
            srv_open.close()
            srv_auth.close()

        assert len(open_findings) == 1
        assert open_findings[0].severity == Severity.HIGH
        assert open_findings[0].cwe_id == "CWE-306"
        assert open_findings[0].confirmed is True
        assert auth_findings == []

    @pytest.mark.asyncio
    async def test_audit_elasticsearch_flags_open_cluster_api(self) -> None:
        class _EsHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "name": "node-1",
                    "cluster_name": "nexus-lab",
                    "tagline": "You Know, for Search",
                }).encode())

            def log_message(self, format, *args):
                pass

        srv = HTTPServer(("127.0.0.1", 0), _EsHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            findings = await audit_elasticsearch("127.0.0.1", port, timeout=3.0)
        finally:
            srv.shutdown()
            srv.server_close()

        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-306"
        assert findings[0].tool_source == "es_probe"


class TestFtpAndSmbAuditors:
    @pytest.mark.asyncio
    async def test_audit_ftp_live_anonymous_login_probe(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(2)
        port = srv.getsockname()[1]

        def _fake_ftp() -> None:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                conn.sendall(b"220 Test FTP Server ready\r\n")
                while True:
                    line = conn.recv(256).decode("ascii", errors="ignore").strip().upper()
                    if not line:
                        break
                    if line.startswith("USER "):
                        conn.sendall(b"331 Anonymous access allowed, send identity as password\r\n")
                    elif line.startswith("PASS "):
                        conn.sendall(b"230 Login successful.\r\n")
                    elif line.startswith("QUIT"):
                        conn.sendall(b"221 Goodbye.\r\n")
                        break

        threading.Thread(target=_fake_ftp, daemon=True).start()
        try:
            findings = await audit_ftp("127.0.0.1", port, timeout=5)
        finally:
            srv.close()

        assert len(findings) == 1
        assert findings[0].title == "FTP: Anonymous Login Allowed"
        assert findings[0].cwe_id == "CWE-287"

    def test_parse_nmap_ftp_and_smb_xml(self) -> None:
        ftp_xml = """<nmaprun><host><ports><port portid="21"><script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)" /></port></ports></host></nmaprun>"""
        smb_xml = """<nmaprun><host><ports><port portid="445">
          <script id="smb2-security-mode" output="Message signing enabled but not required" />
          <script id="smb-protocols" output="dialects: NT LM 0.12 (SMBv1)" />
        </port></ports></host></nmaprun>"""
        assert len(_parse_nmap_ftp_xml(ftp_xml, "10.0.0.5", 21)) == 1
        smb_findings = _parse_nmap_smb_xml(smb_xml, "10.0.0.5", 445)
        assert {f.cwe_id for f in smb_findings} == {"CWE-300", "CWE-326"}

    def test_parse_nxc_smb_output(self) -> None:
        raw = "SMB 10.0.0.9 445 DC01 [*] Windows Server (signing:False) (SMBv1:True)"
        findings = _parse_nxc_smb_output(raw, "10.0.0.9", 445)
        assert len(findings) == 2
        assert all(f.tool_source == "netexec" for f in findings)

    @pytest.mark.asyncio
    async def test_audit_smb_uses_nmap_fallback_and_dispatcher_routes(self) -> None:
        smb_xml = """<nmaprun><host><ports><port portid="445"><script id="smb2-security-mode" output="Message signing disabled" /></port></ports></host></nmaprun>"""

        async def _fake_run(tool: str, args: list[str], **_kwargs):
            Path(args[args.index("-oX") + 1]).write_text(smb_xml, encoding="utf-8")
            return ToolOutput(tool=tool, args=args, returncode=0, stdout="", stderr="")

        with (
            patch("nexus.scanner.network_services.ToolRunner.is_available", side_effect=lambda name: name == "nmap"),
            patch("nexus.scanner.network_services.ToolRunner.run", AsyncMock(side_effect=_fake_run)),
        ):
            findings = await audit_network_service("smb.local", 445, "microsoft-ds")

        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-300"

    @pytest.mark.asyncio
    async def test_audit_docker_api_and_memcached(self) -> None:
        class _DockerHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ApiVersion": "1.43", "Os": "linux"}).encode())

            def log_message(self, format, *args):
                pass

        d_srv = HTTPServer(("127.0.0.1", 0), _DockerHandler)
        d_port = d_srv.server_address[1]
        threading.Thread(target=d_srv.serve_forever, daemon=True).start()
        m_srv, m_port, _ = _start_tcp_responder(b"VERSION 1.6.22\r\n")
        try:
            d_findings = await audit_docker_api("127.0.0.1", d_port, timeout=3.0)
            m_findings = await audit_network_service("127.0.0.1", m_port, "memcached")
        finally:
            d_srv.shutdown()
            d_srv.server_close()
            m_srv.close()

        assert len(d_findings) == 1
        assert d_findings[0].severity == Severity.CRITICAL and d_findings[0].tool_source == "docker_probe"
        assert len(m_findings) == 1
        assert m_findings[0].tool_source == "memcached_probe"

    @pytest.mark.asyncio
    async def test_clean_ftp_and_smb_do_not_trigger_duplicate_nmap_rescan(self) -> None:
        # Clean FTP (anonymous denied with 530) must NOT re-run nmap
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(2)
        ftp_port = srv.getsockname()[1]

        def _deny_ftp() -> None:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                conn.sendall(b"220 Secure FTP\r\n")
                while True:
                    line = conn.recv(256).decode("ascii", errors="ignore").strip().upper()
                    if not line:
                        break
                    if line.startswith("USER "):
                        conn.sendall(b"331 Password required\r\n")
                    elif line.startswith("PASS "):
                        conn.sendall(b"530 Login incorrect.\r\n")
                        break

        threading.Thread(target=_deny_ftp, daemon=True).start()
        nmap_mock = AsyncMock()
        try:
            with (
                patch("nexus.scanner.network_services.ToolRunner.is_available", return_value=True),
                patch("nexus.scanner.network_services.ToolRunner.run", nmap_mock),
            ):
                ftp_findings = await audit_ftp("127.0.0.1", ftp_port, timeout=5)
        finally:
            srv.close()

        assert ftp_findings == []
        nmap_mock.assert_not_awaited()

        # Clean SMB from nxc (signing:True, SMBv1:False) must NOT re-run nmap
        nxc_clean = ToolOutput(
            tool="nxc", args=[], returncode=0,
            stdout="SMB 127.0.0.1 445 SRV [*] Windows (signing:True) (SMBv1:False)\n",
            stderr="",
        )
        run_mock = AsyncMock(return_value=nxc_clean)
        with (
            patch("nexus.scanner.network_services.ToolRunner.is_available", return_value=True),
            patch("nexus.scanner.network_services.ToolRunner.run", run_mock),
        ):
            smb_findings = await audit_smb("127.0.0.1", 445)

        assert smb_findings == []
        assert run_mock.await_count == 1
        assert run_mock.await_args.args[0] == "nxc"

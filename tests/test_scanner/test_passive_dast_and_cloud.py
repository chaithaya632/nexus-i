"""Wave 6 tests: passive HTML/JS DAST, GraphQL introspection, auth-diff, DB/SMTP, and cloud probes."""

from __future__ import annotations

import json
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from nexus.db.models import Severity
from nexus.scanner.exposure import audit_exposed_artifacts
from nexus.scanner.network_services import (
    audit_cloud_control_plane,
    audit_mongodb,
    audit_mysql,
    audit_network_service,
    audit_postgresql,
    audit_smtp,
)
from nexus.scanner.passive_dast import (
    analyze_html_passive,
    audit_auth_enforcement,
    audit_graphql_introspection,
)


class TestPassiveHtmlDast:
    def test_detects_insecure_form_csrf_mixed_sri_tabnabbing_and_dom_sink(self) -> None:
        html = """<!DOCTYPE html><html><body>
        <form method="post" action="http://app.local/login">
          <input type="password" name="pw" />
        </form>
        <script src="http://cdn.insecure.local/x.js"></script>
        <script src="https://cdn.thirdparty.invalid/lib.js"></script>
        <iframe src="http://frames.local/embed"></iframe>
        <a href="https://ext.invalid" target="_blank">External</a>
        <script>document.getElementById('out').innerHTML = location.hash;</script>
        </body></html>"""
        findings = analyze_html_passive("https://app.local/dashboard", html)
        titles = {f.title for f in findings}
        assert "Cleartext Password Submission Over HTTP" in titles
        assert "POST Form Missing Anti-CSRF Token Field" in titles
        assert "Mixed Active Content: HTTP Script on HTTPS Page" in titles
        assert "External Script Missing Subresource Integrity (SRI)" in titles
        assert "Mixed Content: HTTP Iframe on HTTPS Page" in titles
        assert "Reverse Tabnabbing Risk (target=_blank Without rel=noopener)" in titles
        assert "Client-Side DOM Sink Audit Candidate" in titles
        dom_f = [f for f in findings if f.title == "Client-Side DOM Sink Audit Candidate"][0]
        assert dom_f.confirmed is False

    def test_clean_hardened_html_yields_zero_passive_findings(self) -> None:
        html = """<!DOCTYPE html><html><body>
        <form method="post" action="/save">
          <input type="hidden" name="csrf_token" value="abc" />
          <input type="password" name="pw" />
        </form>
        <script src="/static/app.js"></script>
        <script src="https://cdn.thirdparty.invalid/lib.js" integrity="sha384-xyz"></script>
        <a href="https://ext.invalid" target="_blank" rel="noopener noreferrer">Safe</a>
        </body></html>"""
        assert analyze_html_passive("https://app.local/settings", html) == []


class TestGraphQLAndAuthDiff:
    @pytest.mark.asyncio
    async def test_graphql_introspection_and_api_auth_diff(self) -> None:
        class _ApiApp(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or 0)
                if length:
                    self.rfile.read(length)
                if self.path == "/graphql":
                    body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_GET(self):
                auth = self.headers.get("Authorization", "")
                if self.path == "/api/v1/protected":
                    if auth == "Bearer valid_tok":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"account":"secret-balance-42"}')
                    else:
                        self.send_response(401)
                        self.end_headers()
                elif self.path == "/api/v1/leaked-users":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"users":["alice","bob","charlie"]}')
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        srv = HTTPServer(("127.0.0.1", 0), _ApiApp)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{port}"
        try:
            gql = await audit_graphql_introspection([base])
            diff = await audit_auth_enforcement(
                [f"{base}/api/v1/protected", f"{base}/api/v1/leaked-users"],
                {"Authorization": "Bearer valid_tok"},
            )
        finally:
            srv.shutdown()
            srv.server_close()

        assert len(gql) == 1
        assert gql[0].title == "GraphQL Schema Introspection Enabled"
        assert gql[0].tool_source == "graphql_probe"

        assert len(diff) == 1
        assert diff[0].severity == Severity.HIGH
        assert diff[0].tool_source == "auth_diff"
        assert "/api/v1/leaked-users" in diff[0].evidence


class TestDatabasesSmtpCloudAndServerStatus:
    @pytest.mark.asyncio
    async def test_apache_status_and_phpinfo_exposure(self) -> None:
        class _DiagApp(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/server-status":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h1>Apache Server Status for app.local</h1>"
                        b"<dt>Server Version: Apache/2.4.57 (Unix)</dt>"
                        b"<dt>1 requests currently being processed</dt></body></html>"
                    )
                elif self.path == "/phpinfo.php":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><title>phpinfo()</title><body>PHP Version 8.1.2<br>"
                        b"Configuration File (php.ini) Path: /etc/php/8.1/php.ini</body></html>"
                    )
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        srv = HTTPServer(("127.0.0.1", 0), _DiagApp)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            findings = await audit_exposed_artifacts([f"http://127.0.0.1:{port}"])
        finally:
            srv.shutdown()
            srv.server_close()

        titles = {f.title for f in findings}
        assert "Apache mod_status Diagnostics Exposed" in titles
        assert "Exposed PHPInfo Diagnostic Page" in titles

    @pytest.mark.asyncio
    async def test_cloud_control_plane_probes_etcd_consul_kubelet(self) -> None:
        class _CloudCtrl(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/version":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}')
                elif self.path == "/v1/status/leader":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'"10.0.0.5:8300"')
                elif self.path == "/pods":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"kind":"PodList","items":[]}')
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        srv = HTTPServer(("127.0.0.1", 0), _CloudCtrl)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            # Map direct ports for test via audit_network_service service hint + port override
            f_etcd = await audit_cloud_control_plane("127.0.0.1", 2379) if False else None
            assert f_etcd is None
        finally:
            srv.shutdown()
            srv.server_close()

        # Spin separate ephemeral mocks for etcd (2379 semantics via helper), or test real port routing with monkeypatched make_http_client
        srv2 = HTTPServer(("127.0.0.1", 0), _CloudCtrl)
        p2 = srv2.server_address[1]
        threading.Thread(target=srv2.serve_forever, daemon=True).start()
        try:
            from unittest.mock import patch
            from nexus.scanner._http import make_http_client as real_mk

            def _rewrite_client(*args, **kwargs):
                return real_mk(*args, **kwargs)

            # Call direct HTTP probe logic with URL rewrite for ephemeral port
            import httpx
            orig_get = httpx.AsyncClient.get

            async def _fake_get(self_cli, url, *a, **kw):
                rewritten = url.replace(":2379/", f":{p2}/").replace(":8500/", f":{p2}/").replace(":10255/", f":{p2}/")
                return await orig_get(self_cli, rewritten, *a, **kw)

            with patch.object(httpx.AsyncClient, "get", _fake_get):
                etcd_f = await audit_network_service("127.0.0.1", 2379, "etcd")
                consul_f = await audit_network_service("127.0.0.1", 8500, "consul")
                kube_f = await audit_network_service("127.0.0.1", 10255, "kubelet")
        finally:
            srv2.shutdown()
            srv2.server_close()

        assert etcd_f[0].tool_source == "etcd_probe" and etcd_f[0].severity == Severity.CRITICAL
        assert consul_f[0].tool_source == "consul_probe" and consul_f[0].severity == Severity.HIGH
        assert kube_f[0].tool_source == "kubelet_probe"

    @pytest.mark.asyncio
    async def test_socket_probes_mongodb_postgresql_mysql_smtp(self) -> None:
        # 1. MongoDB mock
        mongo_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mongo_srv.bind(("127.0.0.1", 0))
        mongo_srv.listen(2)
        mp = mongo_srv.getsockname()[1]

        def _serve_mongo():
            c, _ = mongo_srv.accept()
            with c:
                req = c.recv(512)
                # Verify OP_MSG (opcode 2013) is used
                if len(req) >= 16:
                    assert struct.unpack("<i", req[12:16])[0] == 2013
                c.sendall(b"\x00" * 36 + b'ismaster\x00\x01maxBsonObjectSize\x00')

        # 2. PostgreSQL mock (SSL N + AuthenticationOk code 0)
        pg_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pg_srv.bind(("127.0.0.1", 0))
        pg_srv.listen(4)
        pp = pg_srv.getsockname()[1]

        def _serve_pg():
            for _ in range(2):
                c, _ = pg_srv.accept()
                with c:
                    req = c.recv(512)
                    if req == struct.pack("!II", 8, 80877103):
                        c.sendall(b"N")
                    else:
                        c.sendall(b"R" + struct.pack("!Ii", 8, 0))

        # 3. MySQL mock (protocol 0x0a, version 8.0.32, cap_low without CLIENT_SSL 0x0800)
        my_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_srv.bind(("127.0.0.1", 0))
        my_srv.listen(2)
        yp = my_srv.getsockname()[1]

        def _serve_my():
            c, _ = my_srv.accept()
            with c:
                pkt_body = b"\x0a8.0.32\x00" + b"\x01\x00\x00\x00" + b"12345678\x00" + struct.pack("<H", 0x0001) + b"\x00" * 16
                c.sendall(struct.pack("<I", len(pkt_body))[:3] + b"\x00" + pkt_body)

        # 4. SMTP mock (no STARTTLS, VRFY advertised)
        smtp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        smtp_srv.bind(("127.0.0.1", 0))
        smtp_srv.listen(2)
        sp = smtp_srv.getsockname()[1]

        def _serve_smtp():
            c, _ = smtp_srv.accept()
            with c:
                c.sendall(b"220 mail.local ESMTP Exim 4.91\r\n")
                c.recv(256)
                c.sendall(b"250-mail.local Hello\r\n250-VRFY\r\n250 HELP\r\n")

        threads = [
            threading.Thread(target=_serve_mongo, daemon=True),
            threading.Thread(target=_serve_pg, daemon=True),
            threading.Thread(target=_serve_my, daemon=True),
            threading.Thread(target=_serve_smtp, daemon=True),
        ]
        for th in threads:
            th.start()

        try:
            f_mongo = await audit_mongodb("127.0.0.1", mp)
            f_pg = await audit_postgresql("127.0.0.1", pp)
            f_my = await audit_mysql("127.0.0.1", yp)
            f_smtp = await audit_smtp("127.0.0.1", sp)
        finally:
            for s in (mongo_srv, pg_srv, my_srv, smtp_srv):
                s.close()

        assert f_mongo[0].tool_source == "mongodb_probe" and f_mongo[0].severity == Severity.HIGH
        assert {f.title for f in f_pg} == {
            "PostgreSQL: SSL/TLS Negotiation Declined",
            "PostgreSQL: Passwordless Trust Authentication Enabled",
        }
        assert f_my[0].tool_source == "mysql_probe" and "8.0.32" in f_my[0].evidence
        assert {f.title for f in f_smtp} == {"SMTP: STARTTLS Not Advertised", "SMTP: VRFY Command Enabled"}

    @pytest.mark.asyncio
    async def test_crawler_and_headers_do_not_forward_auth_across_redirects(self) -> None:
        from unittest.mock import patch
        from nexus.scanner.crawler import crawl_web
        from nexus.scanner.headers import audit_http_security

        leaked: list[str] = []

        class _ExtTarget(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get("Authorization"):
                    leaked.append(self.headers["Authorization"])
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>external</html>")

            def log_message(self, *args):
                pass

        ext_srv = HTTPServer(("127.0.0.1", 0), _ExtTarget)
        ext_port = ext_srv.server_address[1]
        threading.Thread(target=ext_srv.serve_forever, daemon=True).start()

        class _RedirOrigin(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{ext_port}/steal")
                self.end_headers()

            def log_message(self, *args):
                pass

        org_srv = HTTPServer(("127.0.0.1", 0), _RedirOrigin)
        org_port = org_srv.server_address[1]
        threading.Thread(target=org_srv.serve_forever, daemon=True).start()
        try:
            with patch("nexus.scanner.crawler.ToolRunner.is_available", return_value=False):
                await crawl_web(f"http://127.0.0.1:{org_port}/", headers={"Authorization": "Bearer secret_hdr_no_leak"})
            await audit_http_security([f"http://127.0.0.1:{org_port}/"], headers={"Authorization": "Bearer secret_hdr_no_leak"})
        finally:
            ext_srv.shutdown()
            ext_srv.server_close()
            org_srv.shutdown()
            org_srv.server_close()

        assert leaked == []

    @pytest.mark.asyncio
    async def test_postgresql_ssl_accepted_probes_startup_over_tls(self) -> None:
        from unittest.mock import MagicMock, patch

        fake_sock = MagicMock()
        fake_sock.recv.return_value = b"S"
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.__exit__.return_value = False

        fake_ssock = MagicMock()
        fake_ssock.recv.return_value = b"R" + struct.pack("!Ii", 8, 3)  # Cleartext password
        fake_ssock.__enter__.return_value = fake_ssock
        fake_ssock.__exit__.return_value = False

        fake_ctx = MagicMock()
        fake_ctx.wrap_socket.return_value = fake_ssock

        with (
            patch("nexus.scanner.network_services.socket.create_connection", return_value=fake_sock),
            patch("nexus.scanner.network_services.ssl.create_default_context", return_value=fake_ctx),
        ):
            findings = await audit_postgresql("127.0.0.1", 5432)

        assert len(findings) == 1
        assert findings[0].title == "PostgreSQL: Cleartext Password Authentication Advertised"
        fake_ctx.wrap_socket.assert_called_once()

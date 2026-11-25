"""Unit tests for TLS and SSH defensive configuration auditors."""

from __future__ import annotations

import json
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexus.db.models import Severity
from nexus.recon.runner import ToolOutput
from nexus.scanner.ssh_audit import (
    _parse_nmap_ssh_xml,
    _parse_ssh_audit_json,
    audit_ssh,
)
from nexus.scanner.tls import (
    _parse_sslyze_json,
    _stdlib_tls_probe,
    audit_tls,
)


class TestTlsAuditor:
    """Tests for sslyze JSON parser, stdlib TLS fallback, and audit_tls dispatch."""

    def test_parse_sslyze_json_detects_weak_proto_heartbleed_and_expired_cert(self) -> None:
        past_date = (datetime.now(UTC) - timedelta(days=10)).isoformat()
        payload = {
            "server_scan_results": [
                {
                    "scan_result": {
                        "tls_1_0_cipher_suites": {
                            "result": {
                                "accepted_cipher_suites": [
                                    {"cipher_suite": {"name": "TLS_RSA_WITH_AES_128_CBC_SHA"}}
                                ]
                            }
                        },
                        "ssl_3_0_cipher_suites": {
                            "result": {
                                "accepted_cipher_suites": [{"cipher_suite": {"name": "SSL_RSA"}}]
                            }
                        },
                        "heartbleed": {"result": {"is_vulnerable_to_heartbleed": True}},
                        "certificate_info": {
                            "result": {
                                "certificate_deployments": [
                                    {
                                        "received_certificate_chain": [
                                            {"not_valid_after": past_date}
                                        ],
                                        "path_validation_results": [
                                            {
                                                "was_validation_successful": False,
                                                "validation_error": "self-signed certificate",
                                                "trust_store": {"name": "Mozilla"},
                                            }
                                        ],
                                    }
                                ]
                            }
                        },
                    }
                }
            ]
        }

        findings = _parse_sslyze_json(json.dumps(payload), "tls.local", 443)
        titles = [f.title for f in findings]
        assert any("SSLv3" in t for t in titles)
        assert any("TLS 1.0" in t for t in titles)
        assert any("Heartbleed" in t for t in titles)
        assert any("Expired" in t for t in titles)
        assert any("Untrusted" in t for t in titles)
        assert all(f.tool_source == "sslyze" for f in findings)

    def test_stdlib_tls_probe_flags_deprecated_proto_and_expiring_cert(self) -> None:
        soon = (datetime.now(UTC) + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
        fake_ssock = MagicMock()
        fake_ssock.getpeercert.return_value = {"notAfter": soon}
        fake_ssock.version.return_value = "TLSv1"
        fake_ssock.__enter__.return_value = fake_ssock
        fake_ssock.__exit__.return_value = False

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.__exit__.return_value = False

        fake_ctx = MagicMock()
        fake_ctx.wrap_socket.return_value = fake_ssock

        with (
            patch("nexus.scanner.tls.ssl.create_default_context", return_value=fake_ctx),
            patch("nexus.scanner.tls.socket.create_connection", return_value=fake_sock),
        ):
            findings = _stdlib_tls_probe("legacy.local", 8443)

        titles = [f.title for f in findings]
        assert any("Deprecated Protocol" in t for t in titles)
        assert any("Expiring Soon" in t for t in titles)
        assert all(f.port == 8443 for f in findings)

    def test_stdlib_tls_probe_flags_cert_verification_error(self) -> None:
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.__exit__.return_value = False

        fake_ctx = MagicMock()
        fake_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("certificate verify failed")

        with (
            patch("nexus.scanner.tls.ssl.create_default_context", return_value=fake_ctx),
            patch("nexus.scanner.tls.socket.create_connection", return_value=fake_sock),
        ):
            findings = _stdlib_tls_probe("selfsigned.local", 443)

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].cwe_id == "CWE-295"

    def test_stdlib_tls_probe_continues_after_cert_verification_error(self) -> None:
        soon = (datetime.now(UTC) + timedelta(days=3)).strftime("%b %d %H:%M:%S %Y GMT")
        fake_ssock = MagicMock()
        fake_ssock.getpeercert.return_value = {"notAfter": soon}
        fake_ssock.version.return_value = "TLSv1.1"
        fake_ssock.__enter__.return_value = fake_ssock
        fake_ssock.__exit__.return_value = False

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.__exit__.return_value = False

        verified_ctx = MagicMock()
        verified_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("self-signed")
        unverified_ctx = MagicMock()
        unverified_ctx.wrap_socket.return_value = fake_ssock

        with (
            patch(
                "nexus.scanner.tls.ssl.create_default_context",
                side_effect=[verified_ctx, unverified_ctx],
            ),
            patch("nexus.scanner.tls.socket.create_connection", return_value=fake_sock),
        ):
            findings = _stdlib_tls_probe("selfsigned.local", 443)

        titles = [f.title for f in findings]
        assert any("Certificate Verification Failed" in t for t in titles)
        assert any("Deprecated Protocol" in t for t in titles)
        assert any("Expiring Soon" in t for t in titles)

    @pytest.mark.asyncio
    async def test_audit_tls_uses_sslyze_when_available(self) -> None:
        sample = {
            "server_scan_results": [
                {
                    "scan_result": {
                        "tls_1_1_cipher_suites": {
                            "result": {
                                "accepted_cipher_suites": [{"cipher_suite": {"name": "TLS_AES"}}]
                            }
                        }
                    }
                }
            ]
        }

        async def _fake_run(tool: str, args: list[str], timeout: int = 120):
            out_idx = args.index("--json_out") + 1
            Path(args[out_idx]).write_text(json.dumps(sample), encoding="utf-8")
            return ToolOutput(tool=tool, args=args, returncode=0, stdout="", stderr="")

        with (
            patch("nexus.scanner.tls.ToolRunner.is_available", return_value=True),
            patch("nexus.scanner.tls.ToolRunner.run", AsyncMock(side_effect=_fake_run)),
        ):
            findings = await audit_tls("example.local", 443)

        assert len(findings) == 1
        assert "TLS 1.1" in findings[0].title

    @pytest.mark.asyncio
    async def test_audit_tls_falls_back_to_stdlib_when_sslyze_absent(self) -> None:
        with (
            patch("nexus.scanner.tls.ToolRunner.is_available", return_value=False),
            patch("nexus.scanner.tls._stdlib_tls_probe", return_value=[]) as mock_probe,
        ):
            findings = await audit_tls("fallback.local", 8443)

        assert findings == []
        mock_probe.assert_called_once_with("fallback.local", 8443)


class TestSshAuditor:
    """Tests for ssh-audit JSON parser, nmap SSH NSE XML parser, and audit_ssh dispatch."""

    def test_parse_ssh_audit_json_extracts_weak_algos_and_cves(self) -> None:
        data = {
            "banner": {"raw": "SSH-2.0-OpenSSH_7.4"},
            "kex": [{"algorithm": "diffie-hellman-group1-sha1", "notes": {"fail": ["removed"]}}],
            "enc": [{"algorithm": "aes128-cbc", "notes": {"warn": ["weak CBC mode"]}}],
            "cves": [{"name": "CVE-2018-15473", "cvssv2": 5.0, "description": "User enumeration"}],
        }
        findings = _parse_ssh_audit_json(json.dumps(data), "ssh.local", 22)
        assert len(findings) == 2
        assert "Weak/Deprecated" in findings[0].title
        assert findings[1].cve_ids == ["CVE-2018-15473"]

    def test_parse_nmap_ssh_xml_detects_weak_algos_and_password_auth(self) -> None:
        xml_sample = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <script id="ssh2-enum-algos" output="kex_algorithms: diffie-hellman-group14-sha1&#10;mac_algorithms: hmac-sha1" />
        <script id="ssh-auth-methods" output="Supported authentication methods: publickey, password" />
      </port>
    </ports>
  </host>
</nmaprun>"""
        findings = _parse_nmap_ssh_xml(xml_sample, "ssh.local", 2222)
        assert len(findings) == 2
        titles = [f.title for f in findings]
        assert any("Weak Cryptographic Algorithms" in t for t in titles)
        assert any("Password Authentication" in t for t in titles)
        assert all(f.port == 2222 and f.tool_source == "nmap_ssh" for f in findings)

    @pytest.mark.asyncio
    async def test_audit_ssh_uses_nmap_fallback_when_ssh_audit_missing(self) -> None:
        xml_sample = """<?xml version="1.0"?>
<nmaprun><host><ports><port protocol="tcp" portid="22">
  <script id="ssh-auth-methods" output="password" />
</port></ports></host></nmaprun>"""

        async def _fake_run(tool: str, args: list[str], timeout: int = 60):
            xml_idx = args.index("-oX") + 1
            Path(args[xml_idx]).write_text(xml_sample, encoding="utf-8")
            return ToolOutput(tool=tool, args=args, returncode=0, stdout="", stderr="")

        with (
            patch(
                "nexus.scanner.ssh_audit.ToolRunner.is_available",
                side_effect=lambda name: name == "nmap",
            ),
            patch("nexus.scanner.ssh_audit.ToolRunner.run", AsyncMock(side_effect=_fake_run)),
        ):
            findings = await audit_ssh("kali.local", 22)

        assert len(findings) == 1
        assert "Password Authentication" in findings[0].title

    @pytest.mark.asyncio
    async def test_audit_tls_validates_host_and_port(self) -> None:
        from nexus.scanner.tls import audit_tls

        with pytest.raises(ValueError):
            await audit_tls("-evil.example.com", 443)
        with pytest.raises(ValueError):
            await audit_tls("example.com", 70000)

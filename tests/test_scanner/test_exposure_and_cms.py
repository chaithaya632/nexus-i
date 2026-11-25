"""Wave 5 tests: signature-verified exposure checks and passive WPScan parser."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from nexus.db.models import Severity
from nexus.recon.runner import ToolOutput
from nexus.scanner.cms_scan import _parse_wpscan_json, wpscan_audit
from nexus.scanner.exposure import audit_exposed_artifacts


class TestSignatureVerifiedExposure:
    @pytest.mark.asyncio
    async def test_live_verified_git_and_dotenv_masking(self) -> None:
        class _ExposedApp(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/.git/HEAD":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"ref: refs/heads/main\n")
                elif self.path == "/.env":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"APP_ENV=production\nDB_PASSWORD=super_secret_pw_99\n")
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass

        srv = HTTPServer(("127.0.0.1", 0), _ExposedApp)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            findings = await audit_exposed_artifacts([f"http://127.0.0.1:{port}"])
        finally:
            srv.shutdown()
            srv.server_close()

        assert len(findings) == 2
        by_title = {f.title: f for f in findings}
        git_f = by_title["Exposed Git Repository (/.git/HEAD)"]
        env_f = by_title["Exposed Environment File (/.env)"]
        assert git_f.severity == Severity.HIGH and git_f.confirmed is True
        assert env_f.severity == Severity.CRITICAL and env_f.confirmed is True
        assert "DB_PASSWORD=***" in env_f.evidence
        assert "super_secret_pw_99" not in env_f.evidence

    @pytest.mark.asyncio
    async def test_spa_html_200_catchall_yields_zero_false_positives(self) -> None:
        class _SpaCatchAll(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<!DOCTYPE html><html><body><div id='app'></div></body></html>")

            def log_message(self, format, *args):
                pass

        srv = HTTPServer(("127.0.0.1", 0), _SpaCatchAll)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            findings = await audit_exposed_artifacts([f"http://127.0.0.1:{port}"])
        finally:
            srv.shutdown()
            srv.server_close()

        assert findings == []


class TestWpScanAuditor:
    def test_parse_wpscan_json_extracts_vulns_plugins_and_users(self) -> None:
        sample = {
            "version": {
                "number": "5.9.1",
                "status": "outdated",
                "vulnerabilities": [{"title": "Core XSS", "references": {"cve": ["2022-21661"]}}],
            },
            "plugins": {
                "wp-automatic": {
                    "version": {"number": "3.92.0"},
                    "vulnerabilities": [{"title": "SQLi", "references": {"cve": ["2024-27956"]}}],
                },
                "akismet": {"version": {"number": "4.0"}, "outdated": True, "latest_version": "5.3", "vulnerabilities": []},
            },
            "users": {"admin": {"id": 1}},
        }
        findings = _parse_wpscan_json(json.dumps(sample), "https://wp.local")
        titles = [f.title for f in findings]
        assert any("WordPress 5.9.1" in t for t in titles)
        assert any("wp-automatic" in t for t in titles)
        assert any("Outdated WordPress Plugin: akismet" in t for t in titles)
        assert any("User Enumeration" in t for t in titles)

    @pytest.mark.asyncio
    async def test_wpscan_audit_passes_stealth_and_cookie(self) -> None:
        sample = {"users": {"editor": {"id": 2}}}

        async def _fake_run(tool: str, args: list[str], **_kwargs):
            out_path = args[args.index("-o") + 1]
            Path(out_path).write_text(json.dumps(sample), encoding="utf-8")
            return ToolOutput(tool=tool, args=args, returncode=0, stdout="", stderr="")

        with (
            patch("nexus.scanner.cms_scan.ToolRunner.is_available", return_value=True),
            patch("nexus.scanner.cms_scan.ToolRunner.run", AsyncMock(side_effect=_fake_run)) as mock_run,
        ):
            findings = await wpscan_audit("https://wp.local", stealth="quiet", headers={"Cookie": "wp_test=1"})

        assert len(findings) == 1
        args = mock_run.call_args.args[1]
        assert "--stealthy" in args
        assert "--no-update" in args
        assert "p,u" in args
        assert "wp_test=1" in args

    @pytest.mark.asyncio
    async def test_wpscan_audit_passes_api_token_and_runner_redacts_secrets(self, monkeypatch) -> None:
        from nexus.recon.runner import _redact_args

        monkeypatch.setenv("WPSCAN_API_TOKEN", "wpvuln_secret_123")
        sample = {"users": {"admin": {"id": 1}}}

        async def _fake_run(tool: str, args: list[str], **_kwargs):
            out_path = args[args.index("-o") + 1]
            Path(out_path).write_text(json.dumps(sample), encoding="utf-8")
            return ToolOutput(tool=tool, args=_redact_args(args), returncode=0, stdout="", stderr="")

        with (
            patch("nexus.scanner.cms_scan.ToolRunner.is_available", return_value=True),
            patch("nexus.scanner.cms_scan.ToolRunner.run", AsyncMock(side_effect=_fake_run)) as mock_run,
        ):
            await wpscan_audit("https://wp.local", headers={"Cookie": "session=abc"})

        raw_args = mock_run.call_args.args[1]
        assert "--api-token" in raw_args
        assert "wpvuln_secret_123" in raw_args
        assert "vp,u" in raw_args
        redacted = _redact_args([*raw_args, "-H", "Authorization: Bearer tok_xyz"])
        assert "wpvuln_secret_123" not in redacted
        assert "session=abc" not in redacted
        assert "tok_xyz" not in " ".join(redacted)
        assert "***" in redacted

    @pytest.mark.asyncio
    async def test_wpscan_audit_retries_without_no_update_when_db_missing(self) -> None:
        calls: list[list[str]] = []

        async def _fake_run(tool: str, args: list[str], **_kwargs):
            calls.append(list(args))
            out_path = args[args.index("-o") + 1]
            payload = (
                {"scan_aborted": "Update required, you can not run a scan if a database file is missing."}
                if "--no-update" in args
                else {"users": {"wpadmin": {"id": 1}}}
            )
            Path(out_path).write_text(json.dumps(payload), encoding="utf-8")
            return ToolOutput(tool=tool, args=[], returncode=4 if "--no-update" in args else 0, stdout="", stderr="")

        with (
            patch("nexus.scanner.cms_scan.ToolRunner.is_available", return_value=True),
            patch("nexus.scanner.cms_scan.ToolRunner.run", AsyncMock(side_effect=_fake_run)),
        ):
            findings = await wpscan_audit("https://wp.local")

        assert len(calls) == 2
        assert "--no-update" in calls[0]
        assert "--no-update" not in calls[1]
        assert len(findings) == 1

    def test_parse_wpscan_json_without_api_token_flags_insecure_core_and_plugins(self) -> None:
        sample = {
            "version": {"number": "6.4.2", "status": "insecure", "vulnerabilities": []},
            "plugins": {
                "contact-form-7": {
                    "version": None,
                    "outdated": False,
                    "latest_version": "6.2.6",
                    "directory_listing": True,
                    "location": "https://wp.local/wp-content/plugins/contact-form-7/",
                    "vulnerabilities": [],
                }
            },
        }
        findings = _parse_wpscan_json(json.dumps(sample), "https://wp.local")
        titles = [f.title for f in findings]
        assert any("WordPress Core Insecure: 6.4.2" in t for t in titles)
        assert any("WordPress Plugin Detected: contact-form-7" in t for t in titles)
        assert any("Directory Listing Enabled: contact-form-7" in t for t in titles)

    def test_wpscan_null_cve_and_runner_nikto_redaction_and_actuator_masking(self) -> None:
        from nexus.recon.runner import _redact_args
        from nexus.scanner.exposure import _verify_actuator_env

        # WPScan JSON with references.cve == null must not crash
        sample = {"version": {"number": "6.0", "vulnerabilities": [{"title": "XSS", "references": {"cve": None}}]}}
        findings = _parse_wpscan_json(json.dumps(sample), "https://wp.local")
        assert len(findings) == 1 and findings[0].cve_ids == []

        # Nikto -Add-header and sensitive custom headers redacted; -h left untouched
        redacted = _redact_args([
            "-h", "target.local", "-Add-header", "Proxy-Authorization: Basic dXNlcjpwYXNz",
            "-Add-header=X-Secret: top_sec",
        ])
        raw_joined = " ".join(redacted)
        assert "dXNlcjpwYXNz" not in raw_joined
        assert "top_sec" not in raw_joined
        assert "-h target.local" in raw_joined

        # /actuator/env masks values while reporting propertySources names
        env_body = json.dumps({"propertySources": [{"name": "applicationConfig", "properties": {"db.pw": {"value": "s3cr3t"}}}]})
        ev = _verify_actuator_env(env_body, "application/json")
        assert ev is not None and "applicationConfig" in ev and "s3cr3t" not in ev

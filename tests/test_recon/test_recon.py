"""Tests for the base ToolRunner and recon module imports."""

import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from nexus.recon.runner import ToolRunner, ToolNotFoundError, ToolOutput


# ── ToolRunner unit tests ─────────────────────────────────────────


def test_tool_output_ok():
    out = ToolOutput(tool="echo", args=["hi"], returncode=0, stdout="hi\n", stderr="")
    assert out.ok is True
    assert out.lines == ["hi"]


def test_tool_output_fail():
    out = ToolOutput(tool="false", args=[], returncode=1, stdout="", stderr="err")
    assert out.ok is False


def test_is_available_known_tool():
    # 'python' should always be in PATH on the test machine
    assert ToolRunner.is_available("python") is True


def test_is_available_missing_tool():
    assert ToolRunner.is_available("nexus_nonexistent_tool_xyz") is False


def test_require_missing_raises():
    with pytest.raises(ToolNotFoundError):
        ToolRunner.require("nexus_nonexistent_tool_xyz")


def test_make_temp_path():
    path = ToolRunner.make_temp_path(".xml")
    assert path.endswith(".xml")
    import os
    os.unlink(path)


@pytest.mark.asyncio
async def test_run_simple_command():
    """Run a real command ('python --version') to verify async subprocess."""
    out = await ToolRunner.run("python", ["--version"], timeout=10)
    assert out.ok
    assert "Python" in out.stdout or "Python" in out.stderr


@pytest.mark.asyncio
async def test_run_nonexistent_tool():
    with pytest.raises(ToolNotFoundError):
        await ToolRunner.run("nexus_nonexistent_tool_xyz", [], timeout=5)


# ── Nmap XML parser tests ────────────────────────────────────────

from nexus.recon.ports import _parse_nmap_xml

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.x" accuracy="95"/></os>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_targets():
    result = _parse_nmap_xml(SAMPLE_NMAP_XML)
    assert len(result["targets"]) == 1
    t = result["targets"][0]
    assert t.ip == "192.168.1.1"
    assert t.host == "router.local"
    assert t.is_live is True
    assert t.os_guess == "Linux 5.x"


def test_parse_nmap_xml_ports():
    result = _parse_nmap_xml(SAMPLE_NMAP_XML)
    # Only open ports (22, 80) — 443 is closed
    assert len(result["ports"]) == 2
    port_nums = {p.port for p in result["ports"]}
    assert port_nums == {22, 80}
    # Check service detection
    ssh_port = [p for p in result["ports"] if p.port == 22][0]
    assert ssh_port.service == "ssh"
    assert "OpenSSH" in ssh_port.version


def test_parse_nmap_xml_findings():
    result = _parse_nmap_xml(SAMPLE_NMAP_XML)
    # One INFO finding per open port
    assert len(result["findings"]) == 2
    titles = {f.title for f in result["findings"]}
    assert any("22" in t for t in titles)
    assert any("80" in t for t in titles)


def test_parse_nmap_xml_empty():
    result = _parse_nmap_xml("<nmaprun></nmaprun>")
    assert result["targets"] == []
    assert result["ports"] == []


def test_parse_nmap_xml_bad_xml():
    result = _parse_nmap_xml("not xml at all")
    assert result["targets"] == []


# ── Subdomain wrapper tests ──────────────────────────────────────

from nexus.recon.subdomains import enumerate_subdomains


@pytest.mark.asyncio
async def test_enumerate_subdomains_fallback():
    """When no tools are available, still returns the root domain."""
    with patch.object(ToolRunner, "is_available", return_value=False):
        targets = await enumerate_subdomains("example.com")
    assert len(targets) >= 1
    assert any(t.host == "example.com" for t in targets)


# ── DNS wrapper tests ────────────────────────────────────────────

from nexus.recon.dns import enumerate_dns
from nexus.db.models import Target


@pytest.mark.asyncio
async def test_enumerate_dns_no_tools():
    """Graceful fallback when dnsx/dig are missing."""
    targets = [Target(host="example.com")]
    with patch.object(ToolRunner, "is_available", return_value=False):
        result_targets, findings = await enumerate_dns(targets)
    assert len(result_targets) == 1


# ── WAF wrapper tests ────────────────────────────────────────────

from nexus.recon.waf import detect_waf


@pytest.mark.asyncio
async def test_detect_waf_no_tool():
    targets = [Target(host="example.com", is_live=True)]
    with patch.object(ToolRunner, "is_available", return_value=False):
        result_targets, findings = await detect_waf(targets)
    assert findings == []  # graceful skip


# ── OSINT wrapper tests ──────────────────────────────────────────

from nexus.recon.osint import gather_osint, _parse_harvester_stdout


def test_parse_harvester_stdout():
    stdout = """
    admin@example.com
    info@example.com
    192.168.1.1
    sub.example.com
    """
    emails, hosts, ips = _parse_harvester_stdout(stdout)
    assert "admin@example.com" in emails
    assert "info@example.com" in emails
    assert "192.168.1.1" in ips
    assert "sub.example.com" in hosts


@pytest.mark.asyncio
async def test_gather_osint_no_tool():
    with patch.object(ToolRunner, "is_available", return_value=False):
        targets, findings = await gather_osint("example.com")
    assert targets == []
    assert findings == []


# ── Tech-stack wrapper tests ─────────────────────────────────────

from nexus.recon.tech import detect_tech_stack


@pytest.mark.asyncio
async def test_detect_tech_stack_no_tools():
    targets = [Target(host="example.com")]
    with patch.object(ToolRunner, "is_available", return_value=False):
        result = await detect_tech_stack(targets)
    assert len(result) == 1  # unchanged, no crash


# ── Module import smoke test ─────────────────────────────────────


def test_recon_package_imports():
    from nexus.recon import (
        ToolRunner,
        ToolNotFoundError,
        nmap_scan,
        enumerate_subdomains,
        detect_tech_stack,
        enumerate_dns,
        detect_waf,
        gather_osint,
    )
    assert callable(nmap_scan)
    assert callable(enumerate_subdomains)


def test_subfinder_plaintext_fallback_and_amass_filter():
    """Verify _extract_valid_host filters progress bars and Amass arrows cleanly."""
    from nexus.recon.subdomains import _extract_valid_host

    assert _extract_valid_host("api.example.com", "example.com") == "api.example.com"
    assert _extract_valid_host("sub.example.com (FQDN) --> a_record --> 1.2.3.4", "example.com") == "sub.example.com"
    assert _extract_valid_host("75 / 292 [------>____] 25.68% 13 p/s", "example.com") == ""
    assert _extract_valid_host("evil.com", "example.com") == ""


@pytest.mark.asyncio
async def test_subfinder_plaintext_no_unbound_local_error():
    """Regression: plain-text output on first line must not trigger UnboundLocalError on `rec`."""
    from nexus.recon.subdomains import subfinder_enum

    fake_out = ToolOutput(
        tool="subfinder", args=[], returncode=0,
        stdout="api.example.com\nweb.example.com\n", stderr="",
    )
    with patch.object(ToolRunner, "run", AsyncMock(return_value=fake_out)):
        targets = await subfinder_enum("example.com")
    assert [t.host for t in targets] == ["api.example.com", "web.example.com"]


def test_harvester_split_host_ip():
    from nexus.recon.osint import _split_host_ip

    assert _split_host_ip("app.example.com:1.2.3.4") == ("app.example.com", "1.2.3.4")
    assert _split_host_ip("*.example.com:1.2.3.4") == ("", "")
    assert _split_host_ip("mail.example.com") == ("mail.example.com", "")


@pytest.mark.asyncio
async def test_enumerate_dns_skips_zone_transfer_for_ip_targets():
    """IP targets like 127.0.0.1 must never trigger `dig axfr 0.1 @0.1`."""
    from nexus.recon.dns import enumerate_dns

    targets = [Target(host="127.0.0.1", ip="127.0.0.1"), Target(host="localhost", ip="127.0.0.1")]
    run_mock = AsyncMock()
    with patch.object(ToolRunner, "is_available", return_value=True), patch.object(ToolRunner, "run", run_mock):
        res_targets, findings = await enumerate_dns(targets)
    assert len(res_targets) == 2
    assert findings == []
    assert run_mock.await_count == 0


@pytest.mark.asyncio
async def test_nmap_scan_root_privilege_fallback():
    """Verify nmap_scan retries without -O/-sS if raw-socket privileges are unavailable."""
    from nexus.recon.ports import nmap_scan

    fail_out = ToolOutput(
        tool="nmap", args=[], returncode=1, stdout="",
        stderr="You requested a scan type which requires root privileges.\nQUITTING!\n",
    )
    ok_out = ToolOutput(tool="nmap", args=[], returncode=0, stdout="", stderr="")
    run_mock = AsyncMock(side_effect=[fail_out, ok_out])

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", run_mock),
    ):
        res = await nmap_scan("http://127.0.0.1:8080/test", stealth="ghost", timeout=10)

    assert run_mock.await_count == 2
    retry_args = run_mock.await_args_list[1].args[1]
    assert "-sT" in retry_args
    assert "-sS" not in retry_args
    assert "-O" not in retry_args
    assert retry_args[-1] == "127.0.0.1"
    assert isinstance(res, dict)


def test_parse_nmap_xml_ipv6_and_script_findings():
    xml_data = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy" product="Jetty"/>
        <script id="http-vuln-cve2021" output="State: VULNERABLE to path traversal"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    res = _parse_nmap_xml(xml_data)
    assert res["targets"][0].ip == "::1"
    assert res["ports"][0].port == 8080
    script_findings = [f for f in res["findings"] if "Nmap script" in f.title]
    assert len(script_findings) == 1
    assert script_findings[0].severity.value == "medium"
    assert script_findings[0].port == 8080
    assert script_findings[0].protocol == "tcp"


# ── Security hardening & Wave-audit regression tests ─────────────


def test_runner_validation_and_redaction():
    import xml.etree.ElementTree as ET
    from nexus.recon.runner import (
        _redact_args,
        safe_parse_xml,
        sanitize_header_value,
        validate_cli_target,
        validate_extra_args,
        validate_headers,
    )

    assert validate_cli_target(" example.com ") == "example.com"
    for bad in ("", "   ", "-evil", "host\x00.com", "host\r\n.com", "a b"):
        with pytest.raises(ValueError):
            validate_cli_target(bad)

    assert sanitize_header_value(" Bearer tok ") == "Bearer tok"
    with pytest.raises(ValueError):
        sanitize_header_value("ok\r\nInjected: 1")
    with pytest.raises(ValueError):
        validate_headers({"-H": "val"})
    with pytest.raises(ValueError):
        validate_headers({"X:Bad": "val"})

    assert validate_extra_args(["-tags", "php"]) == ["-tags", "php"]
    for bad_args in (["--os-shell"], ["-oX", "/tmp/x"], ["-iL=/etc/passwd"], ["bad\narg"]):
        with pytest.raises(ValueError):
            validate_extra_args(bad_args)

    redacted = _redact_args([
        "-p", "s3cr3t",
        "-P", "/tmp/pass.txt",
        "--data", "user=a&pass=b",
        "-H", "X-Custom: tok123",
        "-Add-header", "Cookie: sid=xyz",
        "-h", "target.local",
    ])
    joined = " ".join(redacted)
    for leak in ("s3cr3t", "/tmp/pass.txt", "user=a&pass=b", "tok123", "sid=xyz"):
        assert leak not in joined
    assert "-h target.local" in joined

    with pytest.raises(ET.ParseError):
        safe_parse_xml('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>')
    el = safe_parse_xml('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun/>')
    assert el.tag == "nmaprun"


@pytest.mark.asyncio
async def test_windows_terminate_process_tree_taskkill():
    from nexus.recon.runner import _terminate_process_tree

    proc = MagicMock()
    proc.pid = 4242
    proc.returncode = None
    proc.wait = AsyncMock(return_value=0)

    tk_proc = MagicMock()
    tk_proc.returncode = 0
    tk_proc.wait = AsyncMock(return_value=0)

    with (
        patch("nexus.recon.runner.os.name", "nt"),
        patch("nexus.recon.runner.asyncio.create_subprocess_exec", AsyncMock(return_value=tk_proc)) as mock_exec,
    ):
        await _terminate_process_tree(proc, use_pg=False)

    mock_exec.assert_awaited_once()
    assert mock_exec.call_args.args[:5] == ("taskkill", "/T", "/F", "/PID", "4242")


@pytest.mark.asyncio
async def test_nmap_ipv6_missing_tool_and_timeout_and_default_ports():
    from nexus.recon.ports import DEFAULT_PORTS, _extract_nmap_target, nmap_scan

    for port in ("2375", "2379", "5000", "8000", "8500", "9000", "11211"):
        assert port in DEFAULT_PORTS.split(",")

    assert _extract_nmap_target("::1") == "::1"
    assert _extract_nmap_target("[::1]:8080") == "::1"
    assert _extract_nmap_target("http://[::1]:8080/api") == "::1"

    with patch.object(ToolRunner, "is_available", return_value=False):
        res = await nmap_scan("example.com")
    assert res == {"targets": [], "ports": [], "findings": [], "raw_xml": ""}

    timeout_out = ToolOutput(tool="nmap", args=[], returncode=-1, stdout="", stderr="TIMEOUT after 10s")
    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(return_value=timeout_out)),
    ):
        res_to = await nmap_scan("::1", timeout=10)
    assert res_to == {"targets": [], "ports": [], "findings": [], "raw_xml": ""}


@pytest.mark.asyncio
async def test_dns_aaaa_cname_records_multipart_tld_and_python_fallback():
    import json
    from nexus.recon.dns import _extract_root_domain, dns_zone_transfer, enumerate_dns

    assert _extract_root_domain("app.example.co.uk") == "example.co.uk"
    assert _extract_root_domain("co.uk") == ""
    assert _extract_root_domain("sub.example.com") == "example.com"

    # Python socket.getaddrinfo fallback when dnsx is absent
    t = Target(host="app.example.co.uk")
    with (
        patch.object(ToolRunner, "is_available", return_value=False),
        patch("nexus.recon.dns._resolve_host_sync", return_value="93.184.216.34"),
    ):
        targets_out, findings_out = await enumerate_dns([t])
    assert targets_out[0].ip == "93.184.216.34"
    assert findings_out == []

    # dnsx AAAA/CNAME/MX/NS/TXT + authoritative NS resolution for dig axfr
    dnsx_line = json.dumps({
        "host": "v6.example.co.uk",
        "aaaa": ["2001:db8::1"],
        "cname": ["cdn.example.co.uk"],
        "mx": ["mail.example.co.uk"],
        "ns": ["ns1.example.co.uk"],
        "txt": ["v=spf1 -all"],
    })
    dig_axfr_out = ToolOutput(tool="dig", args=[], returncode=0, stdout="a\nb\nc\n", stderr="")

    async def _fake_run(tool, args, **_kw):
        if tool == "dnsx":
            return ToolOutput(tool="dnsx", args=args, returncode=0, stdout=dnsx_line + "\n", stderr="")
        if tool == "dig" and args[0] == "axfr":
            return dig_axfr_out
        return ToolOutput(tool="dig", args=args, returncode=0, stdout="", stderr="")

    t2 = Target(host="v6.example.co.uk")
    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_fake_run)) as mock_run,
    ):
        res_t, res_f = await enumerate_dns([t2])
    assert res_t[0].ip == "2001:db8::1"
    assert any("DNS Records Enumerated" in f.title for f in res_f)
    assert any("Zone Transfer Allowed (example.co.uk)" in f.title for f in res_f)
    dig_calls = [c.args[1] for c in mock_run.await_args_list if c.args[0] == "dig"]
    assert ["axfr", "example.co.uk", "@ns1.example.co.uk"] in dig_calls

    # Authoritative NS lookup via dig +short NS when nameserver not passed
    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=[
            ToolOutput(tool="dig", args=[], returncode=0, stdout="ns2.example.org.\n", stderr=""),
            ToolOutput(tool="dig", args=[], returncode=0, stdout="", stderr=""),
        ])) as mock_ns_run,
    ):
        assert await dns_zone_transfer("example.org") is None
    assert mock_ns_run.await_args_list[1].args[1] == ["axfr", "example.org", "@ns2.example.org"]


def test_subdomains_idn_punycode():
    from nexus.recon.subdomains import _extract_valid_host

    assert _extract_valid_host("api.xn--p1ai", "xn--p1ai") == "api.xn--p1ai"
    assert _extract_valid_host("sub.münchen.de", "münchen.de") == "sub.xn--mnchen-3ya.de"


@pytest.mark.asyncio
async def test_tech_non_collision_key_and_waf_https_ports():
    import json
    from nexus.recon.tech import detect_tech_stack
    from nexus.recon.waf import detect_waf

    httpx_lines = "\n".join([
        json.dumps({"url": "http://app.local:80", "input": "app.local", "host": "app.local", "port": 80, "scheme": "http", "tech": ["Nginx"]}),
        json.dumps({"url": "https://app.local:8443", "input": "https://app.local:8443", "host": "app.local", "port": 8443, "scheme": "https", "tech": ["React"]}),
    ])
    t_http = Target(host="http://app.local:80")
    t_https = Target(host="https://app.local:8443")

    with (
        patch("nexus.recon.tech._resolve_httpx_bin", return_value="httpx"),
        patch.object(ToolRunner, "is_available", side_effect=lambda n: n == "whatweb"),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=[
            ToolOutput(tool="httpx", args=[], returncode=0, stdout=httpx_lines, stderr=""),
            ToolOutput(tool="whatweb", args=[], returncode=0, stdout="", stderr=""),
            ToolOutput(tool="whatweb", args=[], returncode=0, stdout="", stderr=""),
        ])) as mock_run,
    ):
        await detect_tech_stack([t_http, t_https])

    assert "Nginx" in t_http.tech_stack and "React" not in t_http.tech_stack
    assert "React" in t_https.tech_stack and "Nginx" not in t_https.tech_stack
    ww_targets = [c.args[1][-1] for c in mock_run.await_args_list if c.args[0] == "whatweb"]
    assert "https://app.local:8443" in ww_targets

    # WAF probes HTTPS for :8443 / bare host
    t_waf = Target(host="secure.local:8443", is_live=True)
    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(return_value=ToolOutput(
            tool="wafw00f", args=[], returncode=0,
            stdout="[*] The site https://secure.local:8443 is behind Cloudflare WAF.", stderr="",
        ))) as waf_run,
    ):
        _, waf_findings = await detect_waf([t_waf])
    assert t_waf.waf_detected == "Cloudflare"
    assert len(waf_findings) == 1
    assert waf_run.await_args.args[1] == ["https://secure.local:8443"]


@pytest.mark.asyncio
async def test_osint_cleans_temp_files_on_runner_exception():
    from pathlib import Path
    from nexus.recon.osint import theharvester_gather

    created_paths: list[str] = []
    orig_make = ToolRunner.make_temp_path

    def _track_temp(suffix=".xml"):
        p = orig_make(suffix)
        created_paths.append(p)
        return p

    with (
        patch.object(ToolRunner, "make_temp_path", side_effect=_track_temp),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=RuntimeError("boom"))),
    ):
        with pytest.raises(RuntimeError):
            await theharvester_gather("example.com")

    assert len(created_paths) == 1
    assert not Path(created_paths[0]).exists()

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

    with patch.object(ToolRunner, "run", run_mock):
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
    assert any("Nmap script" in f.title and f.severity.value == "medium" for f in res["findings"])

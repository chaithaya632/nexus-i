"""Tests for the base ToolRunner and recon module imports."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexus.recon.runner import ToolNotFoundError, ToolOutput, ToolRunner

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

from nexus.db.models import Target
from nexus.recon.dns import enumerate_dns


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

from nexus.recon.osint import _parse_harvester_stdout, gather_osint


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
        enumerate_subdomains,
        nmap_scan,
    )

    assert callable(nmap_scan)
    assert callable(enumerate_subdomains)


def test_subfinder_plaintext_fallback_and_amass_filter():
    """Verify _extract_valid_host filters progress bars and Amass arrows cleanly."""
    from nexus.recon.subdomains import _extract_valid_host

    assert _extract_valid_host("api.example.com", "example.com") == "api.example.com"
    assert (
        _extract_valid_host("sub.example.com (FQDN) --> a_record --> 1.2.3.4", "example.com")
        == "sub.example.com"
    )
    assert _extract_valid_host("75 / 292 [------>____] 25.68% 13 p/s", "example.com") == ""
    assert _extract_valid_host("evil.com", "example.com") == ""


@pytest.mark.asyncio
async def test_subfinder_plaintext_no_unbound_local_error():
    """Regression: plain-text output on first line must not trigger UnboundLocalError on `rec`."""
    from nexus.recon.subdomains import subfinder_enum

    fake_out = ToolOutput(
        tool="subfinder",
        args=[],
        returncode=0,
        stdout="api.example.com\nweb.example.com\n",
        stderr="",
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
    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", run_mock),
    ):
        res_targets, findings = await enumerate_dns(targets)
    assert len(res_targets) == 2
    assert findings == []
    assert run_mock.await_count == 0


@pytest.mark.asyncio
async def test_nmap_scan_root_privilege_fallback():
    """Verify nmap_scan retries without -O/-sS if raw-socket privileges are unavailable."""
    from nexus.recon.ports import nmap_scan

    fail_out = ToolOutput(
        tool="nmap",
        args=[],
        returncode=1,
        stdout="",
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

    redacted = _redact_args(
        [
            "-p",
            "s3cr3t",
            "-P",
            "/tmp/pass.txt",
            "--data",
            "user=a&pass=b",
            "-H",
            "X-Custom: tok123",
            "-Add-header",
            "Cookie: sid=xyz",
            "-h",
            "target.local",
        ]
    )
    joined = " ".join(redacted)
    for leak in ("s3cr3t", "/tmp/pass.txt", "user=a&pass=b", "tok123", "sid=xyz"):
        assert leak not in joined
    assert "-h target.local" in joined

    with pytest.raises(ET.ParseError):
        safe_parse_xml(
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'
        )
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
        patch(
            "nexus.recon.runner.asyncio.create_subprocess_exec", AsyncMock(return_value=tk_proc)
        ) as mock_exec,
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

    timeout_out = ToolOutput(
        tool="nmap", args=[], returncode=-1, stdout="", stderr="TIMEOUT after 10s"
    )
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
    dnsx_line = json.dumps(
        {
            "host": "v6.example.co.uk",
            "aaaa": ["2001:db8::1"],
            "cname": ["cdn.example.co.uk"],
            "mx": ["mail.example.co.uk"],
            "ns": ["ns1.example.co.uk"],
            "txt": ["v=spf1 -all"],
        }
    )
    dig_axfr_out = ToolOutput(tool="dig", args=[], returncode=0, stdout="a\nb\nc\n", stderr="")

    async def _fake_run(tool, args, **_kw):
        if tool == "dnsx":
            return ToolOutput(
                tool="dnsx", args=args, returncode=0, stdout=dnsx_line + "\n", stderr=""
            )
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
        patch.object(
            ToolRunner,
            "run",
            AsyncMock(
                side_effect=[
                    ToolOutput(
                        tool="dig", args=[], returncode=0, stdout="ns2.example.org.\n", stderr=""
                    ),
                    ToolOutput(tool="dig", args=[], returncode=0, stdout="", stderr=""),
                ]
            ),
        ) as mock_ns_run,
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

    httpx_lines = "\n".join(
        [
            json.dumps(
                {
                    "url": "http://app.local:80",
                    "input": "app.local",
                    "host": "app.local",
                    "port": 80,
                    "scheme": "http",
                    "tech": ["Nginx"],
                }
            ),
            json.dumps(
                {
                    "url": "https://app.local:8443",
                    "input": "https://app.local:8443",
                    "host": "app.local",
                    "port": 8443,
                    "scheme": "https",
                    "tech": ["React"],
                }
            ),
        ]
    )
    t_http = Target(host="http://app.local:80")
    t_https = Target(host="https://app.local:8443")

    with (
        patch("nexus.recon.tech._resolve_httpx_bin", return_value="httpx"),
        patch.object(ToolRunner, "is_available", side_effect=lambda n: n == "whatweb"),
        patch.object(
            ToolRunner,
            "run",
            AsyncMock(
                side_effect=[
                    ToolOutput(tool="httpx", args=[], returncode=0, stdout=httpx_lines, stderr=""),
                    ToolOutput(tool="whatweb", args=[], returncode=0, stdout="", stderr=""),
                    ToolOutput(tool="whatweb", args=[], returncode=0, stdout="", stderr=""),
                ]
            ),
        ) as mock_run,
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
        patch.object(
            ToolRunner,
            "run",
            AsyncMock(
                return_value=ToolOutput(
                    tool="wafw00f",
                    args=[],
                    returncode=0,
                    stdout="[*] The site https://secure.local:8443 is behind Cloudflare WAF.",
                    stderr="",
                )
            ),
        ) as waf_run,
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


# ── Nmap auto -Pn, firewall retry, and security tests ──────────


def _write_nmap_xml_at_ox(args: list[str], xml_content: str) -> None:
    xml_path = args[args.index("-oX") + 1]
    from pathlib import Path

    Path(xml_path).write_text(xml_content, encoding="utf-8")


@pytest.mark.asyncio
async def test_nmap_single_host_auto_pn_and_no_duplicate():
    from nexus.recon.ports import nmap_scan

    open_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>"""

    async def _run_write(_tool, args, **_kw):
        _write_nmap_xml_at_ox(args, open_xml)
        return ToolOutput(tool="nmap", args=args, returncode=0, stdout="", stderr="")

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_run_write)) as mock_run,
    ):
        res = await nmap_scan("192.168.1.50", stealth="normal")

    called_args = mock_run.await_args.args[1]
    assert called_args.count("-Pn") == 1
    assert called_args[-2:] == ["--", "192.168.1.50"]
    assert [p.port for p in res["ports"]] == [22]

    for extra, stealth in (
        (["-PN"], "normal"),
        (["-P0"], "normal"),
        (None, "ghost"),
    ):
        with (
            patch.object(ToolRunner, "is_available", return_value=True),
            patch.object(ToolRunner, "run", AsyncMock(side_effect=_run_write)) as mock_flag_run,
        ):
            await nmap_scan("192.168.1.50", stealth=stealth, extra_args=extra)
        flag_args = mock_flag_run.await_args.args[1]
        assert "-Pn" not in flag_args or flag_args.count("-Pn") == 1
        if extra:
            assert "-Pn" not in flag_args


@pytest.mark.asyncio
async def test_nmap_cidr_omits_initial_pn_and_retries_on_host_down():
    from nexus.recon.ports import nmap_scan

    down_xml = """<?xml version="1.0"?>
<nmaprun>
  <runstats><finished time="1"/><hosts up="0" down="256" total="256"/></runstats>
</nmaprun>"""
    up_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports>
  </host>
  <runstats><finished time="2"/><hosts up="1" down="255" total="256"/></runstats>
</nmaprun>"""

    call_idx = 0

    async def _run_cidr(_tool, args, **_kw):
        nonlocal call_idx
        call_idx += 1
        if call_idx == 1:
            _write_nmap_xml_at_ox(args, down_xml)
            return ToolOutput(
                tool="nmap",
                args=args,
                returncode=0,
                stdout="Note: Host seems down.\nNmap done: 256 IP addresses (0 hosts up) scanned",
                stderr="",
            )
        _write_nmap_xml_at_ox(args, up_xml)
        return ToolOutput(tool="nmap", args=args, returncode=0, stdout="", stderr="")

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_run_cidr)) as mock_run,
    ):
        res = await nmap_scan("192.168.1.0/24", stealth="normal")

    assert mock_run.await_count == 2
    first_args = mock_run.await_args_list[0].args[1]
    retry_args = mock_run.await_args_list[1].args[1]
    assert "-Pn" not in first_args
    assert "-Pn" in retry_args
    assert retry_args[-2:] == ["--", "192.168.1.0/24"]
    assert [p.port for p in res["ports"]] == [80]

    # XML-only <hosts up="0"/> also triggers exactly 1 bounded retry even if still 0 hosts up
    async def _always_down(_tool, args, **_kw):
        _write_nmap_xml_at_ox(args, down_xml)
        return ToolOutput(tool="nmap", args=args, returncode=0, stdout="", stderr="")

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_always_down)) as mock_bounded,
    ):
        res_down = await nmap_scan("2001:db8::/32", stealth="normal")

    assert mock_bounded.await_count == 2
    assert res_down["ports"] == []


@pytest.mark.asyncio
async def test_nmap_cidr_10_hosts_up_does_not_false_trigger_pn_retry():
    from nexus.recon.ports import nmap_scan

    ten_up_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
  <runstats><finished time="1"/><hosts up="10" down="246" total="256"/></runstats>
</nmaprun>"""

    async def _run_ten_up(_tool, args, **_kw):
        _write_nmap_xml_at_ox(args, ten_up_xml)
        return ToolOutput(
            tool="nmap",
            args=args,
            returncode=0,
            stdout="Nmap done: 256 IP addresses (10 hosts up) scanned in 4.1s",
            stderr="",
        )

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_run_ten_up)) as mock_run,
    ):
        res = await nmap_scan("192.168.1.0/24", stealth="normal")

    assert mock_run.await_count == 1
    assert [p.port for p in res["ports"]] == [22]


@pytest.mark.asyncio
async def test_nmap_all_filtered_extraports_slow_connect_retry_and_extra_filtering():
    from nexus.recon.ports import nmap_scan

    filtered_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <ports>
      <extraports state="filtered" count="33"/>
    </ports>
  </host>
</nmaprun>"""
    open_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
      <extraports state="filtered" count="32"/>
    </ports>
  </host>
</nmaprun>"""

    calls = 0

    async def _run_filtered_then_open(_tool, args, **_kw):
        nonlocal calls
        calls += 1
        _write_nmap_xml_at_ox(args, filtered_xml if calls == 1 else open_xml)
        return ToolOutput(tool="nmap", args=args, returncode=0, stdout="", stderr="")

    extra = [
        "-sS",
        "-T4",
        "--max-retries",
        "1",
        "--min-rate=1000",
        "-D",
        "RND:5",
        "--script",
        "http-title",
        "-n",
    ]
    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_run_filtered_then_open)) as mock_run,
    ):
        res = await nmap_scan("10.10.10.5", stealth="loud", extra_args=extra)

    assert mock_run.await_count == 2
    retry_args = mock_run.await_args_list[1].args[1]
    assert retry_args[:6] == ["-sT", "-Pn", "-sV", "-T2", "--max-retries", "2"]
    assert "--script" in retry_args and "http-title" in retry_args and "-n" in retry_args
    for stripped in ("-sS", "-T4", "--min-rate=1000", "-D", "RND:5", "1"):
        assert stripped not in retry_args
    assert [p.port for p in res["ports"]] == [443]


@pytest.mark.asyncio
async def test_nmap_still_all_filtered_warns_and_never_labels_filtered_as_open(caplog):
    import logging

    from nexus.recon.ports import nmap_scan

    all_filtered_ports_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="filtered"/></port>
      <port protocol="tcp" portid="443"><state state="filtered"/></port>
      <extraports state="filtered" count="31"/>
    </ports>
  </host>
</nmaprun>"""

    async def _always_filtered(_tool, args, **_kw):
        _write_nmap_xml_at_ox(args, all_filtered_ports_xml)
        return ToolOutput(tool="nmap", args=args, returncode=0, stdout="", stderr="")

    with (
        caplog.at_level(logging.WARNING, logger="nexus.recon.ports"),
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_always_filtered)) as mock_run,
    ):
        res = await nmap_scan("10.10.10.9")

    assert mock_run.await_count == 2
    assert len(res["targets"]) == 1
    assert res["targets"][0].is_live is True
    assert res["ports"] == []
    assert res["findings"] == []
    assert any("still returned only filtered ports" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_nmap_mixed_states_skip_retry_and_retry_timeout_cleans_temp():
    from pathlib import Path

    from nexus.recon.ports import nmap_scan

    mixed_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.11" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="closed"/></port>
      <port protocol="udp" portid="53"><state state="open|filtered"/><service name="domain"/></port>
      <extraports state="filtered" count="31"/>
    </ports>
  </host>
</nmaprun>"""

    async def _run_mixed(_tool, args, **_kw):
        _write_nmap_xml_at_ox(args, mixed_xml)
        return ToolOutput(tool="nmap", args=args, returncode=0, stdout="", stderr="")

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_run_mixed)) as mock_run,
    ):
        res = await nmap_scan("10.10.10.11")

    assert mock_run.await_count == 1
    assert [(p.port, p.state) for p in res["ports"]] == [(53, "open|filtered")]

    filtered_xml = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="10.10.10.12" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="filtered"/></port></ports>
</host></nmaprun>"""
    created_paths: list[str] = []
    orig_make = ToolRunner.make_temp_path

    def _track_temp(suffix=".xml"):
        p = orig_make(suffix)
        created_paths.append(p)
        return p

    attempt = 0

    async def _run_then_timeout(_tool, args, **_kw):
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            _write_nmap_xml_at_ox(args, filtered_xml)
            return ToolOutput(tool="nmap", args=args, returncode=0, stdout="", stderr="")
        return ToolOutput(tool="nmap", args=args, returncode=-1, stdout="", stderr="TIMEOUT")

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "make_temp_path", side_effect=_track_temp),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_run_then_timeout)) as mock_to,
    ):
        res_to = await nmap_scan("10.10.10.12", timeout=5)

    assert mock_to.await_count == 2
    assert res_to == {"targets": [], "ports": [], "findings": [], "raw_xml": ""}
    assert len(created_paths) == 1
    assert not Path(created_paths[0]).exists()


@pytest.mark.asyncio
async def test_nmap_root_fallback_and_firewall_retry_bounded():
    from nexus.recon.ports import nmap_scan

    filtered_xml = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<ports><extraports state="filtered" count="10"/></ports></host></nmaprun>"""
    open_xml = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>"""

    call_n = 0

    async def _root_then_filtered_then_open(_tool, args, **_kw):
        nonlocal call_n
        call_n += 1
        if call_n == 1:
            return ToolOutput(
                tool="nmap",
                args=args,
                returncode=1,
                stdout="",
                stderr="You requested a scan type which requires root privileges.",
            )
        _write_nmap_xml_at_ox(args, filtered_xml if call_n == 2 else open_xml)
        return ToolOutput(tool="nmap", args=args, returncode=0, stdout="", stderr="")

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_root_then_filtered_then_open)) as m1,
    ):
        res1 = await nmap_scan("10.0.0.5", stealth="loud", extra_args=["-sS", "--script", "banner"])

    assert m1.await_count == 3
    assert "-O" not in m1.await_args_list[1].args[1]
    assert "-sS" not in m1.await_args_list[1].args[1]
    assert "-sT" in m1.await_args_list[1].args[1]
    assert "--script" in m1.await_args_list[2].args[1]
    assert m1.await_args_list[2].args[1].count("-sT") == 1
    assert [p.port for p in res1["ports"]] == [22]

    down_xml = """<?xml version="1.0"?>
<nmaprun><runstats><hosts up="0" down="256" total="256"/></runstats></nmaprun>"""
    cidr_calls = 0

    async def _root_then_down_then_open(_tool, args, **_kw):
        nonlocal cidr_calls
        cidr_calls += 1
        if cidr_calls == 1:
            return ToolOutput(
                tool="nmap",
                args=args,
                returncode=1,
                stdout="",
                stderr="requires root privileges",
            )
        _write_nmap_xml_at_ox(args, down_xml if cidr_calls == 2 else open_xml)
        return ToolOutput(tool="nmap", args=args, returncode=0, stdout="", stderr="")

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_root_then_down_then_open)) as m2,
    ):
        res2 = await nmap_scan("10.0.0.0/24", stealth="loud")

    assert m2.await_count == 3
    assert "-O" not in m2.await_args_list[1].args[1]
    assert "-Pn" not in m2.await_args_list[1].args[1]
    assert "-Pn" in m2.await_args_list[2].args[1]
    assert "-O" not in m2.await_args_list[2].args[1]
    assert [p.port for p in res2["ports"]] == [22]


@pytest.mark.asyncio
async def test_nmap_cli_sanitization_and_xxe_safety():
    from nexus.recon.ports import _compatible_connect_extra, nmap_scan

    for bad_target in ("-evil", "http://-evil.com/x", "1.2.3.4 --script=x", "host\x00.com"):
        with pytest.raises(ValueError):
            await nmap_scan(bad_target)

    for bad_extra in (
        ["--", "169.254.169.254"],
        ["-oX/tmp/pwn.xml"],
        ["-oS", "/tmp/pwn"],
        ["-iL/etc/passwd"],
        ["-il/etc/passwd"],
    ):
        with pytest.raises(ValueError):
            await nmap_scan("127.0.0.1", extra_args=bad_extra)

    xxe_xml = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<nmaprun><host><status state='up'/><address addr='127.0.0.1' addrtype='ipv4'/>"
        "<hostnames><hostname name='&xxe;'/></hostnames></host></nmaprun>"
    )

    async def _run_xxe(_tool, args, **_kw):
        _write_nmap_xml_at_ox(args, xxe_xml)
        return ToolOutput(tool="nmap", args=args, returncode=0, stdout="", stderr="")

    with (
        patch.object(ToolRunner, "is_available", return_value=True),
        patch.object(ToolRunner, "run", AsyncMock(side_effect=_run_xxe)) as mock_run,
    ):
        res = await nmap_scan("127.0.0.1", extra_args=["--open"])

    called_args = mock_run.await_args.args[1]
    assert "--open" in called_args
    assert called_args[-2:] == ["--", "127.0.0.1"]
    assert res["targets"] == []
    assert res["ports"] == []
    assert res["findings"] == []

    assert _compatible_connect_extra(
        ["--max-retries=2", "-T", "4", "--script", "ssl-enum", "-n"]
    ) == [
        "--script",
        "ssl-enum",
        "-n",
    ]

"""Tests for scanner wrappers and result importer."""

import json
import pytest
from unittest.mock import patch

from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner


# ── Nuclei parser tests ──────────────────────────────────────────

from nexus.scanner.nuclei import _parse_nuclei_line

SAMPLE_NUCLEI_JSON = json.dumps({
    "template-id": "cve-2021-44228",
    "info": {
        "name": "Apache Log4j RCE",
        "severity": "critical",
        "description": "Remote code execution via Log4j JNDI lookup.",
        "classification": {
            "cve-id": ["CVE-2021-44228"],
            "cwe-id": ["CWE-502"],
            "cvss-score": 10.0,
        },
    },
    "host": "example.com",
    "port": 8080,
    "type": "http",
    "matched-at": "http://example.com:8080/api",
    "request": "GET /api HTTP/1.1",
    "response": "HTTP/1.1 200 OK",
})


def test_parse_nuclei_line_valid():
    f = _parse_nuclei_line(SAMPLE_NUCLEI_JSON)
    assert f is not None
    assert f.severity == Severity.CRITICAL
    assert "CVE-2021-44228" in f.cve_ids
    assert f.cwe_id == "CWE-502"
    assert f.cvss_score == 10.0
    assert f.host == "example.com"
    assert f.port == 8080
    assert "Log4j" in f.title


def test_parse_nuclei_line_minimal():
    line = json.dumps({
        "template-id": "tech-detect",
        "info": {"name": "Nginx detected", "severity": "info"},
        "host": "test.com",
        "type": "http",
    })
    f = _parse_nuclei_line(line)
    assert f is not None
    assert f.severity == Severity.INFO
    assert f.cve_ids == []


def test_parse_nuclei_line_bad_json():
    f = _parse_nuclei_line("not json")
    assert f is None


def test_parse_nuclei_cwe_normalization():
    line = json.dumps({
        "template-id": "test",
        "info": {
            "name": "Test",
            "severity": "high",
            "classification": {"cwe-id": "79"},
        },
        "host": "x.com",
        "type": "http",
    })
    f = _parse_nuclei_line(line)
    assert f is not None
    assert f.cwe_id == "CWE-79"


# ── Nikto parser tests ───────────────────────────────────────────

from nexus.scanner.nikto import _parse_csv_line, _classify_severity


def test_parse_csv_line():
    line = '"host","1.2.3.4","80","0","GET","/","Description, ""quoted"" here"'
    parts = _parse_csv_line(line)
    assert len(parts) == 7
    assert parts[0] == "host"
    assert parts[6] == 'Description, "quoted" here'


def test_classify_severity_high():
    assert _classify_severity("Remote code execution detected") == Severity.HIGH
    assert _classify_severity("SQL injection in parameter") == Severity.HIGH
    assert _classify_severity("Default password for admin") == Severity.HIGH


def test_classify_severity_medium():
    assert _classify_severity("Missing X-Frame-Options header") == Severity.MEDIUM
    assert _classify_severity("Directory listing enabled") == Severity.MEDIUM


def test_classify_severity_low():
    assert _classify_severity("Some unrecognized text") == Severity.LOW


# ── ffuf output parse test ───────────────────────────────────────

from nexus.scanner.web import ffuf_scan


@pytest.mark.asyncio
async def test_ffuf_no_tool():
    """ffuf should raise ToolNotFoundError when binary is missing."""
    from unittest.mock import patch
    from nexus.recon.runner import ToolNotFoundError
    with patch("nexus.recon.runner.asyncio.create_subprocess_exec", side_effect=FileNotFoundError("ffuf")):
        with pytest.raises(ToolNotFoundError):
            await ffuf_scan("http://example.com")


# ── Importer tests ───────────────────────────────────────────────

from nexus.scanner.importer import import_csv, import_nessus, import_burp_xml

SAMPLE_CSV = """host,port,severity,title,description
example.com,80,high,XSS in search,Reflected XSS via q param
example.com,443,medium,Missing HSTS,Strict-Transport-Security not set
"""


def test_import_csv():
    findings = import_csv(SAMPLE_CSV)
    assert len(findings) == 2
    assert findings[0].severity == Severity.HIGH
    assert findings[0].host == "example.com"
    assert findings[1].severity == Severity.MEDIUM


SAMPLE_NESSUS = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="test">
    <ReportHost name="192.168.1.1">
      <ReportItem port="22" protocol="tcp" severity="2" pluginName="SSH Weak Cipher">
        <description>The SSH server supports weak ciphers.</description>
        <solution>Disable weak ciphers in sshd_config.</solution>
        <cve>CVE-2023-12345</cve>
        <cwe>327</cwe>
        <cvss_base_score>5.3</cvss_base_score>
      </ReportItem>
      <ReportItem port="80" protocol="tcp" severity="3" pluginName="Apache RCE">
        <description>Remote code execution in Apache.</description>
        <cve>CVE-2021-41773</cve>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def test_import_nessus():
    findings = import_nessus(SAMPLE_NESSUS)
    assert len(findings) == 2
    ssh = [f for f in findings if "SSH" in f.title][0]
    assert ssh.severity == Severity.MEDIUM
    assert "CVE-2023-12345" in ssh.cve_ids
    assert ssh.cwe_id == "CWE-327"
    assert ssh.cvss_score == 5.3
    assert ssh.port == 22

    rce = [f for f in findings if "RCE" in f.title][0]
    assert rce.severity == Severity.HIGH


SAMPLE_BURP = """<?xml version="1.0"?>
<issues>
  <issue>
    <host ip="10.0.0.1">example.com</host>
    <path>/admin</path>
    <name>Directory listing</name>
    <severity>Medium</severity>
    <issueDetail>Directory listing enabled on /admin.</issueDetail>
    <remediationDetail>Disable directory listing.</remediationDetail>
  </issue>
</issues>
"""


def test_import_burp_xml():
    findings = import_burp_xml(SAMPLE_BURP)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert "Directory listing" in f.title
    assert f.remediation == "Disable directory listing."


def test_import_nessus_bad_xml():
    findings = import_nessus("not xml")
    assert findings == []


# ── Module import smoke test ─────────────────────────────────────

def test_scanner_package_imports():
    from nexus.scanner import nuclei_scan, ffuf_scan, nikto_scan, import_file
    assert callable(nuclei_scan)
    assert callable(import_file)


def test_parse_nikto_csv_real_kali_format():
    """Regression: Nikto 2.6.1 CSV quotes every field and writes empty summary row."""
    from nexus.scanner.nikto import _parse_nikto_csv

    sample_csv = (
        '"Nikto - v2.6.1/"\n'
        '"127.0.0.1","127.0.0.1","18997","","","",""\n'
        '"127.0.0.1","127.0.0.1","18997","https://developer.mozilla.org/HSTS","GET","/","Suggested security header missing: strict-transport-security."\n'
        '"127.0.0.1","127.0.0.1","18997","0","GET","/.git/","Directory .git/ found on server"\n'
    )
    findings = _parse_nikto_csv(sample_csv, target="127.0.0.1", default_port=18997)
    assert len(findings) == 2
    assert findings[0].port == 18997
    assert findings[0].severity == Severity.MEDIUM
    assert findings[1].severity == Severity.HIGH


def test_nuclei_string_and_empty_ports():
    str_port = json.dumps({
        "template-id": "test-str", "info": {"name": "StrPort", "severity": "low"},
        "host": "x.com", "port": "8443", "type": "https",
    })
    empty_port = json.dumps({
        "template-id": "test-empty", "info": {"name": "EmptyPort", "severity": "info"},
        "host": "x.com", "port": "", "type": "http",
    })
    assert _parse_nuclei_line(str_port).port == 8443
    assert _parse_nuclei_line(empty_port).port is None


@pytest.mark.asyncio
async def test_ffuf_reads_clean_json_ignoring_stdout_prefix():
    from pathlib import Path
    from unittest.mock import AsyncMock
    from nexus.recon.runner import ToolOutput

    async def fake_run(tool, args, **kw):
        out_path = Path(args[args.index("-o") + 1])
        out_path.write_text(json.dumps({
            "results": [{"url": "http://app.local:8080/admin", "status": 200, "length": 42, "words": 5}]
        }), encoding="utf-8")
        return ToolOutput(tool="ffuf", args=args, returncode=0, stdout="admin\n", stderr="")

    with patch.object(ToolRunner, "run", AsyncMock(side_effect=fake_run)):
        findings = await ffuf_scan("http://app.local:8080", wordlist="dummy.txt")
    assert len(findings) == 1
    assert findings[0].host == "app.local"
    assert findings[0].port == 8080
    assert findings[0].severity == Severity.LOW


def test_import_file_autodetects_all_formats(tmp_path):
    from nexus.scanner.importer import import_file

    nessus_p = tmp_path / "scan.nessus"
    nessus_p.write_text(SAMPLE_NESSUS, encoding="utf-8")
    assert len(import_file(nessus_p)) == 2

    burp_p = tmp_path / "burp.xml"
    burp_p.write_text(SAMPLE_BURP, encoding="utf-8")
    assert len(import_file(burp_p)) == 1

    csv_p = tmp_path / "findings.csv"
    csv_p.write_text(SAMPLE_CSV, encoding="utf-8")
    assert len(import_file(csv_p)) == 2

    with pytest.raises(FileNotFoundError):
        import_file(tmp_path / "missing.xml")


@pytest.mark.asyncio
async def test_ffuf_adds_ac_and_stealth_rate_limits():
    from unittest.mock import AsyncMock
    from nexus.recon.runner import ToolOutput

    mock_run = AsyncMock(return_value=ToolOutput(tool="ffuf", args=[], returncode=0, stdout="", stderr=""))
    with patch.object(ToolRunner, "run", mock_run):
        await ffuf_scan("https://app.local", wordlist="dummy.txt", stealth="ghost")

    args = mock_run.await_args.args[1]
    assert "-ac" in args
    assert "-rate" in args and args[args.index("-rate") + 1] == "2"
    assert "-p" in args and args[args.index("-p") + 1] == "1.0"


def test_importer_size_guard_and_xxe_rejection(tmp_path):
    from nexus.scanner.importer import import_file

    small_csv = tmp_path / "big.csv"
    small_csv.write_text(SAMPLE_CSV, encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds limit"):
        import_file(small_csv, max_bytes=10)

    xxe_nessus = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><NessusClientData_v2><ReportHost name="&xxe;"/></NessusClientData_v2>'
    assert import_nessus(xxe_nessus) == []
    assert import_burp_xml(xxe_nessus) == []


@pytest.mark.asyncio
async def test_sqli_per_parameter_reset_risk_cap_and_credential_hardening(tmp_path):
    from unittest.mock import AsyncMock
    from nexus.exploit.credential import hydra_attack, test_default_creds
    from nexus.exploit.sqli import sqlmap_scan
    from nexus.recon.runner import ToolOutput

    # 1. sqlmap resets injectable per Parameter:, ignores 'not injectable', caps risk <= 2
    stdout = "\n".join([
        "Parameter: id (GET)",
        "Parameter 'id' is vulnerable.",
        "Type: error-based",
        "Payload: id=1'",
        "Parameter: page (GET)",
        "Parameter 'page' does not seem to be injectable",
        "Payload: should_not_trigger",
    ])
    mock_sql = AsyncMock(return_value=ToolOutput(tool="sqlmap", args=[], returncode=0, stdout=stdout, stderr=""))
    with patch("nexus.exploit.sqli.ToolRunner.run", mock_sql):
        findings = await sqlmap_scan("http://app.local/items?id=1&page=2", risk=3)

    assert len(findings) == 1
    assert "error-based" in findings[0].title
    sql_args = mock_sql.await_args.args[1]
    assert sql_args[sql_args.index("--risk") + 1] == "2"

    # Reject CRLF / leading '-' in sqli and hydra
    with pytest.raises(ValueError):
        await sqlmap_scan("-u", param="id")
    with pytest.raises(ValueError):
        await hydra_attack("127.0.0.1", "ssh", username="-evil", password="pw")

    # 2. hydra adds -f for wordlists and skips missing Linux wordlists cleanly
    missing_c, missing_f = await hydra_attack(
        "127.0.0.1", "ssh", user_list="/nonexistent/users.txt", pass_list="/nonexistent/pass.txt"
    )
    assert missing_c == [] and missing_f == []

    ul = tmp_path / "u.txt"
    pl = tmp_path / "p.txt"
    ul.write_text("admin\n", encoding="utf-8")
    pl.write_text("secret\n", encoding="utf-8")
    mock_hydra = AsyncMock(return_value=ToolOutput(tool="hydra", args=[], returncode=0, stdout="", stderr=""))
    with patch("nexus.exploit.credential.ToolRunner.run", mock_hydra):
        await hydra_attack("127.0.0.1", "ssh", user_list=str(ul), pass_list=str(pl))
    assert "-f" in mock_hydra.await_args.args[1]

    # 3. test_default_creds applies configurable inter-attempt delay
    sleep_calls: list[float] = []

    async def _fake_sleep(d: float):
        sleep_calls.append(d)

    with (
        patch("nexus.exploit.credential.ToolRunner.run", AsyncMock(return_value=ToolOutput(tool="hydra", args=[], returncode=0, stdout="", stderr=""))),
        patch("nexus.exploit.credential.asyncio.sleep", side_effect=_fake_sleep),
    ):
        await test_default_creds("127.0.0.1", 22, "ssh", [("u1", "p1"), ("u2", "p2")], delay_s=0.25)
    assert sleep_calls == [0.25]

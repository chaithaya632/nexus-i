"""Nikto web-server scanner wrapper."""

from __future__ import annotations

import csv
import io
import logging
import re
from typing import Any
from urllib.parse import urlparse

from nexus.db.models import Finding, Severity
from nexus.recon.runner import (
    ToolRunner,
    validate_cli_target,
    validate_extra_args,
    validate_headers,
    validate_port,
)

log = logging.getLogger("nexus.scanner.nikto")

# Nikto OSVDB/finding patterns that map to higher severity
_HIGH_PATTERNS = [
    re.compile(r"remote (code|command) execution", re.I),
    re.compile(r"directory traversal", re.I),
    re.compile(r"file (inclusion|upload)", re.I),
    re.compile(r"(sql|ldap|xml|xpath) injection", re.I),
    re.compile(r"default (password|credential|admin)", re.I),
    re.compile(r"phpinfo", re.I),
    re.compile(r"\.git/", re.I),
    re.compile(r"\.env", re.I),
    re.compile(r"backup file", re.I),
]

_MEDIUM_PATTERNS = [
    re.compile(r"server version", re.I),
    re.compile(r"directory (listing|indexing)", re.I),
    re.compile(r"X-Frame-Options", re.I),
    re.compile(r"X-Content-Type-Options", re.I),
    re.compile(r"Strict-Transport-Security", re.I),
    re.compile(r"clickjack", re.I),
    re.compile(r"cookie.*httponly", re.I),
]


async def nikto_scan(
    target: str,
    *,
    port: int | None = None,
    ssl: bool = False,
    headers: dict[str, str] | None = None,
    timeout: int = 600,
    extra_args: list[str] | None = None,
) -> list[Finding]:
    """Run nikto against a target and return Findings.

    Args:
        target: hostname or IP (or full URL).
        port: specific port (default 80/443).
        ssl: force SSL.
        timeout: max seconds.
    """
    from pathlib import Path
    import tempfile

    # Nikto errors with "-port cannot be used with a full URI" if both URL and -p are passed
    clean_target = validate_cli_target(target, label="target")
    if port is not None:
        port = validate_port(port)
    clean_headers = validate_headers(headers)
    safe_extra = validate_extra_args(extra_args)

    is_uri = "://" in clean_target
    use_ssl = ssl or clean_target.lower().startswith("https://")
    inferred_port = port
    if is_uri:
        parsed = urlparse(clean_target)
        if parsed.port is not None and inferred_port is None:
            inferred_port = parsed.port

    with tempfile.TemporaryDirectory(prefix="nexus_nikto_") as td:
        csv_path = Path(td) / "nikto.csv"
        args = ["-h", clean_target, "-o", str(csv_path), "-Format", "csv", "-nointeractive"]

        if port and not is_uri:
            args.extend(["-p", str(port)])
        elif is_uri and port and f":{port}" not in clean_target:
            # Strip scheme to use -p cleanly with explicit non-default port
            host_only = (urlparse(clean_target).hostname or "").strip() or clean_target
            args[1] = host_only
            args.extend(["-p", str(port)])

        if ssl and not is_uri:
            args.append("-ssl")

        if clean_headers:
            for k, v in clean_headers.items():
                args.extend(["-Add-header", f"{k}: {v}"])

        if safe_extra:
            args.extend(safe_extra)

        out = await ToolRunner.run("nikto", args, timeout=timeout)
        csv_text = ""
        if csv_path.is_file():
            csv_text = csv_path.read_text(encoding="utf-8", errors="replace")
        if not csv_text.strip():
            csv_text = out.stdout

    return _parse_nikto_csv(csv_text, target=clean_target, default_port=inferred_port, ssl=use_ssl)


def _parse_nikto_csv(
    csv_text: str,
    *,
    target: str = "",
    default_port: int | None = None,
    ssl: bool = False,
) -> list[Finding]:
    """Parse Nikto CSV text (where data rows are quoted) into Findings using csv.reader."""
    findings: list[Finding] = []
    filtered_lines = [
        line for line in csv_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not filtered_lines:
        return findings

    for parts in csv.reader(io.StringIO("\n".join(filtered_lines))):
        # Nikto CSV: "host","IP","port","osvdb/ref","method","uri","description"
        if len(parts) < 7:
            continue

        host = parts[0].strip()
        ip = parts[1].strip()
        port_raw = parts[2].strip()
        osvdb = parts[3].strip()
        method = parts[4].strip()
        uri = parts[5].strip()
        desc = parts[6].strip()

        # Skip header/metadata lines or empty host summary rows
        if host.lower() == "host" or not desc:
            continue

        p = int(port_raw) if port_raw.isdigit() else (default_port or (443 if ssl else 80))
        severity = _classify_severity(desc)

        findings.append(Finding(
            host=host or ip or target,
            port=p,
            protocol="https" if ssl else "http",
            title=f"Nikto: {desc[:80]}",
            description=desc,
            severity=severity,
            tool_source="nikto",
            evidence=f"Reference: {osvdb}\nMethod: {method}\nURI: {uri}\n{desc}",
        ))

    log.info("nikto found %d issues on %s", len(findings), target)
    return findings


def _parse_csv_line(line: str) -> list[str]:
    """Parse a single CSV line via stdlib csv.reader."""
    for row in csv.reader(io.StringIO(line)):
        return row
    return []


def _classify_severity(description: str) -> Severity:
    """Classify nikto finding severity based on description patterns."""
    for pat in _HIGH_PATTERNS:
        if pat.search(description):
            return Severity.HIGH
    for pat in _MEDIUM_PATTERNS:
        if pat.search(description):
            return Severity.MEDIUM
    return Severity.LOW

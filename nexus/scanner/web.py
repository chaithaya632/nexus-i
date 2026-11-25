"""ffuf directory/endpoint brute-forcer wrapper."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from nexus.db.models import Finding, Severity
from nexus.recon.runner import ToolRunner

log = logging.getLogger("nexus.scanner.web")

# Default wordlist paths on Kali Linux (with dirb fallbacks if SecLists missing)
DEFAULT_WORDLISTS: dict[str, str] = {
    "dirs_small": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "dirs_medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "raft_dirs": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "api": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
}

_WORDLIST_FALLBACKS: list[str] = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
]


def _resolve_wordlist(wordlist: str, wordlist_name: str) -> str:
    if wordlist:
        return wordlist
    preferred = DEFAULT_WORDLISTS.get(wordlist_name, DEFAULT_WORDLISTS["common"])
    if Path(preferred).is_file():
        return preferred
    for candidate in _WORDLIST_FALLBACKS:
        if Path(candidate).is_file():
            return candidate
    return preferred

# Stealth-aware thread counts
_STEALTH_THREADS: dict[str, int] = {
    "loud": 80,
    "normal": 40,
    "quiet": 15,
    "ghost": 5,
}


async def ffuf_scan(
    target_url: str,
    *,
    wordlist: str = "",
    wordlist_name: str = "common",
    stealth: str = "normal",
    extensions: list[str] | None = None,
    match_codes: str = "200,204,301,302,307,401,403,405",
    headers: dict[str, str] | None = None,
    timeout: int = 600,
    extra_args: list[str] | None = None,
) -> list[Finding]:
    """Run ffuf against a target URL and return findings.

    The URL must contain 'FUZZ' where the wordlist value is injected.
    If not present, '/FUZZ' is appended automatically.
    """
    if "FUZZ" not in target_url:
        target_url = target_url.rstrip("/") + "/FUZZ"

    wl = _resolve_wordlist(wordlist, wordlist_name)
    threads = _STEALTH_THREADS.get(stealth, 40)
    json_path = ToolRunner.make_temp_path(".json")

    args = [
        "-u", target_url,
        "-w", wl,
        "-t", str(threads),
        "-mc", match_codes,
        "-o", json_path,
        "-of", "json",
        "-s",  # silent mode
    ]

    if extensions:
        args.extend(["-e", ",".join(extensions)])

    if headers:
        for k, v in headers.items():
            args.extend(["-H", f"{k}: {v}"])

    if extra_args:
        args.extend(extra_args)

    try:
        out = await ToolRunner.run("ffuf", args, timeout=timeout)

        # Read clean JSON from -o file (ffuf prints matched words before stdout JSON)
        raw_json = ""
        jp = Path(json_path)
        if jp.is_file():
            raw_json = jp.read_text(encoding="utf-8", errors="replace")
        if not raw_json.strip():
            raw_json = out.stdout
    finally:
        Path(json_path).unlink(missing_ok=True)

    findings: list[Finding] = []
    try:
        data = json.loads(raw_json)
        results = data.get("results", [])
    except json.JSONDecodeError:
        log.warning("ffuf did not return valid JSON")
        return findings

    base_host_port = target_url.split("//")[-1].split("/")[0] if "//" in target_url else target_url.split("/")[0]
    base_host = base_host_port.split(":")[0]
    base_port: int | None = None
    if ":" in base_host_port and base_host_port.split(":")[1].isdigit():
        base_port = int(base_host_port.split(":")[1])

    for r in results:
        url = r.get("url", "")
        status = r.get("status", 0)
        length = r.get("length", 0)
        words = r.get("words", 0)

        # Determine severity based on status and content
        severity = Severity.INFO
        title_prefix = "Directory/endpoint found"
        if status in (200, 204):
            severity = Severity.LOW
            title_prefix = "Accessible endpoint"
        elif status in (401, 403):
            severity = Severity.INFO
            title_prefix = "Protected endpoint"
        elif status in (301, 302, 307):
            severity = Severity.INFO
            title_prefix = "Redirect"

        findings.append(Finding(
            host=base_host,
            port=base_port,
            protocol="https" if target_url.startswith("https://") else "http",
            title=f"{title_prefix}: {url}",
            description=(
                f"Discovered endpoint via directory brute-force.  "
                f"Status: {status}, Length: {length}, Words: {words}"
            ),
            severity=severity,
            tool_source="ffuf",
            evidence=f"URL: {url}\nStatus: {status}\nContent-Length: {length}\nWords: {words}",
        ))

    log.info("ffuf found %d endpoints on %s", len(findings), target_url)
    return findings

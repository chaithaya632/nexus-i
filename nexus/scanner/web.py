"""ffuf directory/endpoint brute-forcer wrapper."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from nexus.db.models import Finding, Severity
from nexus.recon.runner import (
    ToolRunner,
    validate_cli_target,
    validate_extra_args,
    validate_headers,
)
from nexus.scanner._http import parse_url_target

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


# Stealth-aware thread counts, rate limits (req/s), and pause delays (seconds)
_STEALTH_THREADS: dict[str, int] = {
    "loud": 80,
    "normal": 40,
    "quiet": 15,
    "ghost": 5,
}
_STEALTH_RATE_PAUSE: dict[str, tuple[int, str]] = {
    "loud": (200, ""),
    "normal": (50, "0.05"),
    "quiet": (10, "0.25"),
    "ghost": (2, "1.0"),
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
    clean_url = validate_cli_target(target_url, label="target_url")
    if "FUZZ" not in clean_url:
        clean_url = clean_url.rstrip("/") + "/FUZZ"

    if wordlist:
        wordlist = validate_cli_target(wordlist, label="wordlist", allow_spaces=True)
    wl = _resolve_wordlist(wordlist, wordlist_name)
    clean_match_codes = validate_cli_target(match_codes, label="match_codes")
    clean_headers = validate_headers(headers)
    safe_extra = validate_extra_args(extra_args)

    threads = _STEALTH_THREADS.get(stealth, 40)
    rate_limit, pause_delay = _STEALTH_RATE_PAUSE.get(stealth, (50, "0.05"))
    json_path = ToolRunner.make_temp_path(".json")

    args = [
        "-u",
        clean_url,
        "-w",
        wl,
        "-t",
        str(threads),
        "-rate",
        str(rate_limit),
        "-ac",  # soft-404 auto-calibration
        "-mc",
        clean_match_codes,
        "-o",
        json_path,
        "-of",
        "json",
        "-s",  # silent mode
    ]
    if pause_delay:
        args.extend(["-p", pause_delay])

    if extensions:
        clean_exts = [validate_cli_target(e, label="extension") for e in extensions]
        args.extend(["-e", ",".join(clean_exts)])

    if clean_headers:
        for k, v in clean_headers.items():
            args.extend(["-H", f"{k}: {v}"])

    if safe_extra:
        args.extend(safe_extra)

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

    base_host, base_port, base_proto = parse_url_target(clean_url)

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

        findings.append(
            Finding(
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
            )
        )

    log.info("ffuf found %d endpoints on %s", len(findings), target_url)
    return findings

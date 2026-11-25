"""Tech-stack detection wrappers — httpx probe + whatweb fingerprinting."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from nexus.db.models import Target
from nexus.recon.runner import ToolRunner

log = logging.getLogger("nexus.recon.tech")


def _resolve_httpx_bin() -> str | None:
    """Resolve the ProjectDiscovery httpx binary.

    On Kali/Debian, `/usr/bin/httpx` is the Python HTTPX CLI while the
    ProjectDiscovery Go scanner is installed as `httpx-toolkit`.
    """
    if ToolRunner.is_available("httpx-toolkit"):
        return "httpx-toolkit"
    if ToolRunner.is_available("httpx"):
        httpx_path = shutil.which("httpx")
        if httpx_path:
            try:
                head = Path(httpx_path).read_bytes()[:64].lower()
                if b"python" in head:
                    return None
            except OSError:
                pass
        return "httpx"
    return None


async def httpx_probe(
    targets: list[str],
    *,
    timeout: int = 300,
    threads: int = 25,
    extra_args: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run httpx to probe HTTP services and return JSON records.

    Each record contains: url, status_code, title, tech, content_length,
    webserver, etc.
    """
    if not targets:
        return []

    httpx_bin = _resolve_httpx_bin()
    if not httpx_bin:
        log.warning("ProjectDiscovery httpx/httpx-toolkit not found — skipping HTTP probe")
        return []

    stdin_data = "\n".join(targets)
    args = [
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-content-length",
        "-follow-redirects",
        "-threads", str(threads),
    ]
    if extra_args:
        args.extend(extra_args)

    out = await ToolRunner.run(
        httpx_bin, args, timeout=timeout, stdin_data=stdin_data
    )

    results: list[dict[str, Any]] = []
    for line in out.lines:
        try:
            rec = json.loads(line)
            results.append(rec)
        except json.JSONDecodeError:
            continue

    log.info("httpx probed %d targets, got %d live responses", len(targets), len(results))
    return results


async def whatweb_scan(
    target: str,
    *,
    aggression: int = 1,
    timeout: int = 120,
) -> dict[str, Any]:
    """Run whatweb and return parsed technology detection.

    aggression levels: 1=stealthy, 3=aggressive, 4=heavy.
    """
    args = [
        "--log-json=-",  # JSON to stdout
        f"--aggression={aggression}",
        "--color=never",
        target,
    ]

    out = await ToolRunner.run("whatweb", args, timeout=timeout)

    techs: list[str] = []
    raw_records: list[dict[str, Any]] = []

    for line in out.lines:
        try:
            rec = json.loads(line)
            raw_records.append(rec)
            # WhatWeb JSON: plugins dict has detected technologies
            plugins = rec.get("plugins", {})
            for plugin_name, plugin_data in plugins.items():
                if plugin_name.lower() not in ("ip", "country", "httpserver"):
                    techs.append(plugin_name)
        except json.JSONDecodeError:
            continue

    return {
        "target": target,
        "technologies": sorted(set(techs)),
        "raw": raw_records,
    }


async def detect_tech_stack(
    targets: list[Target],
    *,
    timeout: int = 300,
) -> list[Target]:
    """Enrich Target models with tech-stack info from httpx and whatweb.

    Modifies targets in-place and returns them.
    """
    hosts = [t.host for t in targets if t.host]
    if not hosts:
        return targets

    # httpx probe (fast, batch)
    httpx_results: dict[str, dict[str, Any]] = {}
    if _resolve_httpx_bin():
        records = await httpx_probe(hosts, timeout=timeout)
        for rec in records:
            # Match by input first, fallback to resolved host
            key = (rec.get("input") or rec.get("host") or "").lower().strip()
            if key:
                httpx_results[key] = rec
            host_only = rec.get("host", "").lower().strip()
            if host_only and host_only not in httpx_results:
                httpx_results[host_only] = rec
    else:
        log.warning("httpx / httpx-toolkit not found — skipping HTTP probe")

    # Enrich targets
    for t in targets:
        host_key = t.host.lower()
        rec = httpx_results.get(host_key, {})
        if rec:
            t.is_live = True
            techs = rec.get("tech", [])
            if isinstance(techs, list):
                t.tech_stack = list(set(t.tech_stack + techs))
            webserver = rec.get("webserver", "")
            if webserver and webserver not in t.tech_stack:
                t.tech_stack.append(webserver)

    # whatweb (slower, per-host — only for live targets if available)
    if ToolRunner.is_available("whatweb"):
        for t in targets:
            if t.is_live:
                try:
                    result = await whatweb_scan(t.host, timeout=60)
                    new_techs = result.get("technologies", [])
                    t.tech_stack = list(set(t.tech_stack + new_techs))
                except Exception as e:
                    log.debug("whatweb failed for %s: %s", t.host, e)
    else:
        log.warning("whatweb not found — skipping fingerprinting")

    return targets

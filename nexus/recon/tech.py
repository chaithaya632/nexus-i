"""Tech-stack detection wrappers — httpx probe + whatweb fingerprinting."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from nexus.db.models import Target
from nexus.recon.runner import ToolRunner, validate_cli_target, validate_extra_args

log = logging.getLogger("nexus.recon.tech")


def _endpoint_key(url_or_host: str, *, default_scheme: str = "http") -> tuple[str, str, int]:
    """Return a non-colliding (host, scheme, port) key for HTTP/HTTPS endpoints."""
    raw = (url_or_host or "").strip()
    if "://" in raw:
        p = urlparse(raw)
        scheme = (p.scheme or default_scheme).lower()
        host = (p.hostname or "").lower()
        port = p.port or (443 if scheme == "https" else 80)
        return host, scheme, port
    p = urlparse(f"{default_scheme}://{raw}")
    host = (p.hostname or "").lower()
    port = p.port or (443 if default_scheme == "https" else 80)
    return host, default_scheme, port


def _record_endpoint_key(rec: dict[str, Any]) -> tuple[str, str, int]:
    """Extract (host, scheme, port) from an httpx JSON record."""
    url = str(rec.get("url") or "").strip()
    if url:
        return _endpoint_key(url)
    scheme = str(rec.get("scheme") or "http").lower().strip()
    raw_host = str(rec.get("host") or rec.get("input") or "").strip().lower()
    raw_port = rec.get("port")
    if isinstance(raw_port, int) or (isinstance(raw_port, str) and raw_port.isdigit()):
        return raw_host, scheme, int(raw_port)
    return _endpoint_key(raw_host, default_scheme=scheme)


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

    clean_targets = [validate_cli_target(t, label="target") for t in targets]
    safe_extra = validate_extra_args(extra_args)

    httpx_bin = _resolve_httpx_bin()
    if not httpx_bin:
        log.warning("ProjectDiscovery httpx/httpx-toolkit not found — skipping HTTP probe")
        return []

    stdin_data = "\n".join(clean_targets)
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
    if safe_extra:
        args.extend(safe_extra)

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
    clean_target = validate_cli_target(target, label="target")
    args = [
        "--log-json=-",  # JSON to stdout
        f"--aggression={int(aggression)}",
        "--color=never",
        clean_target,
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

    # httpx probe (fast, batch) — keyed by (host, scheme, port) to prevent http/https collisions
    httpx_results: dict[tuple[str, str, int], dict[str, Any]] = {}
    by_host: dict[str, list[dict[str, Any]]] = {}
    if _resolve_httpx_bin():
        records = await httpx_probe(hosts, timeout=timeout)
        for rec in records:
            ep_key = _record_endpoint_key(rec)
            if ep_key[0]:
                httpx_results[ep_key] = rec
                by_host.setdefault(ep_key[0], []).append(rec)
            if rec.get("input"):
                in_key = _endpoint_key(str(rec["input"]))
                if in_key[0]:
                    httpx_results.setdefault(in_key, rec)
                    if ep_key[0] and in_key[0] != ep_key[0]:
                        by_host.setdefault(in_key[0], []).append(rec)
    else:
        log.warning("httpx / httpx-toolkit not found — skipping HTTP probe")

    # Enrich targets and track best live URL (supporting HTTPS & non-standard ports) for whatweb
    live_urls: dict[str, str] = {}
    for t in targets:
        raw_host = (t.host or "").strip()
        if "://" in raw_host:
            ep_key = _endpoint_key(raw_host)
            matched = [httpx_results[ep_key]] if ep_key in httpx_results else []
        elif ":" in raw_host and not raw_host.startswith("[") and raw_host.rsplit(":", 1)[1].isdigit():
            h_only, p_str = raw_host.rsplit(":", 1)
            port_num = int(p_str)
            matched = [
                rec for (kh, _ks, kp), rec in httpx_results.items()
                if kh == h_only.lower() and kp == port_num
            ]
        else:
            matched = by_host.get(raw_host.lower(), [])

        for rec in matched:
            t.is_live = True
            techs = rec.get("tech", [])
            if isinstance(techs, list):
                t.tech_stack = list(set(t.tech_stack + techs))
            webserver = rec.get("webserver", "")
            if webserver and webserver not in t.tech_stack:
                t.tech_stack.append(webserver)
            rec_url = str(rec.get("url") or "").strip()
            if rec_url:
                cur_url = live_urls.get(t.host, "")
                if not cur_url or (rec_url.startswith("https://") and not cur_url.startswith("https://")):
                    live_urls[t.host] = rec_url

    # whatweb (slower, per-host — only for live targets if available)
    if ToolRunner.is_available("whatweb"):
        for t in targets:
            if t.is_live:
                ww_target = live_urls.get(t.host) or t.host
                try:
                    result = await whatweb_scan(ww_target, timeout=60)
                    new_techs = result.get("technologies", [])
                    t.tech_stack = list(set(t.tech_stack + new_techs))
                except Exception as e:
                    log.debug("whatweb failed for %s: %s", ww_target, e)
    else:
        log.warning("whatweb not found — skipping fingerprinting")

    return targets

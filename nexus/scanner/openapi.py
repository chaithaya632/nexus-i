"""OpenAPI / Swagger specification parser and API security surface analyzer."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import yaml

from nexus.db.models import Finding, Severity
from nexus.scanner._http import parse_url_target

log = logging.getLogger("nexus.scanner.openapi")

_PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")
_WRITE_METHODS = frozenset({"post", "put", "patch", "delete"})
_BLOCKED_METADATA_HOSTS = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)


def _is_ssrf_unsafe_server_url(srv_url: str, *, allowed_host: str = "") -> bool:
    """Return True if *srv_url* points to metadata/private/loopback targets not matching *allowed_host*."""
    parsed = urlparse(srv_url)
    if parsed.scheme.lower() not in ("http", "https"):
        return True
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return True
    if allowed_host and host == allowed_host.lower():
        return False
    if host in _BLOCKED_METADATA_HOSTS or host.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        if (
            ip.is_link_local
            or ip.is_loopback
            or ip.is_private
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True
    except ValueError:
        pass
    return False


def _substitute_path_params(path: str) -> str:
    """Replace OpenAPI path parameters like `{user_id}` with deterministic sample values."""

    def _repl(match: re.Match[str]) -> str:
        name = match.group(1).lower()
        if "uuid" in name:
            return "00000000-0000-0000-0000-000000000001"
        if "id" in name or "num" in name:
            return "1"
        return "test"

    return _PATH_PARAM_RE.sub(_repl, path)


def parse_openapi_spec(spec_path: str | Path, base_url_override: str = "") -> dict[str, Any]:
    """Parse an OpenAPI v3 or Swagger v2 JSON/YAML file into structured endpoint metadata."""
    p = Path(spec_path)
    if not p.is_file():
        raise FileNotFoundError(f"OpenAPI spec not found: {p}")

    raw_text = p.read_text(encoding="utf-8", errors="replace")
    try:
        spec = json.loads(raw_text)
    except json.JSONDecodeError:
        spec = yaml.safe_load(raw_text)

    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        raise ValueError(f"Invalid OpenAPI/Swagger specification (missing 'paths'): {p}")

    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    title = str(info.get("title", p.name))
    version = str(info.get("version", ""))

    allowed_base_host = (
        (urlparse(base_url_override).hostname or "").strip().lower() if base_url_override else ""
    )
    base_urls: list[str] = []
    # OpenAPI 3.x servers
    servers = spec.get("servers")
    if isinstance(servers, list):
        for srv in servers:
            if isinstance(srv, dict) and isinstance(srv.get("url"), str):
                srv_url = srv["url"].strip()
                if srv_url.startswith(("http://", "https://")):
                    if _is_ssrf_unsafe_server_url(srv_url, allowed_host=allowed_base_host):
                        log.warning("Blocked unsafe OpenAPI server URL (SSRF guard): %s", srv_url)
                        continue
                    base_urls.append(srv_url.rstrip("/"))
                elif srv_url.startswith("/") and base_url_override:
                    joined = urljoin(
                        base_url_override.rstrip("/") + "/", srv_url.lstrip("/")
                    ).rstrip("/")
                    base_urls.append(joined)

    # Swagger 2.0 host + basePath + schemes
    if not base_urls and spec.get("host"):
        schemes = spec.get("schemes") or ["https"]
        scheme = "https" if "https" in schemes else schemes[0]
        base_path = str(spec.get("basePath", "")).strip()
        if base_path and not base_path.startswith("/"):
            base_path = "/" + base_path
        sw_url = f"{scheme}://{spec['host'].strip()}{base_path.rstrip('/')}"
        if _is_ssrf_unsafe_server_url(sw_url, allowed_host=allowed_base_host):
            log.warning("Blocked unsafe Swagger host URL (SSRF guard): %s", sw_url)
        else:
            base_urls.append(sw_url)

    if base_url_override:
        clean_override = base_url_override.rstrip("/")
        if clean_override not in base_urls:
            base_urls.insert(0, clean_override)

    # Check security schemes
    components = spec.get("components") if isinstance(spec.get("components"), dict) else {}
    sec_schemes = components.get("securitySchemes") or spec.get("securityDefinitions") or {}
    has_security_schemes = bool(isinstance(sec_schemes, dict) and sec_schemes)
    global_security = spec.get("security")

    endpoints: list[dict[str, Any]] = []
    urls: list[str] = []
    seen_urls: set[str] = set()
    unauth_endpoints: list[dict[str, Any]] = []

    primary_base = base_urls[0] if base_urls else ""
    for raw_path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        concrete_path = _substitute_path_params(str(raw_path))
        full_url = f"{primary_base}/{concrete_path.lstrip('/')}" if primary_base else concrete_path

        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue

            if "security" in op:
                op_sec = op.get("security")
                auth_required = bool(op_sec)
            elif global_security is not None:
                auth_required = bool(global_security)
            else:
                auth_required = False

            params = [
                pr.get("name", "")
                for pr in (path_item.get("parameters", []) + op.get("parameters", []))
                if isinstance(pr, dict) and pr.get("name")
            ]
            ep = {
                "method": method.upper(),
                "path": str(raw_path),
                "url": full_url,
                "auth_required": auth_required,
                "explicitly_public": op.get("security") == [],
                "params": params,
            }
            endpoints.append(ep)
            if not auth_required:
                unauth_endpoints.append(ep)

            if full_url.startswith(("http://", "https://")) and full_url not in seen_urls:
                seen_urls.add(full_url)
                urls.append(full_url)

    return {
        "title": title,
        "version": version,
        "base_urls": base_urls,
        "has_security_schemes": has_security_schemes,
        "endpoints": endpoints,
        "urls": urls,
        "unauthenticated_endpoints": unauth_endpoints,
    }


def audit_openapi_spec(
    spec_path: str | Path, base_url_override: str = ""
) -> tuple[list[str], list[Finding]]:
    """Extract target API URLs and identify security schema weaknesses from an OpenAPI spec."""
    parsed = parse_openapi_spec(spec_path, base_url_override=base_url_override)
    findings: list[Finding] = []

    anchor_url = parsed["base_urls"][0] if parsed["base_urls"] else base_url_override
    host, port, proto = parse_url_target(anchor_url) if anchor_url else ("api-spec", None, "https")

    if not parsed["has_security_schemes"] and parsed["endpoints"]:
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol=proto,
                title="OpenAPI: No Security Schemes Defined",
                description=(
                    f"Specification '{parsed['title']}' defines {len(parsed['endpoints'])} API operation(s) "
                    f"without any securitySchemes or securityDefinitions."
                ),
                severity=Severity.LOW,
                cwe_id="CWE-306",
                tool_source="openapi",
                evidence=f"Spec: {Path(spec_path).name} ({len(parsed['endpoints'])} endpoints)",
            )
        )

    unauth_writes = [
        ep for ep in parsed["unauthenticated_endpoints"] if ep["method"].lower() in _WRITE_METHODS
    ]
    if unauth_writes:
        sample = ", ".join(f"{e['method']} {e['path']}" for e in unauth_writes[:8])
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol=proto,
                title=f"OpenAPI: {len(unauth_writes)} State-Changing Endpoints Lack Security Requirement",
                description=(
                    f"Write operations in '{parsed['title']}' do not require authentication in the API schema."
                ),
                severity=Severity.MEDIUM,
                cwe_id="CWE-306",
                tool_source="openapi",
                evidence=f"Endpoints: {sample}",
            )
        )

    insecure_servers = [
        u
        for u in parsed["base_urls"]
        if u.startswith("http://") and "localhost" not in u and "127.0.0.1" not in u
    ]
    if insecure_servers:
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol=proto,
                title="OpenAPI: Cleartext HTTP Server URL Declared",
                description="API specification exposes non-localhost HTTP endpoint URL(s) without TLS.",
                severity=Severity.LOW,
                cwe_id="CWE-319",
                tool_source="openapi",
                evidence="Servers: " + ", ".join(insecure_servers[:5]),
            )
        )

    log.info(
        "Parsed OpenAPI '%s': %d URLs, %d endpoints, %d spec findings",
        parsed["title"],
        len(parsed["urls"]),
        len(parsed["endpoints"]),
        len(findings),
    )
    return parsed["urls"], findings

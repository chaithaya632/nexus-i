"""Offline & on-demand CISA KEV / NVD CVE catalog importers for NEXUS KnowledgeGraph."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml

log = logging.getLogger("nexus.brain.cve_sync")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_MAX_FEED_BYTES = 50 * 1024 * 1024  # 50 MiB safety cap
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _write_merged_cves(dest: Path, cves_map: dict[str, dict[str, Any]]) -> None:
    """Merge new CVE entries into an existing YAML catalog without clobbering custom entries."""
    existing_cves: dict[str, Any] = {}
    if dest.is_file():
        try:
            loaded = yaml.safe_load(dest.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("cves"), dict):
                existing_cves = dict(loaded["cves"])
        except (yaml.YAMLError, OSError) as exc:
            log.warning("Could not read existing CVE file %s for merge: %s", dest, exc)
    merged = {**existing_cves, **cves_map}
    dest.write_text(
        yaml.safe_dump({"cves": merged}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _slug(raw: str) -> str:
    return _SLUG_RE.sub("-", (raw or "").strip().lower()).strip("-") or "generic"


def _normalize_kev_record(item: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    cve_id = str(item.get("cveID") or "").strip().upper()
    if not _CVE_RE.match(cve_id):
        return None
    vendor = str(item.get("vendorProject") or "").strip()
    product = str(item.get("product") or "").strip()
    prod_slug = _slug(f"{vendor}-{product}" if vendor and product else (product or vendor or "generic"))
    fps = [x for x in dict.fromkeys([product, vendor]) if x]
    ransomware = str(item.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
    cwes = item.get("cwes") or []
    cwe = str(cwes[0]).strip() if isinstance(cwes, list) and cwes else ""
    desc = str(item.get("shortDescription") or item.get("vulnerabilityName") or cve_id).strip()
    action = str(item.get("requiredAction") or "").strip()

    return cve_id, {
        "description": desc,
        "severity": "critical" if ransomware else "high",
        "cvss": 9.0 if ransomware else 8.0,
        "products": [prod_slug],
        "cwe": cwe,
        "fingerprints": fps or [prod_slug],
        "remediation": action,
    }


def import_cisa_kev_data(data: dict[str, Any], out_dir: Path) -> tuple[int, Path]:
    """Convert a parsed CISA KEV JSON object into `<out_dir>/cves/kev.yaml`."""
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise ValueError("Invalid CISA KEV JSON: missing 'vulnerabilities' list")

    cves_map: dict[str, dict[str, Any]] = {}
    for item in vulns:
        if not isinstance(item, dict):
            continue
        parsed = _normalize_kev_record(item)
        if parsed:
            cve_id, entry = parsed
            cves_map[cve_id] = entry

    cves_dir = Path(out_dir) / "cves"
    cves_dir.mkdir(parents=True, exist_ok=True)
    dest = cves_dir / "kev.yaml"
    _write_merged_cves(dest, cves_map)
    return len(cves_map), dest


def import_cisa_kev_file(src_path: str | Path, data_dir: Path) -> tuple[int, Path]:
    """Load a local CISA KEV JSON file and persist it under `<data_dir>/cves/kev.yaml`."""
    p = Path(src_path)
    if not p.is_file():
        raise FileNotFoundError(f"CISA KEV JSON file not found: {p}")
    raw = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(raw, dict):
        raise ValueError(f"Expected JSON object in {p}")
    return import_cisa_kev_data(raw, data_dir)


def _extract_nvd_cpe_specs(cve_obj: dict[str, Any]) -> tuple[list[str], list[str]]:
    products: list[str] = []
    fingerprints: list[str] = []
    configs = cve_obj.get("configurations") or []
    for cfg in configs:
        if not isinstance(cfg, dict):
            continue
        for node in cfg.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict) or not match.get("vulnerable", True):
                    continue
                criteria = str(match.get("criteria") or "")
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue
                raw_prod = parts[4].strip()
                if raw_prod in ("*", "-", ""):
                    continue
                prod_name = _slug(raw_prod)
                if raw_prod not in fingerprints and raw_prod.lower() not in {f.lower() for f in fingerprints}:
                    fingerprints.append(raw_prod)
                ver_start_inc = match.get("versionStartIncluding")
                ver_start_exc = match.get("versionStartExcluding")
                ver_end_exc = match.get("versionEndExcluding")
                ver_end_inc = match.get("versionEndIncluding")
                exact_ver = parts[5] if parts[5] not in ("*", "-", "") else ""

                clauses: list[str] = []
                if ver_start_inc:
                    clauses.append(f">={ver_start_inc}")
                elif ver_start_exc:
                    clauses.append(f">{ver_start_exc}")
                if ver_end_exc:
                    clauses.append(f"<{ver_end_exc}")
                elif ver_end_inc:
                    clauses.append(f"<={ver_end_inc}")

                if clauses:
                    products.append(f"{prod_name} {','.join(clauses)}" if prod_name and prod_name != "*" else ",".join(clauses))
                elif exact_ver:
                    products.append(f"{prod_name}-{exact_ver}")
                elif prod_name:
                    products.append(prod_name)
    return (list(dict.fromkeys(products)) or ["generic"])[:8], fingerprints[:6]


def import_nvd_json_data(data: dict[str, Any], out_dir: Path) -> tuple[int, Path]:
    """Convert an NVD API v2.0 JSON feed into `<out_dir>/cves/nvd_custom.yaml`."""
    items = data.get("vulnerabilities")
    if not isinstance(items, list):
        raise ValueError("Invalid NVD JSON: missing 'vulnerabilities' list")

    cves_map: dict[str, dict[str, Any]] = {}
    for wrapper in items:
        if not isinstance(wrapper, dict):
            continue
        cve_obj = wrapper.get("cve") if isinstance(wrapper.get("cve"), dict) else wrapper
        cve_id = str(cve_obj.get("id") or "").strip().upper()
        if not _CVE_RE.match(cve_id):
            continue

        desc = cve_id
        for d in cve_obj.get("descriptions") or []:
            if isinstance(d, dict) and d.get("lang") == "en" and d.get("value"):
                desc = str(d["value"]).strip()
                break

        cvss = 5.0
        severity = "medium"
        metrics = cve_obj.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            mlist = metrics.get(key)
            if isinstance(mlist, list) and mlist and isinstance(mlist[0], dict):
                cdata = mlist[0].get("cvssData") or {}
                if isinstance(cdata, dict) and cdata.get("baseScore") is not None:
                    cvss = float(cdata["baseScore"])
                    sev_raw = str(cdata.get("baseSeverity") or mlist[0].get("baseSeverity") or "").lower()
                    if sev_raw in ("critical", "high", "medium", "low"):
                        severity = sev_raw
                    else:
                        severity = "critical" if cvss >= 9.0 else ("high" if cvss >= 7.0 else ("medium" if cvss >= 4.0 else "low"))
                    break

        cwe = ""
        for w in cve_obj.get("weaknesses") or []:
            if isinstance(w, dict):
                for wd in w.get("description") or []:
                    if isinstance(wd, dict) and str(wd.get("value", "")).startswith("CWE-"):
                        cwe = str(wd["value"]).strip()
                        break
            if cwe:
                break

        products, fps = _extract_nvd_cpe_specs(cve_obj)
        cves_map[cve_id] = {
            "description": desc[:400],
            "severity": severity,
            "cvss": cvss,
            "products": products,
            "cwe": cwe,
            "fingerprints": fps or products[:1],
        }

    cves_dir = Path(out_dir) / "cves"
    cves_dir.mkdir(parents=True, exist_ok=True)
    dest = cves_dir / "nvd_custom.yaml"
    _write_merged_cves(dest, cves_map)
    return len(cves_map), dest


def import_nvd_json_file(src_path: str | Path, data_dir: Path) -> tuple[int, Path]:
    """Load a local NVD v2 JSON file and persist it under `<data_dir>/cves/nvd_custom.yaml`."""
    p = Path(src_path)
    if not p.is_file():
        raise FileNotFoundError(f"NVD JSON file not found: {p}")
    raw = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(raw, dict):
        raise ValueError(f"Expected JSON object in {p}")
    return import_nvd_json_data(raw, data_dir)


async def sync_cisa_kev(
    data_dir: Path,
    *,
    url: str = CISA_KEV_URL,
    timeout: float = 30.0,
    max_bytes: int = _MAX_FEED_BYTES,
) -> tuple[int, Path]:
    """Download the official CISA KEV JSON catalog and persist it under `<data_dir>/cves/kev.yaml`."""
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ValueError(f"KEV sync URL must use https:// scheme, got: {url!r}")

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            if urlsplit(str(resp.url)).scheme.lower() != "https":
                raise ValueError(f"KEV sync redirected to non-HTTPS URL: {resp.url}")
            cl_header = resp.headers.get("content-length")
            if cl_header and cl_header.isdigit() and int(cl_header) > max_bytes:
                raise ValueError(f"KEV feed exceeds maximum allowed size ({max_bytes} bytes)")
            buf = bytearray()
            async for chunk in resp.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise ValueError(f"KEV feed exceeds maximum allowed size ({max_bytes} bytes)")
            payload = json.loads(buf.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Unexpected response format from KEV feed")
    return import_cisa_kev_data(payload, data_dir)

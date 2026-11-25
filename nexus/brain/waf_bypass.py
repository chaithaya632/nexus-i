"""WAF bypass technique library — 200+ techniques per WAF type."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

BUILTIN_BYPASSES: dict[str, list[dict[str, str]]] = {
    "cloudflare": [
        {"technique": "origin_ip_leak", "description": "Find origin IP via DNS history, Censys, Shodan", "tool": "custom"},
        {"technique": "header_bypass", "description": "X-Originating-IP / X-Forwarded-For / X-Real-IP headers", "tool": "curl"},
        {"technique": "subdomain_bypass", "description": "Target non-proxied subdomains (direct-connect, staging)", "tool": "subfinder"},
        {"technique": "cache_poison", "description": "Cache poisoning via Host header manipulation", "tool": "custom"},
        {"technique": "unicode_normalization", "description": "Unicode/UTF-8 encoding bypass for SQLi/XSS payloads", "tool": "sqlmap"},
        {"technique": "chunked_transfer", "description": "HTTP chunked transfer encoding to split payloads", "tool": "custom"},
        {"technique": "websocket_bypass", "description": "Attack via WebSocket connections (less filtered)", "tool": "custom"},
    ],
    "akamai": [
        {"technique": "path_traversal_encoding", "description": "Double URL encoding, path parameter pollution", "tool": "ffuf"},
        {"technique": "http_method_override", "description": "X-HTTP-Method-Override header", "tool": "curl"},
        {"technique": "json_content_type", "description": "Change Content-Type to application/json", "tool": "curl"},
        {"technique": "parameter_pollution", "description": "HPP — duplicate parameters to confuse parser", "tool": "custom"},
    ],
    "modsecurity": [
        {"technique": "comment_injection", "description": "SQL comments to break signature: /*!50000 UNION*/", "tool": "sqlmap"},
        {"technique": "case_variation", "description": "Mixed case: SeLeCt, UnIoN", "tool": "sqlmap"},
        {"technique": "whitespace_bypass", "description": "Replace spaces with tabs, newlines, /**/ comments", "tool": "sqlmap"},
        {"technique": "null_byte", "description": "Null byte injection %00 to terminate strings", "tool": "custom"},
        {"technique": "paranoia_level_check", "description": "Test at CRS PL1 (default) vs PL2-4 rules", "tool": "nuclei"},
    ],
    "aws_waf": [
        {"technique": "body_size_bypass", "description": "AWS WAF only inspects first 8KB of body", "tool": "custom"},
        {"technique": "content_type_switch", "description": "Switch between form-data and JSON", "tool": "curl"},
        {"technique": "regional_bypass", "description": "Target regional endpoints with different WAF rules", "tool": "custom"},
    ],
    "generic": [
        {"technique": "encoding_layers", "description": "Double/triple URL encoding", "tool": "custom"},
        {"technique": "header_injection", "description": "Inject via uncommon headers (X-Custom, Referer)", "tool": "curl"},
        {"technique": "http2_downgrade", "description": "Force HTTP/1.1 to bypass HTTP/2-only rules", "tool": "curl"},
        {"technique": "slow_rate", "description": "Slow request rate to avoid rate-based blocks", "tool": "custom"},
        {"technique": "ip_rotation", "description": "Rotate source IPs via proxy chains", "tool": "proxychains"},
        {"technique": "user_agent_rotation", "description": "Use legitimate browser User-Agent strings", "tool": "custom"},
        {"technique": "fragment_payloads", "description": "Split attack payloads across multiple parameters", "tool": "custom"},
    ],
}


class WAFBypassLibrary:
    """Searchable WAF bypass technique database."""

    def __init__(self) -> None:
        self._bypasses: dict[str, list[dict[str, str]]] = dict(BUILTIN_BYPASSES)

    @property
    def technique_count(self) -> int:
        return sum(len(v) for v in self._bypasses.values())

    @property
    def waf_count(self) -> int:
        return len(self._bypasses)

    def load_from_directory(self, knowledge_dir: Path) -> None:
        waf_dir = knowledge_dir / "waf"
        if not waf_dir.is_dir():
            return
        for yaml_file in sorted(waf_dir.glob("*.yaml")):
            try:
                raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError):
                continue
            if isinstance(raw, dict):
                for waf_name, techniques in raw.items():
                    if isinstance(techniques, list):
                        existing = self._bypasses.setdefault(waf_name, [])
                        existing.extend(techniques)

    def get_bypasses(self, waf_name: str) -> list[dict[str, str]]:
        """Get bypass techniques for a specific WAF."""
        key = waf_name.lower().strip()
        # Direct match
        for name, bypasses in self._bypasses.items():
            if key in name.lower():
                return bypasses + self._bypasses.get("generic", [])
        # Fallback to generic
        return self._bypasses.get("generic", [])

    def identify_waf(self, headers: dict[str, str], body: str = "") -> str:
        """Simple WAF identification from response headers."""
        h = {k.lower(): v.lower() for k, v in headers.items()}
        if "cf-ray" in h or "cloudflare" in h.get("server", ""):
            return "cloudflare"
        if "akamai" in h.get("server", "") or "x-akamai" in " ".join(h.keys()):
            return "akamai"
        if "x-sucuri" in " ".join(h.keys()):
            return "sucuri"
        if "x-cdn" in h and "imperva" in h.get("x-cdn", ""):
            return "imperva"
        if any("modsecurity" in v for v in h.values()):
            return "modsecurity"
        if "x-amz-cf-id" in h:
            return "aws_waf"
        return "unknown"

    def stats(self) -> dict[str, int]:
        return {"waf_types": self.waf_count, "techniques": self.technique_count}

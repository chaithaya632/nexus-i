"""Payload database - PoC templates and encoders.

Payloads are loaded from YAML data files in the knowledge base.
Built-in templates use placeholder variables:
    {LHOST}  - attacker IP
    {LPORT}  - attacker port
    {TARGET} - target URL/IP
    {CMD}    - command to execute
"""

from __future__ import annotations

import base64
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Payload:
    """Single payload template."""
    name: str
    category: str
    platform: str = "linux"
    language: str = ""
    template: str = ""
    description: str = ""
    evasion_level: int = 0
    tags: list[str] = field(default_factory=list)


class PayloadDB:
    """In-memory payload database.

    On Kali/Linux systems, payloads load from YAML knowledge base files.
    On other systems, the DB starts empty and loads from YAML only.
    This avoids antivirus false positives on development machines.
    """

    def __init__(self) -> None:
        self._payloads: list[Payload] = []
        self._load_category_stubs()

    @property
    def count(self) -> int:
        return len(self._payloads)

    def _load_category_stubs(self) -> None:
        """Register category metadata without inline exploit strings.

        Actual payload templates are loaded from YAML via load_from_yaml().
        Categories: revshell, webshell, sqli, xss, ssrf, cmdi, lfi, ssti, xxe, auth_bypass
        """
        categories = [
            ("revshell", "Reverse shell payloads for bash, python, php, perl, ruby, nc, socat, java, nodejs"),
            ("webshell", "Web shell templates for PHP, JSP, ASPX, Python CGI"),
            ("sqli", "SQL injection payloads: auth bypass, union, error-based, blind, time-based"),
            ("xss", "Cross-site scripting payloads: reflected, stored, DOM-based, filter bypass"),
            ("ssrf", "Server-side request forgery payloads: localhost, cloud metadata, protocol handlers"),
            ("cmdi", "OS command injection payloads: semicolon, pipe, backtick, blind OOB"),
            ("lfi", "Local file inclusion and path traversal payloads"),
            ("ssti", "Server-side template injection payloads for Jinja2, Twig, Mako, ERB"),
            ("xxe", "XML external entity payloads: file read, SSRF, OOB exfiltration"),
            ("auth_bypass", "Authentication bypass payloads: header injection, path manipulation"),
        ]
        # Store as stub payloads so categories() works before YAML load
        for cat_name, cat_desc in categories:
            self._payloads.append(Payload(
                name=f"_category_{cat_name}",
                category=cat_name,
                platform="universal",
                description=cat_desc,
            ))

    def load_from_yaml(self, yaml_dir: Path) -> None:
        """Load payload templates from YAML files in the knowledge base."""
        if not yaml_dir.is_dir():
            return
        for f in sorted(yaml_dir.glob("*.yaml")):
            try:
                raw = yaml.safe_load(f.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError):
                continue
            if not isinstance(raw, dict):
                continue
            for entry in raw.get("payloads", []):
                if isinstance(entry, dict) and "name" in entry and "template" in entry:
                    self._payloads.append(Payload(
                        name=entry["name"],
                        category=entry.get("category", "custom"),
                        platform=entry.get("platform", "linux"),
                        language=entry.get("language", ""),
                        template=entry["template"],
                        description=entry.get("description", ""),
                        evasion_level=entry.get("evasion_level", 0),
                        tags=entry.get("tags", []),
                    ))

    def add_payload(self, payload: Payload) -> None:
        """Add a payload programmatically."""
        self._payloads.append(payload)

    def search(
        self,
        category: str | None = None,
        platform: str | None = None,
        language: str | None = None,
        keyword: str | None = None,
        max_evasion: int | None = None,
    ) -> list[Payload]:
        """Search payloads by criteria."""
        # Exclude internal category stubs from search results
        results = [p for p in self._payloads if not p.name.startswith("_category_")]
        if category:
            results = [p for p in results if p.category == category]
        if platform:
            results = [p for p in results if p.platform in (platform, "universal")]
        if language:
            results = [p for p in results if p.language == language]
        if keyword:
            kw = keyword.lower()
            results = [
                p for p in results
                if kw in p.name.lower()
                or kw in p.description.lower()
                or any(kw in t for t in p.tags)
            ]
        if max_evasion is not None:
            results = [p for p in results if p.evasion_level <= max_evasion]
        return results

    def render(self, payload: Payload, variables: dict[str, str]) -> str:
        """Render a payload template with actual values."""
        result = payload.template
        for key, val in variables.items():
            placeholder = "{" + key.upper() + "}"
            result = result.replace(placeholder, val)
        return result

    def get_by_name(self, name: str) -> Payload | None:
        """Get a payload by exact name."""
        for p in self._payloads:
            if p.name == name:
                return p
        return None

    def categories(self) -> list[str]:
        """List all payload categories."""
        return sorted({p.category for p in self._payloads})


# -- Encoder utilities (safe on all platforms) --


def encode_base64(payload: str) -> str:
    """Encode payload as base64."""
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


def encode_url(payload: str) -> str:
    """URL-encode a payload string."""
    return urllib.parse.quote(payload, safe="")


def encode_double_url(payload: str) -> str:
    """Double URL-encode a payload string."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def encode_hex(payload: str) -> str:
    """Hex-encode a payload string."""
    return "".join(f"\\x{b:02x}" for b in payload.encode("utf-8"))


def encode_unicode(payload: str) -> str:
    """Unicode-escape a payload string."""
    return "".join(f"\\u{ord(c):04x}" for c in payload)


def encode_html_entity(payload: str) -> str:
    """HTML entity-encode a payload string."""
    return "".join(f"&#{ord(c)};" for c in payload)


def encode_js_char_code(payload: str) -> str:
    """Convert to JavaScript String.fromCharCode()."""
    codes = ",".join(str(ord(c)) for c in payload)
    return f"String.fromCharCode({codes})"

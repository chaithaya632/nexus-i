"""Baseline suppression engine (`.nexusignore`) for DevSecOps CI/CD workflows."""

from __future__ import annotations

import fnmatch
import logging
import shlex
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nexus.db.models import Finding

log = logging.getLogger("nexus.correlator.baseline")


def _normalize_cwe(val: str) -> str:
    s = val.strip().upper()
    if not s:
        return ""
    return s if s.startswith("CWE-") else f"CWE-{s}"


def _strip_inline_comment(line: str) -> str:
    """Strip unquoted `# ...` inline comments from a text rule line."""
    in_quote: str | None = None
    for idx, ch in enumerate(line):
        if ch in ("'", '"'):
            if in_quote is None:
                in_quote = ch
            elif in_quote == ch:
                in_quote = None
        elif ch == "#" and in_quote is None:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx].strip()
    return line.strip()


def _unquote_token(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ('"', "'"):
        return tok[1:-1]
    return tok


def _as_str_list(entry: dict[str, Any], *keys: str) -> list[str]:
    out: list[str] = []
    for k in keys:
        if k not in entry or entry[k] is None:
            continue
        val = entry[k]
        if isinstance(val, list):
            out.extend(str(item).strip() for item in val if item is not None and str(item).strip())
        else:
            s = str(val).strip()
            if s:
                out.append(s)
    return out


@dataclass
class IgnoreRule:
    """Single suppression predicate parsed from `.nexusignore`."""

    raw: str
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    titles: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    reason: str = ""

    def matches(self, finding: Finding) -> bool:
        """Return True iff every non-empty constraint in this rule matches the finding."""
        if not any(
            (self.cves, self.cwes, self.hosts, self.ports, self.tools, self.titles, self.severities)
        ):
            return False

        f_cves = {c.upper() for c in finding.cve_ids}
        if self.cves and not any(c.upper() in f_cves for c in self.cves):
            return False

        if self.cwes:
            f_cwe = _normalize_cwe(finding.cwe_id)
            if f_cwe not in {_normalize_cwe(c) for c in self.cwes}:
                return False

        if self.hosts:
            host_l = finding.host.lower()
            if not any(fnmatch.fnmatch(host_l, h.lower()) for h in self.hosts):
                return False

        if self.ports:
            p_str = str(finding.port or "")
            if p_str not in set(self.ports):
                return False

        if self.tools and finding.tool_source.lower() not in {t.lower() for t in self.tools}:
            return False

        if self.severities and finding.severity.value.lower() not in {
            s.lower() for s in self.severities
        }:
            return False

        if self.titles:
            title_l = finding.title.lower()
            matched_title = any(
                fnmatch.fnmatch(title_l, t.lower())
                if any(ch in t for ch in "*?[]")
                else t.lower() in title_l
                for t in self.titles
            )
            if not matched_title:
                return False

        return True


def _parse_text_line(line: str) -> IgnoreRule | None:
    stripped = _strip_inline_comment(line)
    if not stripped:
        return None
    rule = IgnoreRule(raw=stripped)
    try:
        # Preserve backslashes consistently on POSIX and Windows (e.g. C:\inetpub\wwwroot)
        tokens = shlex.split(stripped, posix=False)
    except ValueError:
        tokens = stripped.split()

    for raw_tok in tokens:
        tok = _unquote_token(raw_tok)
        if ":" in tok:
            k, v = tok.split(":", 1)
            kl = k.strip().lower()
            val = _unquote_token(v.strip())
            if not val:
                continue
            if kl == "cve":
                rule.cves.append(val)
            elif kl == "cwe":
                rule.cwes.append(_normalize_cwe(val))
            elif kl == "host":
                rule.hosts.append(val)
            elif kl == "port":
                rule.ports.append(val)
            elif kl == "tool":
                rule.tools.append(val)
            elif kl == "title":
                rule.titles.append(val)
            elif kl in ("sev", "severity"):
                rule.severities.append(val)
        else:
            upper = tok.upper()
            if upper.startswith("CVE-"):
                rule.cves.append(upper)
            elif upper.startswith("CWE-"):
                rule.cwes.append(upper)
            else:
                rule.titles.append(tok)
    return rule


def load_ignore_rules(ignore_path: str | Path) -> list[IgnoreRule]:
    """Load suppression rules from a line-based or YAML `.nexusignore` file."""
    p = Path(ignore_path)
    if not p.is_file():
        return []

    raw_text = p.read_text(encoding="utf-8", errors="replace")

    # Support optional YAML structured form (`ignores: [...]`)
    try:
        parsed_yaml = yaml.safe_load(raw_text)
    except yaml.YAMLError:
        parsed_yaml = None

    rules: list[IgnoreRule] = []
    if isinstance(parsed_yaml, dict) and isinstance(parsed_yaml.get("ignores"), list):
        for entry in parsed_yaml["ignores"]:
            if isinstance(entry, str):
                r = _parse_text_line(entry)
                if r:
                    rules.append(r)
            elif isinstance(entry, dict):
                r = IgnoreRule(
                    raw=str(entry),
                    cves=_as_str_list(entry, "cve", "cves"),
                    cwes=[_normalize_cwe(c) for c in _as_str_list(entry, "cwe", "cwes")],
                    hosts=_as_str_list(entry, "host", "hosts"),
                    ports=_as_str_list(entry, "port", "ports"),
                    tools=_as_str_list(entry, "tool", "tools"),
                    titles=_as_str_list(entry, "title", "titles"),
                    severities=_as_str_list(entry, "severity", "severities", "sev"),
                    reason=str(entry.get("reason", "")),
                )
                rules.append(r)
        return rules

    for line in raw_text.splitlines():
        r = _parse_text_line(line)
        if r:
            rules.append(r)
    return rules


def resolve_ignore_path(explicit_path: str | Path | None = None) -> Path | None:
    """Return explicit ignore path if it exists, else `.nexusignore` in cwd if present."""
    if explicit_path:
        p = Path(explicit_path)
        return p if p.is_file() else None
    default_p = Path.cwd() / ".nexusignore"
    return default_p if default_p.is_file() else None


def apply_baseline_suppressions(
    findings: Iterable[Finding],
    rules: list[IgnoreRule],
) -> tuple[list[Finding], int]:
    """Mark matching findings with `false_positive = True`; return (findings, suppressed_count)."""
    out = list(findings)
    if not rules:
        return out, 0

    suppressed = 0
    for f in out:
        if any(r.matches(f) for r in rules):
            if not f.false_positive:
                suppressed += 1
            f.false_positive = True
    return out, suppressed

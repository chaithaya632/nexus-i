"""Declarative YAML passive detection rule engine for extensible HTTP checks."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nexus.db.models import Finding, Severity
from nexus.scanner._http import parse_url_target

log = logging.getLogger("nexus.scanner.yaml_rules")

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@dataclass
class PassiveRule:
    """Single declarative passive security check loaded from YAML."""

    id: str
    title: str
    severity: Severity = Severity.INFO
    cwe_id: str = ""
    description: str = ""
    remediation: str = ""
    url_regex: str = ""
    body_regex: str = ""
    header_regex: str = ""
    status_codes: list[int] = field(default_factory=list)
    confirmed: bool = False


class YamlPassiveRuleEngine:
    """Loads custom YAML passive check templates and matches HTTP traffic safely."""

    def __init__(self) -> None:
        self._rules: list[PassiveRule] = []
        self._compiled: dict[
            str, tuple[re.Pattern[str] | None, re.Pattern[str] | None, re.Pattern[str] | None]
        ] = {}

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def add_rule(self, rule: PassiveRule) -> None:
        try:
            u_re = re.compile(rule.url_regex, re.IGNORECASE) if rule.url_regex else None
            b_re = re.compile(rule.body_regex, re.IGNORECASE) if rule.body_regex else None
            h_re = re.compile(rule.header_regex, re.IGNORECASE) if rule.header_regex else None
        except re.error as exc:
            log.warning("Invalid regex in passive rule '%s': %s", rule.id, exc)
            return
        self._rules.append(rule)
        self._compiled[rule.id] = (u_re, b_re, h_re)

    def load_file(self, path: str | Path) -> int:
        p = Path(path)
        if not p.is_file():
            return 0
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            log.warning("Failed to load YAML passive rules %s: %s", p, exc)
            return 0
        items = (
            data.get("rules", [])
            if isinstance(data, dict)
            else (data if isinstance(data, list) else [])
        )
        added = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            rid = str(item.get("id") or "").strip()
            title = str(item.get("title") or "").strip()
            if not rid or not title:
                continue
            rule = PassiveRule(
                id=rid,
                title=title,
                severity=_SEV_MAP.get(str(item.get("severity", "info")).lower(), Severity.INFO),
                cwe_id=str(item.get("cwe_id") or ""),
                description=str(item.get("description") or title),
                remediation=str(item.get("remediation") or ""),
                url_regex=str(item.get("url_regex") or ""),
                body_regex=str(item.get("body_regex") or ""),
                header_regex=str(item.get("header_regex") or ""),
                status_codes=[int(c) for c in (item.get("status_codes") or []) if str(c).isdigit()],
                confirmed=bool(item.get("confirmed", False)),
            )
            self.add_rule(rule)
            added += 1
        return added

    def load_directory(self, directory: str | Path) -> int:
        d = Path(directory)
        if not d.is_dir():
            return 0
        total = 0
        for p in sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml"))):
            total += self.load_file(p)
        return total

    def inspect_response(
        self,
        url: str,
        *,
        status_code: int = 200,
        headers: dict[str, str] | Any = None,
        body: str = "",
    ) -> list[Finding]:
        """Evaluate loaded passive YAML rules against one HTTP response."""
        if not self._rules:
            return []
        host, port, proto = parse_url_target(url)
        hdr_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        body_sample = (body or "")[:200_000]

        findings: list[Finding] = []
        for rule in self._rules:
            if rule.status_codes and status_code not in rule.status_codes:
                continue
            u_re, b_re, h_re = self._compiled.get(rule.id, (None, None, None))
            if not (u_re or b_re or h_re):
                continue
            matched_parts: list[str] = []
            if u_re:
                m = u_re.search(url)
                if not m:
                    continue
                matched_parts.append(f"url={m.group(0)[:80]}")
            if h_re:
                m = h_re.search(hdr_blob)
                if not m:
                    continue
                matched_parts.append(f"header={m.group(0)[:80]}")
            if b_re:
                m = b_re.search(body_sample)
                if not m:
                    continue
                matched_parts.append(f"body={m.group(0)[:80]}")

            findings.append(
                Finding(
                    host=host,
                    port=port,
                    protocol=proto,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    cwe_id=rule.cwe_id,
                    remediation=rule.remediation,
                    tool_source=f"yaml_rule:{rule.id}",
                    evidence=f"URL: {url}\nRule: {rule.id}\nMatched: {', '.join(matched_parts)}",
                    confirmed=rule.confirmed,
                )
            )
        return findings

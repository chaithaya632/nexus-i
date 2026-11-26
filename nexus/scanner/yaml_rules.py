"""Declarative YAML passive detection rule engine for extensible HTTP checks."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nexus.db.models import Finding, Severity
from nexus.scanner._http import mask_secret_value, parse_url_target, redact_sensitive_url

log = logging.getLogger("nexus.scanner.yaml_rules")

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}
_SECRET_CWES = frozenset(
    {
        "CWE-312",
        "CWE-315",
        "CWE-321",
        "CWE-522",
        "CWE-532",
        "CWE-598",
        "CWE-640",
        "CWE-798",
    }
)
_AUTH_ECHO_RE = re.compile(
    r"(authorization|cookie|x-api-key|x-auth-token)\s*[:=]",
    re.IGNORECASE,
)


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
    owasp_category: str = ""
    scheme: str = ""  # optional "http" or "https"
    content_type_regex: str = ""
    absent_header_regex: str = ""
    exclude_body_regex: str = ""
    exclude_url_regex: str = ""
    mask_secret: bool = False


@dataclass(frozen=True)
class _CompiledRule:
    """Pre-compiled regex matchers for a PassiveRule."""

    u_re: re.Pattern[str] | None = None
    excl_u_re: re.Pattern[str] | None = None
    ct_re: re.Pattern[str] | None = None
    h_re: re.Pattern[str] | None = None
    abs_h_re: re.Pattern[str] | None = None
    b_re: re.Pattern[str] | None = None
    excl_b_re: re.Pattern[str] | None = None


def _compile_optional(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str] | None:
    """Compile a non-empty regex pattern or return None."""
    return re.compile(pattern, flags) if pattern else None


class YamlPassiveRuleEngine:
    """Loads custom YAML passive check templates and matches HTTP traffic safely."""

    def __init__(self) -> None:
        self._rules: list[PassiveRule] = []
        self._compiled: dict[str, _CompiledRule] = {}

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def _register_rule(self, rule: PassiveRule) -> bool:
        """Compile and register a rule; return False if any regex fails to compile."""
        try:
            compiled = _CompiledRule(
                u_re=_compile_optional(rule.url_regex),
                excl_u_re=_compile_optional(rule.exclude_url_regex),
                ct_re=_compile_optional(rule.content_type_regex),
                h_re=_compile_optional(rule.header_regex, re.IGNORECASE | re.MULTILINE),
                abs_h_re=_compile_optional(rule.absent_header_regex, re.IGNORECASE | re.MULTILINE),
                b_re=_compile_optional(rule.body_regex),
                excl_b_re=_compile_optional(rule.exclude_body_regex),
            )
        except re.error as exc:
            log.warning("Invalid regex in passive rule '%s': %s", rule.id, exc)
            return False

        rule.scheme = str(rule.scheme or "").strip().lower()
        if rule.id in self._compiled:
            log.warning("Duplicate passive rule ID '%s'; overwriting existing rule", rule.id)
            for idx, existing in enumerate(self._rules):
                if existing.id == rule.id:
                    self._rules[idx] = rule
                    break
        else:
            self._rules.append(rule)
        self._compiled[rule.id] = compiled
        return True

    def add_rule(self, rule: PassiveRule) -> None:
        self._register_rule(rule)

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
            (data.get("rules") or [])
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
            raw_codes = item.get("status_codes") or []
            if not isinstance(raw_codes, (list, tuple, set)):
                raw_codes = [raw_codes]
            rule = PassiveRule(
                id=rid,
                title=title,
                severity=_SEV_MAP.get(
                    str(item.get("severity", "info")).strip().lower(), Severity.INFO
                ),
                cwe_id=str(item.get("cwe_id") or ""),
                description=str(item.get("description") or title),
                remediation=str(item.get("remediation") or ""),
                url_regex=str(item.get("url_regex") or ""),
                body_regex=str(item.get("body_regex") or ""),
                header_regex=str(item.get("header_regex") or ""),
                status_codes=[int(c) for c in raw_codes if str(c).isdigit()],
                confirmed=bool(item.get("confirmed", False)),
                owasp_category=str(item.get("owasp_category") or ""),
                scheme=str(item.get("scheme") or "").strip().lower(),
                content_type_regex=str(item.get("content_type_regex") or ""),
                absent_header_regex=str(item.get("absent_header_regex") or ""),
                exclude_body_regex=str(item.get("exclude_body_regex") or ""),
                exclude_url_regex=str(item.get("exclude_url_regex") or ""),
                mask_secret=bool(item.get("mask_secret", False)),
            )
            if self._register_rule(rule):
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
        headers: dict[str, str] | list[tuple[str, str]] | Any = None,
        body: str = "",
    ) -> list[Finding]:
        """Evaluate loaded passive YAML rules against one HTTP response."""
        if not self._rules:
            return []
        host, port, proto = parse_url_target(url)
        if hasattr(headers, "multi_items"):
            hdr_items = list(headers.multi_items())
        elif isinstance(headers, list):
            hdr_items = list(headers)
        else:
            hdr_items = list((headers or {}).items())
        hdr_blob = "\n".join(f"{k}: {v}" for k, v in hdr_items)
        content_type = next(
            (str(v) for k, v in hdr_items if str(k).lower() == "content-type"),
            "",
        )
        body_sample = (body or "")[:200_000]
        safe_url = redact_sensitive_url(url)

        findings: list[Finding] = []
        for rule in self._rules:
            if rule.status_codes and status_code not in rule.status_codes:
                continue
            rule_scheme = rule.scheme.strip().lower() if rule.scheme else ""
            if rule_scheme and proto != rule_scheme:
                continue
            comp = self._compiled.get(rule.id)
            if comp is None or not (comp.u_re or comp.b_re or comp.h_re or comp.abs_h_re):
                continue
            if comp.excl_u_re and comp.excl_u_re.search(url):
                continue

            should_mask = rule.mask_secret or rule.cwe_id.strip().upper() in _SECRET_CWES
            matched_parts: list[str] = []
            if comp.u_re:
                m = comp.u_re.search(url)
                if not m:
                    continue
                u_val = redact_sensitive_url(m.group(0)) if should_mask else m.group(0)
                if should_mask and u_val == m.group(0) and "=" in u_val:
                    u_key, u_raw = u_val.split("=", 1)
                    u_val = f"{u_key}={mask_secret_value(u_raw)}"
                matched_parts.append(f"url={u_val[:80]}")
            if comp.ct_re:
                m = comp.ct_re.search(content_type)
                if not m:
                    continue
                matched_parts.append(f"content_type={m.group(0)[:80]}")
            if comp.h_re:
                m = comp.h_re.search(hdr_blob)
                if not m:
                    continue
                h_raw = m.group(0)
                if should_mask or _AUTH_ECHO_RE.search(h_raw):
                    if ":" in h_raw:
                        hk, hv = h_raw.split(":", 1)
                        h_val = f"{hk}: {mask_secret_value(hv)}"
                    else:
                        h_val = mask_secret_value(h_raw)
                else:
                    h_val = h_raw
                matched_parts.append(f"header={h_val[:80]}")
            if comp.abs_h_re:
                if comp.abs_h_re.search(hdr_blob):
                    continue
                matched_parts.append(f"absent_header!={rule.absent_header_regex[:60]}")
            if comp.excl_b_re and comp.excl_b_re.search(body_sample):
                continue
            if comp.b_re:
                m = comp.b_re.search(body_sample)
                if not m:
                    continue
                b_raw = m.group(0)
                b_val = (
                    mask_secret_value(b_raw)
                    if (should_mask or _AUTH_ECHO_RE.search(b_raw))
                    else b_raw
                )
                matched_parts.append(f"body={b_val[:80]}")

            findings.append(
                Finding(
                    host=host,
                    port=port,
                    protocol=proto,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    remediation=rule.remediation,
                    tool_source=f"yaml_rule:{rule.id}",
                    evidence=(
                        f"URL: {safe_url}\nRule: {rule.id}\nMatched: {', '.join(matched_parts)}"
                    ),
                    confirmed=rule.confirmed,
                )
            )
        return findings

"""Deterministic tests for the OWASP Top 100 passive rule catalog and pipeline integration."""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import yaml

from nexus.brain.remediation import RemediationDB
from nexus.brain.taxonomy import OWASP_TOP_10_2021, TaxonomyMapper
from nexus.core.config import NexusConfig, ScanProfile, StealthLevel, Tier
from nexus.core.engine import NexusEngine
from nexus.core.phases.scan import _run_passive_response_checks
from nexus.correlator.dedup import deduplicate_findings
from nexus.db.models import Finding, Port, Severity, Target
from nexus.scanner._http import parse_url_target
from nexus.scanner.headers import analyze_security_headers
from nexus.scanner.passive_dast import analyze_html_passive
from nexus.scanner.proxy import NexusProxyRecorder
from nexus.scanner.yaml_rules import PassiveRule, YamlPassiveRuleEngine

BUNDLED_RULES_DIR = Path(__file__).resolve().parents[2] / "nexus" / "brain" / "knowledge" / "rules"
OWASP_TOP100_YAML = BUNDLED_RULES_DIR / "owasp_top100_passive.yaml"
VALID_SEVERITIES = {s.value for s in Severity}


def _hardened_html_headers() -> dict[str, str]:
    return {
        "Content-Type": "text/html; charset=utf-8",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
        ),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cache-Control": "no-store, private",
        "X-Robots-Tag": "noindex, nofollow",
        "Set-Cookie": (
            "__Host-session=opaqueTokenValue123456; Path=/; Secure; HttpOnly; SameSite=Strict"
        ),
    }


def _make_mock_http_client(route_map: dict[str, tuple[int, dict[str, str], str]]) -> MagicMock:
    async def _fake_get(url: str, **_kwargs: object) -> MagicMock:
        status, hdrs, body = route_map[url]
        resp = MagicMock()
        resp.status_code = status
        resp.headers = hdrs
        resp.text = body
        resp.url = url
        return resp

    client = MagicMock()
    client.get = AsyncMock(side_effect=_fake_get)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


# ── 1. Catalog Integrity & Knowledge Cross-Mapping ────────────────


def test_owasp_top100_catalog_integrity_and_knowledge_mappings() -> None:
    assert OWASP_TOP100_YAML.is_file()
    raw_top100 = yaml.safe_load(OWASP_TOP100_YAML.read_text(encoding="utf-8"))
    assert isinstance(raw_top100, dict)
    top100_rules = raw_top100.get("rules")
    assert isinstance(top100_rules, list)
    assert len(top100_rules) == 100

    # Collect all YAML files in rules/ and verify zero duplicate IDs
    all_raw_rules: list[dict[str, object]] = []
    all_raw_ids: list[str] = []
    for yaml_path in sorted(
        list(BUNDLED_RULES_DIR.glob("*.yaml")) + list(BUNDLED_RULES_DIR.glob("*.yml"))
    ):
        parsed = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        items = parsed.get("rules", []) if isinstance(parsed, dict) else parsed
        assert isinstance(items, list)
        for item in items:
            assert isinstance(item, dict)
            rid = str(item.get("id") or "").strip()
            assert rid
            all_raw_ids.append(rid)
            all_raw_rules.append(item)

    assert len(all_raw_ids) == len(set(all_raw_ids)), "Duplicate rule IDs found in rules/"
    assert len(all_raw_rules) >= 110

    engine = YamlPassiveRuleEngine()
    loaded = engine.load_directory(BUNDLED_RULES_DIR)
    assert loaded == len(all_raw_rules)
    assert loaded >= 110
    assert engine.rule_count == loaded

    tax = TaxonomyMapper()
    rem_db = RemediationDB()

    # Exactly 10 rules per OWASP Top 10:2021 category (A01..A10) with complete metadata
    cat_counts: dict[str, int] = {f"A{i:02d}": 0 for i in range(1, 11)}
    for item in top100_rules:
        rid = str(item.get("id") or "").strip()
        title = str(item.get("title") or "").strip()
        desc = str(item.get("description") or "").strip()
        remediation = str(item.get("remediation") or "").strip()
        cwe_id = str(item.get("cwe_id") or "").strip()
        owasp_cat = str(item.get("owasp_category") or "").strip()
        severity = str(item.get("severity") or "").strip().lower()

        assert rid
        assert title
        assert desc
        assert remediation
        assert severity in VALID_SEVERITIES
        assert re.fullmatch(r"CWE-\d+", cwe_id), f"Invalid CWE ID in {rid}: {cwe_id!r}"
        assert owasp_cat

        cat_code = owasp_cat.split()[0]
        assert cat_code in cat_counts, f"Unexpected OWASP category in {rid}: {owasp_cat!r}"
        expected_cat_label = f"{cat_code} — {tax.get_owasp_name(cat_code)}"
        assert owasp_cat == expected_cat_label, f"{rid}: {owasp_cat!r} != {expected_cat_label!r}"
        cat_counts[cat_code] += 1

        mapped = tax.map_cwe(cwe_id)
        assert mapped is not None, f"TaxonomyMapper.map_cwe({cwe_id!r}) returned None for {rid}"
        assert mapped["owasp"] == owasp_cat, (
            f"OWASP drift in {rid} ({cwe_id}): {owasp_cat!r} != {mapped['owasp']!r}"
        )

        has_matcher = any(
            bool(item.get(field))
            for field in ("url_regex", "body_regex", "header_regex", "absent_header_regex")
        )
        assert has_matcher, f"Rule {rid} has no active matcher"

    assert all(count == 10 for count in cat_counts.values()), f"Category counts: {cat_counts}"

    # Every CWE across ALL rules in rules/ must map via TaxonomyMapper and exist in RemediationDB
    for item in all_raw_rules:
        rid = str(item.get("id") or "").strip()
        cwe_id = str(item.get("cwe_id") or "").strip()
        assert re.fullmatch(r"CWE-\d+", cwe_id), f"Invalid CWE ID in {rid}: {cwe_id!r}"

        mapped = tax.map_cwe(cwe_id)
        assert mapped is not None, f"TaxonomyMapper.map_cwe({cwe_id!r}) returned None for {rid}"
        assert mapped["cwe"] == cwe_id
        assert mapped["owasp_id"] in OWASP_TOP_10_2021
        assert mapped["owasp"] == f"{mapped['owasp_id']} — {tax.get_owasp_name(mapped['owasp_id'])}"

        rem_entry = rem_db.get(cwe_id)
        assert rem_entry is not None, f"RemediationDB.get({cwe_id!r}) returned None for {rid}"
        assert rem_entry.short_fix.strip() != ""
        assert rem_entry.detailed_fix.strip() != ""


# ── 2. Engine Matcher Feature Tests ───────────────────────────────


def test_engine_absent_header_scheme_content_type_and_exclusions() -> None:
    engine = YamlPassiveRuleEngine()
    engine.add_rule(
        PassiveRule(
            id="feat-absent-hdr-https-html",
            title="HTTPS HTML Missing Custom Policy",
            severity=Severity.LOW,
            cwe_id="CWE-693",
            owasp_category="A05 — Security Misconfiguration",
            remediation="Add X-Custom-Policy header.",
            scheme="HTTPS",
            content_type_regex=r"text/html",
            absent_header_regex=r"(?:^|\n)X-Custom-Policy\s*:",
            exclude_url_regex=r"/health(?:\?|$)",
            exclude_body_regex=r"__MAINTENANCE_PAGE__",
            status_codes=[200],
            confirmed=True,
        )
    )

    # Fires on HTTPS text/html when X-Custom-Policy is absent and exclusions do not match
    hits = engine.inspect_response(
        "https://app.example.test/dashboard",
        status_code=200,
        headers={"content-type": "text/html; charset=utf-8"},
        body="<html><body>Dashboard</body></html>",
    )
    assert len(hits) == 1
    assert hits[0].tool_source == "yaml_rule:feat-absent-hdr-https-html"
    assert hits[0].owasp_category == "A05 — Security Misconfiguration"
    assert hits[0].remediation == "Add X-Custom-Policy header."
    assert hits[0].confirmed is True

    # Suppressed when header is present (case-insensitive)
    assert (
        engine.inspect_response(
            "https://app.example.test/dashboard",
            status_code=200,
            headers={"Content-Type": "text/html", "x-custom-policy": "strict"},
            body="<html><body>Dashboard</body></html>",
        )
        == []
    )

    # Suppressed by scheme mismatch (http != https)
    assert (
        engine.inspect_response(
            "http://app.example.test/dashboard",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html><body>Dashboard</body></html>",
        )
        == []
    )

    # Suppressed by content_type_regex mismatch
    assert (
        engine.inspect_response(
            "https://app.example.test/dashboard",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"ok":true}',
        )
        == []
    )

    # Suppressed by exclude_url_regex
    assert (
        engine.inspect_response(
            "https://app.example.test/health",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html>OK</html>",
        )
        == []
    )

    # Suppressed by exclude_body_regex
    assert (
        engine.inspect_response(
            "https://app.example.test/dashboard",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html>__MAINTENANCE_PAGE__</html>",
        )
        == []
    )

    # HTTP-only scheme rule ignores HTTPS and matches HTTP
    engine.add_rule(
        PassiveRule(
            id="feat-http-only",
            title="Plaintext Login Over HTTP",
            severity=Severity.HIGH,
            cwe_id="CWE-319",
            owasp_category="A02 — Cryptographic Failures",
            scheme="http",
            body_regex=r"<input[^>]+type=['\"]?password",
        )
    )
    assert (
        engine.inspect_response(
            "https://app.example.test/login",
            status_code=200,
            body='<input type="password">',
        )
        == []
    )
    http_hits = engine.inspect_response(
        "http://app.example.test/login",
        status_code=200,
        body='<input type="password">',
    )
    assert [f.tool_source for f in http_hits] == ["yaml_rule:feat-http-only"]


def test_engine_invalid_regex_skip_and_duplicate_rule_overwrite(tmp_path: Path) -> None:
    engine = YamlPassiveRuleEngine()

    # Every regex field with invalid syntax must be safely skipped without raising
    bad_rules = [
        PassiveRule(id="bad-url", title="Bad URL", url_regex="[unclosed("),
        PassiveRule(
            id="bad-excl-url",
            title="Bad Exclude URL",
            url_regex="/a",
            exclude_url_regex="(?P<",
        ),
        PassiveRule(
            id="bad-ct",
            title="Bad CT",
            url_regex="/a",
            content_type_regex="*invalid",
        ),
        PassiveRule(id="bad-hdr", title="Bad Hdr", header_regex="[a-z"),
        PassiveRule(id="bad-abs-hdr", title="Bad Abs Hdr", absent_header_regex="(unclosed"),
        PassiveRule(id="bad-body", title="Bad Body", body_regex="[0-9"),
        PassiveRule(
            id="bad-excl-body",
            title="Bad Excl Body",
            body_regex="ok",
            exclude_body_regex="(abc",
        ),
    ]
    for br in bad_rules:
        engine.add_rule(br)
    assert engine.rule_count == 0

    # YAML file containing 1 invalid regex rule + 1 valid rule loads only the valid rule
    yaml_file = tmp_path / "mixed_rules.yaml"
    yaml_file.write_text(
        """rules:
  - id: bad-yaml-rule
    title: Broken Regex Rule
    body_regex: "[unclosed"
  - id: custom-dup-rule
    title: Original Title
    severity: low
    cwe_id: CWE-200
    owasp_category: "A01 — Broken Access Control"
    status_codes: 200
    body_regex: "LEGACY_MARKER"
""",
        encoding="utf-8",
    )
    added = engine.load_file(yaml_file)
    assert added == 1
    assert engine.rule_count == 1

    first_hits = engine.inspect_response(
        "https://app.example.test/", status_code=200, body="LEGACY_MARKER"
    )
    assert len(first_hits) == 1
    assert first_hits[0].title == "Original Title"
    assert first_hits[0].severity == Severity.LOW

    # Overwriting duplicate rule ID replaces both metadata and compiled matchers in-place
    engine.add_rule(
        PassiveRule(
            id="custom-dup-rule",
            title="Updated Title",
            severity=Severity.HIGH,
            cwe_id="CWE-538",
            owasp_category="A05 — Security Misconfiguration",
            body_regex="UPDATED_MARKER",
            confirmed=True,
        )
    )
    assert engine.rule_count == 1
    assert (
        engine.inspect_response("https://app.example.test/", status_code=200, body="LEGACY_MARKER")
        == []
    )
    updated_hits = engine.inspect_response(
        "https://app.example.test/", status_code=200, body="UPDATED_MARKER"
    )
    assert len(updated_hits) == 1
    assert updated_hits[0].title == "Updated Title"
    assert updated_hits[0].severity == Severity.HIGH
    assert updated_hits[0].cwe_id == "CWE-538"
    assert updated_hits[0].owasp_category == "A05 — Security Misconfiguration"
    assert updated_hits[0].confirmed is True


# ── 3. Category-by-Category Positive & Negative Tests (A01–A10) ───


@pytest.mark.parametrize(
    ("expected_rule_id", "expected_owasp_prefix", "url", "status_code", "headers", "body"),
    [
        # A01 — Broken Access Control
        (
            "owasp-a01-cors-null-origin",
            "A01",
            "https://app.example.test/api/data",
            200,
            {"Access-Control-Allow-Origin": "null"},
            "{}",
        ),
        (
            "owasp-a01-git-config-exposed",
            "A01",
            "https://app.example.test/.git/config",
            200,
            {"Content-Type": "text/plain"},
            '[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n',
        ),
        (
            "owasp-a01-idor-sequential-user-leak",
            "A01",
            "https://app.example.test/api/v1/users/42",
            200,
            {"Content-Type": "application/json"},
            '{"user_id": 42, "email": "alice@example.test"}',
        ),
        # A02 — Cryptographic Failures
        (
            "owasp-a02-aws-access-key-leak",
            "A02",
            "https://app.example.test/assets/app.js",
            200,
            {"Content-Type": "application/javascript"},
            'const awsId = "' + "AKIA" + "0123456789ABCDEF" + '";',
        ),
        (
            "owasp-a02-samesite-none-without-secure",
            "A02",
            "https://app.example.test/session",
            200,
            {"Set-Cookie": "sid=testtoken123; Path=/; HttpOnly; SameSite=None"},
            "",
        ),
        (
            "owasp-a02-weak-hsts-max-age",
            "A02",
            "https://app.example.test/",
            200,
            {"Strict-Transport-Security": "max-age=300"},
            "",
        ),
        # A03 — Injection
        (
            "owasp-a03-sql-error-disclosure",
            "A03",
            "https://app.example.test/items?id=1",
            500,
            {"Content-Type": "text/plain"},
            "You have an error in your SQL syntax; check the manual for your MySQL server",
        ),
        (
            "owasp-a03-json-served-as-text-html",
            "A03",
            "https://app.example.test/api/search",
            200,
            {"Content-Type": "text/html; charset=utf-8"},
            '{"query":"test","ok":true}',
        ),
        # A04 — Insecure Design
        (
            "owasp-a04-hidden-price-or-role-input",
            "A04",
            "https://app.example.test/checkout",
            200,
            {"Content-Type": "text/html"},
            '<form method="post"><input type="hidden" name="price" value="19.99"></form>',
        ),
        (
            "owasp-a04-missing-ratelimit-on-auth-endpoint",
            "A04",
            "https://app.example.test/login",
            401,
            {"Content-Type": "application/json"},
            '{"error":"invalid credentials"}',
        ),
        # A05 — Security Misconfiguration
        (
            "owasp-a05-server-os-banner-disclosure",
            "A05",
            "https://app.example.test/",
            200,
            {"Server": "Apache/2.4.58 (Ubuntu)"},
            "",
        ),
        (
            "owasp-a05-server-config-file-exposed",
            "A05",
            "https://app.example.test/appsettings.json",
            200,
            {"Content-Type": "application/json"},
            '{"ConnectionStrings":{"Default":"Server=db.internal;Database=app"}}',
        ),
        # A06 — Vulnerable Components
        (
            "owasp-a06-outdated-jquery",
            "A06",
            "https://app.example.test/",
            200,
            {"Content-Type": "text/html"},
            '<html><script src="/static/jquery-3.4.1.min.js"></script></html>',
        ),
        (
            "owasp-a06-outdated-apache-httpd",
            "A06",
            "https://app.example.test/",
            200,
            {"Server": "Apache/2.4.50"},
            "",
        ),
        # A07 — Identification and Authentication
        (
            "owasp-a07-basic-auth-over-http",
            "A07",
            "http://app.example.test/admin",
            401,
            {"WWW-Authenticate": 'Basic realm="Admin"'},
            "",
        ),
        (
            "owasp-a07-password-page-over-http",
            "A07",
            "http://app.example.test/signin",
            200,
            {"Content-Type": "text/html"},
            '<form><input type="password" name="pwd"></form>',
        ),
        (
            "owasp-a07-password-reset-token-leaked",
            "A07",
            "https://app.example.test/reset-password",
            200,
            {"Content-Type": "application/json"},
            '{"reset_token":"rst_demo_token_998877"}',
        ),
        # A08 — Software and Data Integrity
        (
            "owasp-a08-external-stylesheet-missing-sri",
            "A08",
            "https://app.example.test/",
            200,
            {"Content-Type": "text/html"},
            '<html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"></head></html>',
        ),
        (
            "owasp-a08-postmessage-missing-origin-check",
            "A08",
            "https://app.example.test/widget.js",
            200,
            {"Content-Type": "application/javascript"},
            'window.addEventListener("message", function(ev) { console.log(ev.data); });',
        ),
        # A09 — Security Logging and Monitoring
        (
            "owasp-a09-public-log-file-exposed",
            "A09",
            "https://app.example.test/debug.log",
            200,
            {"Content-Type": "text/plain"},
            "[2026-11-26 10:00:00] INFO Worker started",
        ),
        (
            "owasp-a09-api-error-missing-correlation-id",
            "A09",
            "https://app.example.test/api/v1/orders",
            500,
            {"Content-Type": "application/json"},
            '{"error":"internal server error"}',
        ),
        # A10 — Server-Side Request Forgery
        (
            "owasp-a10-internal-fetch-error-reflection",
            "A10",
            "https://app.example.test/import",
            502,
            {"Content-Type": "text/plain"},
            "Failed to connect to 169.254.169.254 port 80: Connection refused",
        ),
        (
            "owasp-a10-proxy-intermediary-header-leak",
            "A10",
            "https://app.example.test/edge",
            200,
            {"X-Upstream-Host": "backend.internal:8080"},
            "",
        ),
    ],
)
def test_owasp_top100_positive_matches_across_all_categories(
    expected_rule_id: str,
    expected_owasp_prefix: str,
    url: str,
    status_code: int,
    headers: dict[str, str],
    body: str,
) -> None:
    engine = YamlPassiveRuleEngine()
    engine.load_directory(BUNDLED_RULES_DIR)

    findings = engine.inspect_response(url, status_code=status_code, headers=headers, body=body)
    expected_source = f"yaml_rule:{expected_rule_id}"
    matched = [f for f in findings if f.tool_source == expected_source]
    assert len(matched) == 1, f"Expected {expected_source} in {[f.tool_source for f in findings]}"
    assert matched[0].owasp_category.startswith(expected_owasp_prefix)
    assert matched[0].cwe_id.startswith("CWE-")
    assert matched[0].remediation != ""


def test_negative_hardened_responses_and_spa_catchall_suppress_false_positives() -> None:
    engine = YamlPassiveRuleEngine()
    engine.load_directory(BUNDLED_RULES_DIR)

    # 1. Hardened HTML response with full modern security headers, SRI, and rel=noopener
    hardened_headers = _hardened_html_headers()
    hardened_html = (
        "<!doctype html><html><head><title>Portal</title>"
        '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" '
        'integrity="sha384-testIntegrityHashValue" crossorigin="anonymous">'
        "</head><body><h1>Portal</h1>"
        '<script src="https://app.example.test/static/jquery-3.7.1.min.js"></script>'
        '<a href="https://docs.example.test" target="_blank" rel="noopener noreferrer">Docs</a>'
        "</body></html>"
    )
    assert (
        engine.inspect_response(
            "https://app.example.test/",
            status_code=200,
            headers=hardened_headers,
            body=hardened_html,
        )
        == []
    )
    assert analyze_html_passive("https://app.example.test/", hardened_html) == []
    assert analyze_security_headers("https://app.example.test/", hardened_headers) == []

    # 2. Clean API JSON response with CORP, nosniff, and UUID objects
    api_headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }
    clean_json = (
        '{"status":"ok","items":[{"uuid":"550e8400-e29b-41d4-a716-446655440000","name":"Widget"}]}'
    )
    assert (
        engine.inspect_response(
            "https://app.example.test/api/v1/items",
            status_code=200,
            headers=api_headers,
            body=clean_json,
        )
        == []
    )

    # 3. SPA HTML catch-all returned with 200 on sensitive paths must NOT fire exposure rules
    spa_catchall = (
        "<!doctype html><html><head><title>App</title></head>"
        "<body><div id='root'>[core] repositoryformatversion = 0 "
        "DB_PASSWORD=placeholder Disallow: /admin</div></body></html>"
    )
    for sensitive_path in (
        "/.env",
        "/.git/config",
        "/phpinfo.php",
        "/.svn/entries",
        "/.htaccess",
        "/docker-compose.yml",
        "/backup.sql",
        "/web.config",
        "/appsettings.json",
        "/robots.txt",
        "/package-lock.json",
        "/debug.log",
    ):
        spa_findings = engine.inspect_response(
            f"https://app.example.test{sensitive_path}",
            status_code=200,
            headers=hardened_headers,
            body=spa_catchall,
        )
        assert spa_findings == [], (
            f"SPA catch-all on {sensitive_path} triggered: {[f.tool_source for f in spa_findings]}"
        )

    # 4. Safe edge cases: origin-checked postMessage, correlation-ID 500, patched component versions
    assert (
        engine.inspect_response(
            "https://app.example.test/widget.js",
            status_code=200,
            headers={"Content-Type": "application/javascript"},
            body='window.addEventListener("message", (ev) => { if (ev.origin !== "https://app.example.test") return; });',
        )
        == []
    )
    assert (
        engine.inspect_response(
            "https://app.example.test/api/v1/orders",
            status_code=500,
            headers={"Content-Type": "application/json", "X-Request-Id": "req-abc-123"},
            body='{"error":"unexpected error"}',
        )
        == []
    )
    assert (
        engine.inspect_response(
            "https://app.example.test/login",
            status_code=200,
            headers={
                **hardened_headers,
                "X-RateLimit-Limit": "10",
            },
            body=hardened_html,
        )
        == []
    )
    assert (
        engine.inspect_response(
            "https://app.example.test/patched",
            status_code=200,
            headers={
                **hardened_headers,
                "Server": "Apache/2.4.62",
            },
            body=hardened_html,
        )
        == []
    )
    assert (
        engine.inspect_response(
            "https://app.example.test/patched-nginx",
            status_code=200,
            headers={
                **hardened_headers,
                "Server": "nginx/1.26.2",
            },
            body=hardened_html,
        )
        == []
    )
    php_modern_sources = {
        f.tool_source
        for f in engine.inspect_response(
            "https://app.example.test/patched-php",
            status_code=200,
            headers={**hardened_headers, "X-Powered-By": "PHP/8.3.10"},
            body=hardened_html,
        )
    }
    assert "yaml_rule:owasp-a06-eol-php-version-banner" not in php_modern_sources


# ── 4. Dedup Preservation Tests ───────────────────────────────────


def test_dedup_preserves_distinct_passive_rules_and_merges_true_duplicates() -> None:
    # Distinct yaml_rule:* findings sharing CWE-200 on '/' must remain separate
    yaml_cwe200_a = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="Server Header Discloses Operating System Details",
        severity=Severity.INFO,
        cwe_id="CWE-200",
        owasp_category="A05 — Security Misconfiguration",
        tool_source="yaml_rule:owasp-a05-server-os-banner-disclosure",
        evidence="URL: https://app.example.test/\nMatched: header=Server: Apache (Ubuntu)",
        confirmed=True,
    )
    yaml_cwe200_b = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="Detailed Framework Version Disclosed in Response Header",
        severity=Severity.INFO,
        cwe_id="CWE-200",
        owasp_category="A01 — Broken Access Control",
        tool_source="yaml_rule:framework-version-header",
        evidence="URL: https://app.example.test/\nMatched: header=X-Powered-By: Express/4.18",
        confirmed=True,
    )
    assert len(deduplicate_findings([yaml_cwe200_a, yaml_cwe200_b])) == 2

    # Distinct yaml_rule:* findings sharing CWE-693 on '/' must remain separate
    yaml_cwe693_a = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="HTML Response Missing Referrer-Policy Header",
        severity=Severity.LOW,
        cwe_id="CWE-693",
        owasp_category="A05 — Security Misconfiguration",
        tool_source="yaml_rule:owasp-a05-missing-referrer-policy",
        evidence="URL: https://app.example.test/",
    )
    yaml_cwe693_b = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="HTML Response Missing Permissions-Policy Header",
        severity=Severity.INFO,
        cwe_id="CWE-693",
        owasp_category="A05 — Security Misconfiguration",
        tool_source="yaml_rule:owasp-a05-missing-permissions-policy",
        evidence="URL: https://app.example.test/",
    )
    assert len(deduplicate_findings([yaml_cwe693_a, yaml_cwe693_b])) == 2

    # Distinct http_headers and passive_dast findings sharing CWE-693 / CWE-319 on '/' remain separate
    hdr_a = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="HTTP: Missing Content-Security-Policy (CSP) Header",
        severity=Severity.LOW,
        cwe_id="CWE-693",
        tool_source="http_headers",
        evidence="URL: https://app.example.test/",
    )
    hdr_b = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="HTTP: Missing X-Content-Type-Options: nosniff",
        severity=Severity.INFO,
        cwe_id="CWE-693",
        tool_source="http_headers",
        evidence="URL: https://app.example.test/",
    )
    dast_a = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="Mixed Active Content: HTTP Script on HTTPS Page",
        severity=Severity.MEDIUM,
        cwe_id="CWE-319",
        tool_source="passive_dast",
        evidence="URL: https://app.example.test/",
    )
    dast_b = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="Mixed Content: HTTP Iframe on HTTPS Page",
        severity=Severity.MEDIUM,
        cwe_id="CWE-319",
        tool_source="passive_dast",
        evidence="URL: https://app.example.test/",
    )
    assert len(deduplicate_findings([hdr_a, hdr_b, dast_a, dast_b])) == 4

    # Identical yaml_rule:<same_id> duplicates on '/' MUST still merge
    dup_yaml_1 = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="HTML Response Missing Referrer-Policy Header",
        severity=Severity.INFO,
        cwe_id="CWE-693",
        owasp_category="A05 — Security Misconfiguration",
        tool_source="yaml_rule:owasp-a05-missing-referrer-policy",
        evidence="URL: https://app.example.test/\nObs: first",
        confirmed=False,
    )
    dup_yaml_2 = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="HTML Response Missing Referrer-Policy Header",
        severity=Severity.LOW,
        cwe_id="CWE-693",
        owasp_category="A05 — Security Misconfiguration",
        tool_source="yaml_rule:owasp-a05-missing-referrer-policy",
        evidence="URL: https://app.example.test/\nObs: second",
        confirmed=True,
    )
    merged_yaml = deduplicate_findings([dup_yaml_1, dup_yaml_2])
    assert len(merged_yaml) == 1
    assert merged_yaml[0].severity == Severity.LOW
    assert merged_yaml[0].confirmed is True
    assert "Obs: first" in merged_yaml[0].evidence
    assert "Obs: second" in merged_yaml[0].evidence

    # Same-CWE nuclei + nikto duplicates on '/' MUST still merge
    nuclei_f = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="[nuclei] Server Banner Disclosure",
        severity=Severity.LOW,
        cwe_id="CWE-200",
        tool_source="nuclei",
        evidence="URL: https://app.example.test/\nMatched via nuclei",
    )
    nikto_f = Finding(
        host="app.example.test",
        port=443,
        protocol="https",
        title="[Nikto] Server header leaks info",
        severity=Severity.MEDIUM,
        cwe_id="CWE-200",
        tool_source="nikto",
        evidence="URL: https://app.example.test/\nMatched via nikto",
    )
    merged_active = deduplicate_findings([nuclei_f, nikto_f])
    assert len(merged_active) == 1
    assert merged_active[0].severity == Severity.MEDIUM
    assert merged_active[0].tool_source == "nikto, nuclei"


# ── 5. ScanPhase + CorrelatePhase End-to-End Mocked Integration ───


@pytest.mark.asyncio
async def test_scan_and_correlate_end_to_end_covers_25_urls_and_retains_metadata(
    tmp_path: Path,
) -> None:
    cfg = NexusConfig(
        data_dir=tmp_path / "nexus_data",
        db_path=str(tmp_path / "owasp100_e2e.db"),
        output_dir=tmp_path / "reports",
        tier=Tier.MINIMAL,
        stealth=StealthLevel.OFF,
        profile=ScanProfile.WEB,
    )
    eng_mgr = NexusEngine(cfg)
    eng_mgr.boot(connect_ai=False)
    try:
        assert eng_mgr.yaml_rules is not None
        assert eng_mgr.yaml_rules.rule_count >= 110

        eng = eng_mgr.create_engagement("app.example.test")
        t = Target(
            engagement_id=eng.id,
            host="app.example.test",
            ip="192.0.2.10",
            is_live=True,
        )
        eng_mgr.db.add_target(t)
        eng_mgr.db.add_port(
            Port(target_id=t.id, port=443, protocol="tcp", state="open", service="https")
        )

        hardened_hdrs = _hardened_html_headers()
        hardened_body = (
            "<!doctype html><html><head><title>OK</title></head>"
            "<body><main>Clean</main></body></html>"
        )

        # Build 12 in-scope URLs (indices 0..7 clean, indices 8..11 vulnerable beyond [:8])
        crawled_urls = [f"https://app.example.test/clean-{i}" for i in range(1, 8)] + [
            "https://app.example.test/.git/config",  # index 8 -> A01
            "https://app.example.test/api/v1/profile",  # index 9 -> A01 + A05 + A08
            "https://app.example.test/api/v1/broken",  # index 10 -> A03 + A09
            "https://app.example.test/legacy-form",  # index 11 -> A02 + A04 + A05 + passive_dast
        ]

        route_map: dict[str, tuple[int, dict[str, str], str]] = {
            "https://app.example.test": (200, hardened_hdrs, hardened_body),
            **{
                f"https://app.example.test/clean-{i}": (200, hardened_hdrs, hardened_body)
                for i in range(1, 8)
            },
            "https://app.example.test/.git/config": (
                200,
                {"Content-Type": "text/plain"},
                '[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n',
            ),
            "https://app.example.test/api/v1/profile": (
                200,
                {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                    "Cross-Origin-Resource-Policy": "same-origin",
                },
                '{"user_id": 7, "email": "user@example.test", "is_admin": false}',
            ),
            "https://app.example.test/api/v1/broken": (
                500,
                {"Content-Type": "text/plain"},
                "SQLite3::SQLException: near 'FROM': syntax error",
            ),
            "https://app.example.test/legacy-form": (
                200,
                {
                    "Content-Type": "text/html",
                    "Strict-Transport-Security": "max-age=31536000",
                    "Permissions-Policy": "camera=()",
                    "Cross-Origin-Opener-Policy": "same-origin",
                    "Cross-Origin-Resource-Policy": "same-origin",
                },
                (
                    "<html><body>"
                    '<form method="post" action="http://app.example.test/submit">'
                    '<input type="password" name="pwd">'
                    "</form>"
                    '<a href="https://external.example.org/docs" target="_blank">External</a>'
                    "</body></html>"
                ),
            ),
        }
        fake_client = _make_mock_http_client(route_map)

        with (
            patch("nexus.core.engine.ToolRunner.is_available", return_value=False),
            patch("nexus.core.engine.crawl_web", AsyncMock(return_value=(crawled_urls, []))),
            patch("nexus.core.engine.audit_http_security", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_exposed_artifacts", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_tls", AsyncMock(return_value=[])),
            patch("nexus.core.engine.audit_graphql_introspection", AsyncMock(return_value=[])),
            patch("nexus.scanner._http.make_http_client", return_value=fake_client),
        ):
            scan_findings = await eng_mgr.run_scan(eng.id, "app.example.test")

        # All 12 URLs (0..11) were inspected by _run_passive_response_checks
        fetched_urls = [call.args[0] for call in fake_client.get.await_args_list]
        assert len(fetched_urls) == 12
        assert fetched_urls[8:] == crawled_urls[7:]

        scan_sources = {f.tool_source for f in scan_findings}
        assert "yaml_rule:owasp-a01-git-config-exposed" in scan_sources
        assert "yaml_rule:owasp-a05-cors-wildcard-on-authenticated-api" in scan_sources
        assert "yaml_rule:owasp-a08-mass-assignment-privileged-fields-exposed" in scan_sources
        assert "yaml_rule:owasp-a01-idor-sequential-user-leak" in scan_sources
        assert "yaml_rule:owasp-a03-sql-error-disclosure" in scan_sources
        assert "yaml_rule:owasp-a09-api-error-missing-correlation-id" in scan_sources
        assert "yaml_rule:owasp-a02-cleartext-http-form-action" in scan_sources
        assert "yaml_rule:owasp-a05-missing-referrer-policy" in scan_sources
        assert "passive_dast" in scan_sources

        # Run CorrelatePhase and inspect persisted SQLite findings
        await eng_mgr.run_correlate(eng.id)
        persisted = eng_mgr.db.get_findings(eng.id)
        by_source: dict[str, list[Finding]] = {}
        for pf in persisted:
            by_source.setdefault(pf.tool_source, []).append(pf)

        # Rule-authored OWASP category & remediation must be retained (not overwritten by CWE fallback)
        cors_api = by_source["yaml_rule:owasp-a05-cors-wildcard-on-authenticated-api"][0]
        assert cors_api.owasp_category == "A05 — Security Misconfiguration"
        assert "Access-Control-Allow-Origin: *" in cors_api.remediation

        mass_assign = by_source["yaml_rule:owasp-a08-mass-assignment-privileged-fields-exposed"][0]
        assert mass_assign.owasp_category == "A08 — Software and Data Integrity"
        assert "DTO" in mass_assign.remediation

        corr_id = by_source["yaml_rule:owasp-a09-api-error-missing-correlation-id"][0]
        assert corr_id.owasp_category == "A09 — Security Logging and Monitoring"
        assert "correlation" in corr_id.remediation.lower()

        git_exp = by_source["yaml_rule:owasp-a01-git-config-exposed"][0]
        assert git_exp.owasp_category == "A01 — Broken Access Control"
        assert "/.git" in git_exp.remediation

        sqli_err = by_source["yaml_rule:owasp-a03-sql-error-disclosure"][0]
        assert sqli_err.owasp_category == "A03 — Injection"
        assert "parameterized queries" in sqli_err.remediation.lower()

        http_form = by_source["yaml_rule:owasp-a02-cleartext-http-form-action"][0]
        assert http_form.owasp_category == "A02 — Cryptographic Failures"
        assert "HTTPS" in http_form.remediation

        # Passive DAST findings must be kept distinct and enriched via TaxonomyMapper + RemediationDB
        passive_dast_findings = by_source["passive_dast"]
        dast_titles = {f.title for f in passive_dast_findings}
        assert "Cleartext Password Submission Over HTTP" in dast_titles
        assert "POST Form Missing Anti-CSRF Token Field" in dast_titles
        assert "Reverse Tabnabbing Risk (target=_blank Without rel=noopener)" in dast_titles
        for df in passive_dast_findings:
            assert df.owasp_category != ""
            assert df.remediation != ""
    finally:
        eng_mgr.shutdown()


@pytest.mark.asyncio
async def test_passive_response_checks_cap_at_25_urls() -> None:
    engine = YamlPassiveRuleEngine()
    engine.load_directory(BUNDLED_RULES_DIR)

    urls = [f"https://app.example.test/page-{i}" for i in range(30)]
    route_map = {
        u: (
            200,
            {"Content-Type": "text/plain"},
            "Active connections: 1\nserver accepts handled requests\nReading: 0 Writing: 1 Waiting: 0"
            if idx == 24
            else "ok",
        )
        for idx, u in enumerate(urls)
    }
    fake_client = _make_mock_http_client(route_map)

    with patch("nexus.scanner._http.make_http_client", return_value=fake_client):
        findings = await _run_passive_response_checks(urls, engine, {}, "eng-cap-test")

    assert fake_client.get.await_count == 25
    assert [call.args[0] for call in fake_client.get.await_args_list] == urls[:25]
    assert any(f.tool_source == "yaml_rule:owasp-a05-nginx-stub-status-exposed" for f in findings)


# ── 6. Security & Precision Regression Tests ──────────────────────


def test_multi_set_cookie_headers_and_long_secure_cookies() -> None:
    engine = YamlPassiveRuleEngine()
    engine.load_directory(BUNDLED_RULES_DIR)

    # H-1 (False Negative fix): second Set-Cookie missing Secure on SameSite=None must fire
    hdrs_fn = httpx.Headers(
        [
            ("Content-Type", "text/html"),
            ("Set-Cookie", "pref=light; Path=/; Secure; HttpOnly"),
            ("Set-Cookie", "tracking=abc; Path=/; SameSite=None"),
        ]
    )
    hits_fn = engine.inspect_response(
        "https://app.example.test/", status_code=200, headers=hdrs_fn, body="ok"
    )
    assert any(f.tool_source == "yaml_rule:owasp-a02-samesite-none-without-secure" for f in hits_fn)

    # H-1 (False Positive fix): safe session cookie + tracking SameSite=None; Secure must NOT fire a07
    hdrs_fp = httpx.Headers(
        [
            ("Content-Type", "text/html"),
            ("Set-Cookie", "session=xyz; Path=/; SameSite=Lax; Secure; HttpOnly"),
            ("Set-Cookie", "tracking=1; Path=/; SameSite=None; Secure"),
        ]
    )
    hits_fp = engine.inspect_response(
        "https://app.example.test/", status_code=200, headers=hdrs_fp, body="ok"
    )
    assert not any(
        f.tool_source
        in (
            "yaml_rule:owasp-a07-auth-cookie-samesite-none",
            "yaml_rule:owasp-a02-samesite-none-without-secure",
        )
        for f in hits_fp
    )

    # M-1: Long >400-byte cookie with SameSite=None before Secure at tail must NOT fire
    long_val = "A" * 350
    hdrs_long = httpx.Headers(
        [
            (
                "Set-Cookie",
                f"jwt={long_val}; SameSite=None; Domain=app.example.test; Path=/dashboard/auth; HttpOnly; Max-Age=86400; Secure",
            )
        ]
    )
    hits_long = engine.inspect_response(
        "https://app.example.test/", status_code=200, headers=hdrs_long, body="ok"
    )
    assert not any(
        f.tool_source == "yaml_rule:owasp-a02-samesite-none-without-secure" for f in hits_long
    )

    # H-1 proxy preservation: multi-value headers passed to NexusProxyRecorder
    rec = NexusProxyRecorder(rules_dir=BUNDLED_RULES_DIR)
    _, proxy_hits = rec.inspect_exchange(
        method="GET",
        url="https://app.example.test/",
        status_code=200,
        response_headers=hdrs_fn,
        response_body="<html>ok</html>",
    )
    assert any(
        f.tool_source == "yaml_rule:owasp-a02-samesite-none-without-secure" for f in proxy_hits
    )


def test_secret_masking_and_url_redaction_in_evidence() -> None:
    engine = YamlPassiveRuleEngine()
    engine.load_directory(BUNDLED_RULES_DIR)

    raw_aws = "AKIA" + "0123456789ABCDEF"
    aws_hits = engine.inspect_response(
        "https://app.example.test/config.js",
        status_code=200,
        headers={"Content-Type": "application/javascript"},
        body=f'const aws = "{raw_aws}";',
    )
    aws_finding = next(
        f for f in aws_hits if f.tool_source == "yaml_rule:owasp-a02-aws-access-key-leak"
    )
    assert raw_aws not in aws_finding.evidence
    assert "AKIA***CDEF" in aws_finding.evidence

    raw_secret = "SuperSecretValue999"
    url_hits = engine.inspect_response(
        f"https://app.example.test/callback?api_key={raw_secret}&ok=1",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"ok":true}',
    )
    url_finding = next(
        f for f in url_hits if f.tool_source == "yaml_rule:owasp-a07-credentials-in-url-query"
    )
    assert raw_secret not in url_finding.evidence
    assert "REDACTED" in url_finding.evidence or "***" in url_finding.evidence

    raw_bearer = "liveBearerTokenSecretValue12345"
    echo_hits = engine.inspect_response(
        "https://app.example.test/debug",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body=f'{{"authorization": "Bearer {raw_bearer}"}}',
    )
    echo_finding = next(
        f
        for f in echo_hits
        if f.tool_source == "yaml_rule:owasp-a09-auth-cookie-echoed-in-debug-response"
    )
    assert raw_bearer not in echo_finding.evidence


def test_precision_regression_cases_and_url_parsing() -> None:
    engine = YamlPassiveRuleEngine()
    engine.load_directory(BUNDLED_RULES_DIR)

    # M-2: Empty "security": [] must NOT suppress unsecured write operations warning
    empty_sec_openapi = (
        '{"openapi":"3.0.3","security":[],"paths":{"/users":{"post":{"summary":"Create"}}}}'
    )
    hits_openapi = engine.inspect_response(
        "https://app.example.test/openapi.json",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body=empty_sec_openapi,
    )
    assert any(
        f.tool_source == "yaml_rule:owasp-a04-openapi-unsecured-write-operations"
        for f in hits_openapi
    )

    # M-3: Static assets under /auth/ must NOT trigger rate-limit or auth cache-control rules
    asset_hits = engine.inspect_response(
        "https://app.example.test/auth/logo.png",
        status_code=200,
        headers={"Content-Type": "image/png", "Cache-Control": "public, max-age=86400"},
        body="PNGDATA",
    )
    assert not any(
        f.tool_source
        in (
            "yaml_rule:owasp-a04-missing-ratelimit-on-auth-endpoint",
            "yaml_rule:owasp-a07-auth-response-missing-cache-control",
        )
        for f in asset_hits
    )

    # M-4: Authenticated Grafana login screen must NOT trigger unauth monitoring exposure
    login_hits = engine.inspect_response(
        "https://app.example.test/login",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<html><head><title>Grafana</title></head><form><input name='user'></form></html>",
    )
    assert not any(
        f.tool_source == "yaml_rule:owasp-a09-monitoring-dashboard-exposed" for f in login_hits
    )

    # M-5: Schemeless port 443 defaults to https and invalid port URL doesn't raise ValueError
    assert parse_url_target("example.com:443/login") == ("example.com", 443, "https")
    assert parse_url_target("http://badhost:notaport/test")[0] == "badhost"

    # L-1: Reversed attribute order in <meta content="noindex" name="robots">
    admin_noindex = engine.inspect_response(
        "https://app.example.test/admin",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body='<html><head><title>Admin Panel</title><meta content="noindex, nofollow" name="robots"></head></html>',
    )
    assert not any(
        f.tool_source == "yaml_rule:owasp-a01-admin-interface-noindex-missing"
        for f in admin_noindex
    )

    # L-2: CRLF Node.js stack trace matches owasp-a09-raw-runtime-exception-leak
    crlf_hits = engine.inspect_response(
        "https://app.example.test/crash",
        status_code=500,
        headers={"Content-Type": "text/plain"},
        body="Error: boom\r\n    at handler (server.js:12:3)\r\n",
    )
    assert any(f.tool_source == "yaml_rule:owasp-a09-raw-runtime-exception-leak" for f in crlf_hits)

    # L-3: Attribute prefix substring ("total_items") must NOT trigger hidden price/role input
    benign_form = engine.inspect_response(
        "https://app.example.test/cart",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body='<form><input type="hidden" name="total_items" value="3"></form>',
    )
    assert not any(
        f.tool_source == "yaml_rule:owasp-a04-hidden-price-or-role-input" for f in benign_form
    )

    # L-4: 128-bit hex session cookie is NOT flagged as weak MD5 digest
    csprng_cookie_hits = engine.inspect_response(
        "https://app.example.test/",
        status_code=200,
        headers={
            **_hardened_html_headers(),
            "Set-Cookie": "session=a1b2c3d4e5f60718293a4b5c6d7e8f90; Path=/; Secure; HttpOnly; SameSite=Lax",
        },
        body="<!doctype html><html><body>OK</body></html>",
    )
    assert not any(
        f.tool_source == "yaml_rule:owasp-a02-weak-hash-in-auth-cookie" for f in csprng_cookie_hits
    )

    # L-6: Distinct crawler secret classes on same bundle stay distinct after dedup
    crawler_a = Finding(
        host="app.example.test",
        port=443,
        title="AWS Access Key Exposed",
        cwe_id="CWE-798",
        tool_source="crawler",
        evidence="URL: https://app.example.test/app.js",
    )
    crawler_b = Finding(
        host="app.example.test",
        port=443,
        title="Slack API Token Exposed",
        cwe_id="CWE-798",
        tool_source="crawler",
        evidence="URL: https://app.example.test/app.js",
    )
    assert len(deduplicate_findings([crawler_a, crawler_b])) == 2


@pytest.mark.asyncio
async def test_passive_response_checks_skip_already_seen_findings() -> None:
    engine = YamlPassiveRuleEngine()
    engine.load_directory(BUNDLED_RULES_DIR)

    url = "https://app.example.test/legacy"
    route_map = {
        url: (
            200,
            {**_hardened_html_headers()},
            '<html><body><a href="https://other.test" target="_blank">Link</a></body></html>',
        )
    }
    fake_client = _make_mock_http_client(route_map)
    already_seen = {
        (
            "app.example.test",
            443,
            "passive_dast",
            "Reverse Tabnabbing Risk (target=_blank Without rel=noopener)",
            "/legacy",
        )
    }
    with patch("nexus.scanner._http.make_http_client", return_value=fake_client):
        findings = await _run_passive_response_checks(
            [url], engine, {}, "eng-dedup", already_seen=already_seen
        )

    assert not any(f.tool_source == "passive_dast" for f in findings)

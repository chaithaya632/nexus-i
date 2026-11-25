"""Tests for nexus.brain.payloads and nexus.brain.remediation."""

import pytest

from nexus.brain.payloads import PayloadDB, Payload, encode_base64, encode_url, encode_hex
from nexus.brain.remediation import RemediationDB


class TestPayloadDB:
    def test_init(self):
        db = PayloadDB()
        # Category stubs should NOT inflate count or resolve via get_by_name
        assert db.count == 0
        assert db.get_by_name("_category_sqli") is None
        assert len(db.categories()) >= 10

    def test_categories(self):
        db = PayloadDB()
        cats = db.categories()
        assert "revshell" in cats
        assert "sqli" in cats
        assert "xss" in cats
        assert "ssrf" in cats
        assert "cmdi" in cats
        assert "lfi" in cats
        assert "ssti" in cats
        assert "xxe" in cats
        assert "auth_bypass" in cats

    def test_add_and_search(self):
        db = PayloadDB()
        db.add_payload(Payload(
            name="test_payload", category="sqli", platform="universal",
            language="sql", template="' OR 1=1--", description="test bypass",
        ))
        results = db.search(category="sqli")
        assert any(p.name == "test_payload" for p in results)

    def test_search_by_keyword(self):
        db = PayloadDB()
        db.add_payload(Payload(
            name="custom_bypass", category="auth_bypass",
            description="special bypass technique",
            tags=["waf-bypass"],
        ))
        results = db.search(keyword="bypass")
        assert len(results) > 0

    def test_render(self):
        db = PayloadDB()
        p = Payload(name="test", category="revshell",
                    template="connect {LHOST} {LPORT}")
        rendered = db.render(p, {"LHOST": "10.0.0.1", "LPORT": "4444"})
        assert "10.0.0.1" in rendered
        assert "4444" in rendered

    def test_get_by_name(self):
        db = PayloadDB()
        db.add_payload(Payload(name="unique_name", category="test"))
        assert db.get_by_name("unique_name") is not None
        assert db.get_by_name("nonexistent") is None

    def test_search_excludes_stubs(self):
        db = PayloadDB()
        results = db.search()
        # Category stubs should not appear in search results
        for p in results:
            assert not p.name.startswith("_category_")

    def test_evasion_filter(self):
        db = PayloadDB()
        db.add_payload(Payload(name="low_ev", category="xss", evasion_level=0))
        db.add_payload(Payload(name="high_ev", category="xss", evasion_level=3))
        results = db.search(category="xss", max_evasion=1)
        names = {p.name for p in results}
        assert "low_ev" in names
        assert "high_ev" not in names


class TestEncoders:
    def test_base64(self):
        assert encode_base64("test") == "dGVzdA=="

    def test_url_encode(self):
        result = encode_url("<script>")
        assert "<" not in result
        assert ">" not in result

    def test_hex_encode(self):
        result = encode_hex("AB")
        assert result == "\\x41\\x42"


class TestRemediationDB:
    def test_load_builtins(self):
        db = RemediationDB()
        assert db.count > 10

    def test_get_cwe(self):
        db = RemediationDB()
        r = db.get("CWE-89")
        assert r is not None
        assert "SQL" in r.title
        assert r.severity == "critical"
        assert r.short_fix != ""

    def test_search(self):
        db = RemediationDB()
        results = db.search("injection")
        assert len(results) > 0

    def test_get_for_finding(self):
        db = RemediationDB()
        r = db.get_for_finding(cwe_id="CWE-79")
        assert r is not None
        assert "XSS" in r.title

    def test_missing_id(self):
        db = RemediationDB()
        assert db.get("CWE-99999") is None

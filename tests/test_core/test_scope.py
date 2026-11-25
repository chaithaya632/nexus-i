"""Tests for nexus.core.scope."""

from pathlib import Path

import pytest
import yaml

from nexus.core.scope import ScopeEnforcer, ScopeViolation


class TestScopeEnforcer:
    def _write_scope(self, tmp_path, data: dict) -> Path:
        p = tmp_path / "scope.yaml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        return p

    def test_domain_match(self, tmp_path):
        p = self._write_scope(
            tmp_path,
            {
                "allowed_domains": ["example.com", "*.test.com"],
            },
        )
        enforcer = ScopeEnforcer.from_file(p)

        assert enforcer.is_in_scope("example.com")
        assert enforcer.is_in_scope("sub.test.com")
        assert enforcer.is_in_scope("deep.sub.test.com")
        assert not enforcer.is_in_scope("evil.com")
        assert not enforcer.is_in_scope("notexample.com")

    def test_ip_match(self, tmp_path):
        p = self._write_scope(
            tmp_path,
            {
                "allowed_ips": ["10.0.0.1", "10.0.0.5"],
            },
        )
        enforcer = ScopeEnforcer.from_file(p)

        assert enforcer.is_in_scope("10.0.0.1")
        assert enforcer.is_in_scope("10.0.0.5")
        assert not enforcer.is_in_scope("10.0.0.2")

    def test_cidr_match(self, tmp_path):
        p = self._write_scope(
            tmp_path,
            {
                "allowed_cidrs": ["192.168.1.0/24"],
            },
        )
        enforcer = ScopeEnforcer.from_file(p)

        assert enforcer.is_in_scope("192.168.1.1")
        assert enforcer.is_in_scope("192.168.1.254")
        assert not enforcer.is_in_scope("192.168.2.1")

    def test_exclusion(self, tmp_path):
        p = self._write_scope(
            tmp_path,
            {
                "allowed_cidrs": ["10.0.0.0/8"],
                "excluded_targets": ["10.0.0.99"],
            },
        )
        enforcer = ScopeEnforcer.from_file(p)

        assert enforcer.is_in_scope("10.0.0.1")
        assert not enforcer.is_in_scope("10.0.0.99")

    def test_enforce_raises(self, tmp_path):
        p = self._write_scope(
            tmp_path,
            {
                "allowed_domains": ["safe.com"],
            },
        )
        enforcer = ScopeEnforcer.from_file(p)

        enforcer.enforce("safe.com")  # should not raise
        with pytest.raises(ScopeViolation):
            enforcer.enforce("evil.com")

    def test_port_filtering(self, tmp_path):
        p = self._write_scope(
            tmp_path,
            {
                "allowed_domains": ["example.com"],
                "allowed_ports": [80, 443, 8080],
            },
        )
        enforcer = ScopeEnforcer.from_file(p)

        assert enforcer.is_port_allowed(80)
        assert enforcer.is_port_allowed(443)
        assert not enforcer.is_port_allowed(22)

        enforcer.enforce("example.com", port=80)  # OK
        with pytest.raises(ScopeViolation):
            enforcer.enforce("example.com", port=22)

    def test_allow_all(self):
        enforcer = ScopeEnforcer.allow_all()
        assert enforcer.is_in_scope("1.2.3.4")
        assert enforcer.is_in_scope("255.255.255.255")

    def test_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ScopeEnforcer.from_file(tmp_path / "nonexistent.yaml")

    def test_for_target_url_ip_cidr_domain(self):
        url_scope = ScopeEnforcer.for_target("https://app.example.com:8443/api?x=1")
        assert url_scope.is_in_scope("app.example.com")
        assert not url_scope.is_in_scope("other.example.com")

        ip_scope = ScopeEnforcer.for_target("10.0.0.5")
        assert ip_scope.is_in_scope("10.0.0.5")
        assert not ip_scope.is_in_scope("10.0.0.6")

        v6_scope = ScopeEnforcer.for_target("2001:0db8::1")
        assert v6_scope.is_in_scope("2001:db8::1")
        assert not v6_scope.is_in_scope("2001:db8::2")

        cidr_scope = ScopeEnforcer.for_target("192.168.10.0/24")
        assert cidr_scope.is_in_scope("192.168.10.42")
        assert not cidr_scope.is_in_scope("192.168.11.42")

        dom_scope = ScopeEnforcer.for_target("example.com.")
        assert dom_scope.is_in_scope("example.com")
        assert dom_scope.is_in_scope("sub.example.com")
        assert not dom_scope.is_in_scope("notexample.com")

        for bad in ("", "   ", "*", "*.example.com", "0.0.0.0/0", "::/0"):
            with pytest.raises(ValueError):
                ScopeEnforcer.for_target(bad)

    def test_from_file_null_yaml_lists(self, tmp_path):
        p = tmp_path / "scope.yaml"
        p.write_text(
            "allowed_domains:\n  - example.com\n"
            "allowed_ips:\nallowed_cidrs:\nexcluded_targets:\nnotes:\n",
            encoding="utf-8",
        )
        enforcer = ScopeEnforcer.from_file(p)
        assert enforcer.is_in_scope("example.com")
        assert not enforcer.is_in_scope("evil.com")

    def test_ipv6_canonicalization_and_trailing_dot(self, tmp_path):
        p = self._write_scope(
            tmp_path,
            {
                "allowed_domains": ["example.com"],
                "allowed_ips": ["2001:0db8:0000:0000::1", "2001:0db8::2"],
                "excluded_targets": ["2001:0db8::2"],
            },
        )
        enforcer = ScopeEnforcer.from_file(p)

        assert enforcer.is_in_scope("2001:db8::1")
        assert not enforcer.is_in_scope("2001:db8::2")
        assert enforcer.is_in_scope("example.com.")
        assert enforcer.is_in_scope("EXAMPLE.COM.")

    def test_excluded_cidr_and_wildcard_domain(self, tmp_path):
        p = self._write_scope(
            tmp_path,
            {
                "allowed_cidrs": ["10.0.0.0/24"],
                "allowed_domains": ["*.example.com"],
                "excluded_targets": ["10.0.0.0/28", "*.prod.example.com"],
            },
        )
        enforcer = ScopeEnforcer.from_file(p)

        assert not enforcer.is_in_scope("10.0.0.5")
        assert enforcer.is_in_scope("10.0.0.20")
        assert not enforcer.is_in_scope("api.prod.example.com")
        assert not enforcer.is_in_scope("prod.example.com")
        assert enforcer.is_in_scope("dev.example.com")

"""Tests for nexus.core.scope."""

import ipaddress
import tempfile
from pathlib import Path

import pytest
import yaml

from nexus.core.scope import ScopeEnforcer, ScopeViolation, Scope


class TestScopeEnforcer:
    def _write_scope(self, tmp_path, data: dict) -> Path:
        p = tmp_path / "scope.yaml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        return p

    def test_domain_match(self, tmp_path):
        p = self._write_scope(tmp_path, {
            "allowed_domains": ["example.com", "*.test.com"],
        })
        enforcer = ScopeEnforcer.from_file(p)

        assert enforcer.is_in_scope("example.com")
        assert enforcer.is_in_scope("sub.test.com")
        assert enforcer.is_in_scope("deep.sub.test.com")
        assert not enforcer.is_in_scope("evil.com")
        assert not enforcer.is_in_scope("notexample.com")

    def test_ip_match(self, tmp_path):
        p = self._write_scope(tmp_path, {
            "allowed_ips": ["10.0.0.1", "10.0.0.5"],
        })
        enforcer = ScopeEnforcer.from_file(p)

        assert enforcer.is_in_scope("10.0.0.1")
        assert enforcer.is_in_scope("10.0.0.5")
        assert not enforcer.is_in_scope("10.0.0.2")

    def test_cidr_match(self, tmp_path):
        p = self._write_scope(tmp_path, {
            "allowed_cidrs": ["192.168.1.0/24"],
        })
        enforcer = ScopeEnforcer.from_file(p)

        assert enforcer.is_in_scope("192.168.1.1")
        assert enforcer.is_in_scope("192.168.1.254")
        assert not enforcer.is_in_scope("192.168.2.1")

    def test_exclusion(self, tmp_path):
        p = self._write_scope(tmp_path, {
            "allowed_cidrs": ["10.0.0.0/8"],
            "excluded_targets": ["10.0.0.99"],
        })
        enforcer = ScopeEnforcer.from_file(p)

        assert enforcer.is_in_scope("10.0.0.1")
        assert not enforcer.is_in_scope("10.0.0.99")

    def test_enforce_raises(self, tmp_path):
        p = self._write_scope(tmp_path, {
            "allowed_domains": ["safe.com"],
        })
        enforcer = ScopeEnforcer.from_file(p)

        enforcer.enforce("safe.com")  # should not raise
        with pytest.raises(ScopeViolation):
            enforcer.enforce("evil.com")

    def test_port_filtering(self, tmp_path):
        p = self._write_scope(tmp_path, {
            "allowed_domains": ["example.com"],
            "allowed_ports": [80, 443, 8080],
        })
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

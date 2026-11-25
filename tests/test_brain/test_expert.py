"""Tests for nexus.brain.expert."""

import pytest

from nexus.brain.expert import RuleEngine, Rule, Fact, build_service_rules


class TestRuleEngine:
    def test_add_and_evaluate(self):
        engine = RuleEngine()
        engine.add_fact("service_http", True, source="nmap")

        rule = Rule(
            name="test_http",
            priority=10,
            conditions=[lambda facts: "service_http" in facts],
            actions=["scan_web"],
        )
        engine.add_rule(rule)

        fired = engine.evaluate()
        assert len(fired) == 1
        assert fired[0][0] == "test_http"
        assert "scan_web" in fired[0][1]

    def test_no_match(self):
        engine = RuleEngine()
        engine.add_fact("service_ssh", True)

        rule = Rule(
            name="needs_http",
            conditions=[lambda facts: "service_http" in facts],
            actions=["scan_web"],
        )
        engine.add_rule(rule)

        fired = engine.evaluate()
        assert len(fired) == 0

    def test_priority_ordering(self):
        engine = RuleEngine()
        engine.add_fact("x", True)

        engine.add_rule(Rule(name="low_pri", priority=50,
                             conditions=[lambda f: "x" in f], actions=["low"]))
        engine.add_rule(Rule(name="high_pri", priority=5,
                             conditions=[lambda f: "x" in f], actions=["high"]))

        fired = engine.evaluate()
        assert fired[0][0] == "high_pri"
        assert fired[1][0] == "low_pri"

    def test_clear_facts(self):
        engine = RuleEngine()
        engine.add_fact("a", 1)
        engine.add_fact("b", 2)
        assert engine.fact_count == 2
        engine.clear_facts()
        assert engine.fact_count == 0

    def test_reset(self):
        engine = RuleEngine()
        engine.add_fact("a", 1)
        engine.add_rule(Rule(name="r", conditions=[], actions=[]))
        engine.reset()
        assert engine.fact_count == 0
        assert engine.rule_count == 0

    def test_get_fact(self):
        engine = RuleEngine()
        engine.add_fact("port_80", True, source="nmap", confidence=0.95)
        assert engine.get_fact("port_80") is True
        assert engine.get_fact("missing") is None
        assert engine.has_fact("port_80")
        assert not engine.has_fact("missing")


class TestServiceRules:
    def test_build_service_rules(self):
        rules = build_service_rules()
        assert len(rules) > 10
        names = {r.name for r in rules}
        assert "http_detected" in names
        assert "ssh_detected" in names
        assert "smb_detected" in names
        assert "sqli_confirmed" in names
        assert "credentials_found" in names

    def test_http_rule_fires(self):
        engine = RuleEngine()
        for rule in build_service_rules():
            engine.add_rule(rule)

        engine.add_fact("service_http", True, source="nmap")
        fired = engine.evaluate()
        rule_names = [name for name, _ in fired]
        assert "http_detected" in rule_names

    def test_multiple_rules_fire(self):
        engine = RuleEngine()
        for rule in build_service_rules():
            engine.add_rule(rule)

        engine.add_fact("service_http", True)
        engine.add_fact("service_ssh", True)
        engine.add_fact("service_smb", True)

        fired = engine.evaluate()
        rule_names = {name for name, _ in fired}
        assert "http_detected" in rule_names
        assert "ssh_detected" in rule_names
        assert "smb_detected" in rule_names

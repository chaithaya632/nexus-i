"""Tests for nexus.core.audit."""

import json
from pathlib import Path

import pytest

from nexus.core.audit import AuditLogger


class TestAuditLogger:
    def test_log_and_verify(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)

        audit.log_action("test_action", target="10.0.0.1", tool="nmap", result="success")
        audit.log_action("second_action", target="10.0.0.2", tool="nuclei")

        valid, count = audit.verify_chain()
        assert valid
        assert count == 2

    def test_chain_integrity(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)

        audit.log_action("action_1")
        audit.log_action("action_2")
        audit.log_action("action_3")

        valid, count = audit.verify_chain()
        assert valid
        assert count == 3

    def test_tampered_log_detected(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)

        audit.log_action("real_action")
        audit.log_action("real_action_2")

        # Tamper with the first line
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[0])
        entry["action"] = "tampered"
        lines[0] = json.dumps(entry, separators=(",", ":"))
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, count = audit.verify_chain()
        assert not valid

    def test_empty_log(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)
        valid, count = audit.verify_chain()
        assert valid
        assert count == 0

    def test_extra_data(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)
        audit.log_action("test", extra={"key": "value", "count": 42})

        line = log_path.read_text(encoding="utf-8").strip()
        entry = json.loads(line)
        assert entry["extra"]["key"] == "value"
        assert entry["extra"]["count"] == 42

        valid, count = audit.verify_chain()
        assert valid
        assert count == 1

    def test_cross_instance_chain_continuity(self, tmp_path):
        """Simulates separate CLI processes writing to the same audit log.

        Each new AuditLogger instance must pick up the last hash from disk,
        not start a fresh genesis chain.
        """
        log_path = tmp_path / "audit.jsonl"

        # Instance 1 writes two entries
        audit1 = AuditLogger(log_path)
        audit1.log_action("boot", tool="nexus")
        audit1.log_action("recon_start", target="10.0.0.1")

        # Instance 2 (new process) must continue the chain
        audit2 = AuditLogger(log_path)
        audit2.log_action("scan_start", target="10.0.0.1")
        audit2.log_action("shutdown", tool="nexus")

        # Instance 3 for good measure
        audit3 = AuditLogger(log_path)
        audit3.log_action("boot", tool="nexus")

        # The entire 5-entry chain must verify cleanly
        verifier = AuditLogger(log_path)
        valid, count = verifier.verify_chain()
        assert valid, "Cross-instance chain is broken"
        assert count == 5

    def test_single_entry_file(self, tmp_path):
        """Edge case: file has exactly one entry — new instance must chain from it."""
        log_path = tmp_path / "audit.jsonl"

        audit1 = AuditLogger(log_path)
        audit1.log_action("only_entry")

        audit2 = AuditLogger(log_path)
        audit2.log_action("second_entry")

        valid, count = audit2.verify_chain()
        assert valid
        assert count == 2

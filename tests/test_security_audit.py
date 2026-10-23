"""Security and robustness validation suite for Arjuna core.

Audits Gates 2, 3, 4, and 5 requirements.
"""

import math
import os
import sqlite3
import tempfile
from pathlib import Path
import pytest

from arjuna.memory import MemoryStore
from arjuna.tools import ToolRegistry


# ============================================================================
# GATE 2: AUDIT TRUSTED-ACTION & EVAL BOUNDARIES
# ============================================================================

def test_calculate_disallows_builtins_and_imports():
    """Verify calculate blocks arbitrary code execution and imports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tools = ToolRegistry(MemoryStore(Path(tmpdir) / "test.db"), allowed_root=Path(tmpdir))

        payloads = [
            "__import__('os').system('whoami')",
            "__builtins__",
            "open('test.txt', 'w')",
            "exec('x = 1')",
            "eval('1 + 1')",
            "globals()",
            "locals()",
        ]
        for p in payloads:
            res = tools.calculate(p)
            assert "Error" in res, f"Payload should have been blocked: {p} -> {res}"


def test_calculate_disallows_subclass_traversal():
    """Verify calculate blocks Python object traversal escapes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tools = ToolRegistry(MemoryStore(Path(tmpdir) / "test.db"), allowed_root=Path(tmpdir))

        # Object traversal attempts
        payloads = [
            "().__class__.__base__",
            "''.__class__.__mro__[1].__subclasses__()",
            "[c for c in ().__class__.__bases__[0].__subclasses__()]",
        ]
        for p in payloads:
            res = tools.calculate(p)
            assert "Error" in res, f"Subclass traversal should be blocked: {p} -> {res}"


def test_calculate_dos_exponentiation_bounds():
    """Verify calculate handles extreme power/allocation expressions safely."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tools = ToolRegistry(MemoryStore(Path(tmpdir) / "test.db"), allowed_root=Path(tmpdir))

        # Extremely large exponentiation that could freeze CPU
        # Python 3.11+ raises ValueError: Exceeds the limit (4300 digits) for integer string conversion
        # or we should check how it behaves
        res = tools.calculate("10 ** 1000000")
        assert "Error" in res or "10 ** 1000000" in res


# ============================================================================
# GATE 3: AUDIT FILESYSTEM & PATH TRAVERSAL BOUNDARIES
# ============================================================================

def test_file_read_blocks_path_traversal():
    """Verify read_local_file cannot read files outside the allowed workspace."""
    with tempfile.TemporaryDirectory() as allowed_dir:
        allowed_path = Path(allowed_dir)
        safe_file = allowed_path / "safe.txt"
        safe_file.write_text("Safe content inside workspace.", encoding="utf-8")

        with tempfile.TemporaryDirectory() as outside_dir:
            secret_file = Path(outside_dir) / "secret.txt"
            secret_file.write_text("CRITICAL_SECRET_DATA", encoding="utf-8")

            tools = ToolRegistry(MemoryStore(allowed_path / "test.db"), allowed_root=allowed_path)

            # Reading safe file should work
            res_safe = tools.read_local_file(str(safe_file))
            assert "Safe content inside workspace." in res_safe

            # Reading outside file must FAIL or be BLOCKED
            res_outside = tools.read_local_file(str(secret_file))
            # If path traversal is unconstrained, this will expose the secret!
            assert "CRITICAL_SECRET_DATA" not in res_outside, (
                "VULNERABILITY: read_local_file accessed file outside allowed directory!"
            )


def test_file_read_blocks_relative_directory_traversal():
    """Verify traversal sequences (../) cannot escape permitted directory."""
    with tempfile.TemporaryDirectory() as allowed_dir:
        allowed_path = Path(allowed_dir)
        sub_dir = allowed_path / "sub"
        sub_dir.mkdir()

        with tempfile.TemporaryDirectory() as outside_dir:
            secret_file = Path(outside_dir) / "secret.txt"
            secret_file.write_text("OUTSIDE_LEAK", encoding="utf-8")

            tools = ToolRegistry(MemoryStore(allowed_path / "test.db"), allowed_root=allowed_path)

            traversal_path = str(sub_dir / ".." / ".." / outside_dir / "secret.txt")
            res = tools.read_local_file(traversal_path)
            assert "OUTSIDE_LEAK" not in res, "VULNERABILITY: directory traversal succeeded!"


def test_file_read_oversized_file():
    """Verify reading oversized files is truncated safely without memory exhaustion."""
    with tempfile.TemporaryDirectory() as tmpdir:
        large_file = Path(tmpdir) / "large.txt"
        large_file.write_text("A" * 10000, encoding="utf-8")

        tools = ToolRegistry(MemoryStore(Path(tmpdir) / "test.db"), allowed_root=Path(tmpdir))
        content = tools.read_local_file(str(large_file), max_chars=500)
        assert len(content) < 600
        assert "Truncated" in content


def test_file_read_nonexistent_and_directory():
    """Verify proper error handling on missing file or directory path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tools = ToolRegistry(MemoryStore(Path(tmpdir) / "test.db"), allowed_root=Path(tmpdir))

        res_missing = tools.read_local_file(str(Path(tmpdir) / "nonexistent.txt"))
        assert "Error" in res_missing

        res_dir = tools.read_local_file(str(tmpdir))
        assert "Error" in res_dir


# ============================================================================
# GATE 4: MEMORY INTEGRITY & PRIVACY AUDIT
# ============================================================================

def test_sql_injection_resilience():
    """Verify SQLite parameterized queries prevent SQL injection."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = MemoryStore(Path(tmpdir) / "test.db")

        # Injections in fact key and value
        store.set_fact("user'; DROP TABLE facts; --", "injected_value")
        store.set_fact("clean_key", "val'; SELECT * FROM conversations; --")

        # Table must still exist and facts must be accessible as literal data
        facts = store.list_facts()
        assert "user'; drop table facts; --" in facts
        assert facts["clean_key"] == "val'; SELECT * FROM conversations; --"

        # Check conversation SQL injection
        conv_id = store.create_conversation("'; DROP TABLE messages; --")
        store.add_message(conv_id, "user", "Test message with ' OR 1=1 --")
        history = store.get_history(conv_id)
        assert len(history) == 1
        assert history[0]["content"] == "Test message with ' OR 1=1 --"


def test_unicode_and_special_character_integrity():
    """Verify UTF-8, emojis, RTL characters, and large inputs in memory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = MemoryStore(Path(tmpdir) / "test.db")

        # Emojis & multi-byte Unicode
        store.set_fact("emoji_test", "🏹 Arjuna AI 🚀 印度 🕉️ 🔥")
        assert store.get_fact("emoji_test") == "🏹 Arjuna AI 🚀 印度 🕉️ 🔥"

        # Large content
        large_text = "X" * 50000
        conv_id = store.create_conversation("Large Text Session")
        store.add_message(conv_id, "user", large_text)
        history = store.get_history(conv_id)
        assert history[0]["content"] == large_text


def test_conversation_cascade_deletion():
    """Verify that deleting a conversation cascade-deletes all associated messages."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        store = MemoryStore(db_path)

        conv_id = store.create_conversation("Ephemeral Session")
        store.add_message(conv_id, "user", "Message 1")
        store.add_message(conv_id, "assistant", "Message 2")

        # Verify messages exist in DB directly
        with store._get_connection() as conn:
            cnt = conn.execute("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", (conv_id,)).fetchone()[0]
            assert cnt == 2

        # Delete conversation
        assert store.delete_conversation(conv_id) is True

        # Verify messages are completely wiped by ON DELETE CASCADE
        with store._get_connection() as conn:
            cnt = conn.execute("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", (conv_id,)).fetchone()[0]
            assert cnt == 0, "Messages were not cascade-deleted!"


def test_fact_deletion_completeness():
    """Verify deleted facts cannot be retrieved or leaked."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = MemoryStore(Path(tmpdir) / "test.db")

        store.set_fact("secret_token", "super_secret_12345")
        assert store.get_fact("secret_token") == "super_secret_12345"

        assert store.delete_fact("secret_token") is True
        assert store.get_fact("secret_token") is None
        assert "secret_token" not in store.list_facts()

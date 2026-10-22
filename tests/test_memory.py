"""Unit tests for SQLite memory store."""

import tempfile
from pathlib import Path
import pytest
from arjuna.memory import MemoryStore


def test_conversation_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        store = MemoryStore(db_path)

        # Create
        conv_id = store.create_conversation("Test Chat")
        assert conv_id is not None
        assert len(conv_id) == 8

        # Add messages
        store.add_message(conv_id, "user", "Hello Arjuna")
        store.add_message(conv_id, "assistant", "Hello! How can I assist?", thinking="User said hello")

        # History check
        history = store.get_history(conv_id)
        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "Hello Arjuna"
        assert history[1]["role"] == "assistant"
        assert history[1]["thinking"] == "User said hello"

        # List conversations
        convs = store.list_conversations()
        assert len(convs) == 1
        assert convs[0]["id"] == conv_id

        # Delete conversation
        assert store.delete_conversation(conv_id) is True
        assert len(store.list_conversations()) == 0
        assert len(store.get_history(conv_id)) == 0


def test_facts_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        store = MemoryStore(db_path)

        # Set fact
        store.set_fact("favorite_color", "blue")
        assert store.get_fact("favorite_color") == "blue"

        # Update fact
        store.set_fact("favorite_color", "green")
        assert store.get_fact("favorite_color") == "green"

        # List facts
        store.set_fact("user_role", "engineer")
        facts = store.list_facts()
        assert len(facts) == 2
        assert facts["favorite_color"] == "green"
        assert facts["user_role"] == "engineer"

        # Delete fact
        assert store.delete_fact("favorite_color") is True
        assert store.get_fact("favorite_color") is None
        assert store.delete_fact("nonexistent") is False

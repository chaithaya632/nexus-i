"""SQLite-backed memory and conversation management for Arjuna."""

from __future__ import annotations

import contextlib
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


class MemoryStore:
    """Manages chat history and persistent key-value memory."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextlib.contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create tables and indices if not already present."""
        with self._get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    thinking TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS facts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_messages_conv_id ON messages(conversation_id);
                CREATE INDEX IF NOT EXISTS idx_facts_key ON facts(key);
                """
            )

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_conversation(self, title: str = "New Conversation") -> str:
        """Create a new conversation session."""
        conv_id = str(uuid.uuid4())[:8]
        now = self._now_iso()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (conv_id, title, now, now),
            )
        return conv_id

    def get_or_create_conversation(self, conv_id: str | None = None) -> str:
        """Retrieve existing conversation ID or initialize a new one."""
        if conv_id:
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT id FROM conversations WHERE id = ?", (conv_id,)
                ).fetchone()
                if row:
                    return str(row["id"])
        return self.create_conversation()

    def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        thinking: str = "",
    ) -> None:
        """Append a message to the active conversation."""
        now = self._now_iso()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO messages (conversation_id, role, content, thinking, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (conversation_id, role, content, thinking, now),
            )
            # Update conversation timestamp and title if it's the first user message
            first_user = conn.execute(
                "SELECT count(*) as cnt FROM messages WHERE conversation_id = ? AND role = 'user'",
                (conversation_id,),
            ).fetchone()
            if first_user and first_user["cnt"] == 1 and role == "user":
                summary_title = (content[:35] + "...") if len(content) > 35 else content
                conn.execute(
                    "UPDATE conversations SET title = ?, updated_at = ? WHERE id = ?",
                    (summary_title, now, conversation_id),
                )
            else:
                conn.execute(
                    "UPDATE conversations SET updated_at = ? WHERE id = ?",
                    (now, conversation_id),
                )

    def get_history(self, conversation_id: str, limit: int = 20) -> list[dict[str, Any]]:
        """Fetch the recent message history for context feeding."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT role, content, thinking, created_at
                FROM messages
                WHERE conversation_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (conversation_id, limit),
            ).fetchall()
        return [
            {
                "role": r["role"],
                "content": r["content"],
                "thinking": r["thinking"],
                "created_at": r["created_at"],
            }
            for r in reversed(rows)
        ]

    def list_conversations(self) -> list[dict[str, Any]]:
        """List all active conversation sessions."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT c.id, c.title, c.updated_at, COUNT(m.id) as message_count
                FROM conversations c
                LEFT JOIN messages m ON c.id = m.conversation_id
                GROUP BY c.id
                ORDER BY c.updated_at DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_conversation(self, conversation_id: str) -> bool:
        """Remove a conversation and its messages."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM conversations WHERE id = ?", (conversation_id,)
            )
            return cur.rowcount > 0

    def set_fact(self, key: str, value: str) -> None:
        """Store or update a persistent memory fact."""
        now = self._now_iso()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO facts (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (key.strip().lower(), value.strip(), now),
            )

    def get_fact(self, key: str) -> str | None:
        """Recall a persistent fact by key."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT value FROM facts WHERE key = ?", (key.strip().lower(),)
            ).fetchone()
            return str(row["value"]) if row else None

    def list_facts(self) -> dict[str, str]:
        """Return all stored facts."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT key, value FROM facts ORDER BY key ASC").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def delete_fact(self, key: str) -> bool:
        """Remove a persistent fact."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM facts WHERE key = ?", (key.strip().lower(),))
            return cur.rowcount > 0

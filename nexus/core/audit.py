"""Immutable, hash-chained audit log for NEXUS engagements."""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    """Append-only, hash-chained audit trail.

    Each entry includes a SHA-256 hash of the previous entry, forming
    an integrity chain that detects tampering.
    """

    def __init__(self, log_path: Path) -> None:
        self._path = log_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev_hash = self._compute_last_hash()

    def _compute_last_hash(self) -> str:
        """Read the last line's hash to continue the chain."""
        if not self._path.is_file():
            return "0" * 64  # Genesis hash
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                last_line = ""
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
                if last_line:
                    return json.loads(last_line).get("hash", "0" * 64)
        except (json.JSONDecodeError, KeyError, OSError):
            pass
        return "0" * 64

    def log_action(
        self,
        action: str,
        target: str = "",
        tool: str = "",
        result: str = "",
        operator: str = "nexus",
        extra: dict | None = None,
    ) -> None:
        """Append an immutable audit entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target": target,
            "tool": tool,
            "result": result,
            "operator": operator,
            "prev_hash": self._prev_hash,
        }
        if extra:
            entry["extra"] = extra

        # Compute hash of this entry (excluding the hash field itself)
        raw = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        entry["hash"] = entry_hash

        line = json.dumps(entry, separators=(",", ":")) + "\n"

        with self._lock:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line)
            self._prev_hash = entry_hash

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the entire audit chain integrity.

        Returns (is_valid, entry_count).
        """
        if not self._path.is_file():
            return True, 0

        prev_hash = "0" * 64
        count = 0

        with open(self._path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, count

                if entry.get("prev_hash") != prev_hash:
                    return False, count

                # Recompute hash
                stored_hash = entry.pop("hash", "")
                raw = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
                if expected != stored_hash:
                    return False, count

                prev_hash = stored_hash
                count += 1

        return True, count

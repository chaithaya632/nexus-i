"""Immutable, hash-chained audit log for NEXUS engagements."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("nexus.core.audit")

_GENESIS_HASH = "0" * 64


class AuditLogger:
    """Append-only, hash-chained audit trail.

    Each entry includes a SHA-256 hash of the previous entry, forming
    an integrity chain that detects tampering.
    """

    def __init__(self, log_path: Path) -> None:
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._corrupted = False
        self._prev_hash = self._compute_last_hash()

    @property
    def corrupted(self) -> bool:
        """True if an existing non-empty audit file had an invalid tail on load."""
        return self._corrupted

    def _compute_last_hash(self) -> str:
        """Read the last line's hash to continue the chain.

        If the file exists and is non-empty but has a malformed/unparseable
        tail or missing hash, mark ``self._corrupted = True`` and derive a
        non-genesis sentinel digest instead of resetting to ``"0" * 64``.
        """
        if not self._path.is_file():
            return _GENESIS_HASH
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                last_line = ""
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
        except OSError as exc:
            self._corrupted = True
            log.warning("Failed reading existing audit log %s: %s", self._path, exc)
            return hashlib.sha256(f"corrupt-io:{exc}".encode("utf-8")).hexdigest()

        if not last_line:
            return _GENESIS_HASH

        try:
            parsed = json.loads(last_line)
        except json.JSONDecodeError as exc:
            self._corrupted = True
            log.warning("Corrupted JSON tail in audit log %s: %s", self._path, exc)
            return hashlib.sha256(last_line.encode("utf-8", errors="replace")).hexdigest()

        if not isinstance(parsed, dict) or not isinstance(parsed.get("hash"), str) or not parsed["hash"]:
            self._corrupted = True
            log.warning("Missing or invalid hash in audit log tail %s", self._path)
            return hashlib.sha256(last_line.encode("utf-8", errors="replace")).hexdigest()

        return parsed["hash"]

    def log_action(
        self,
        action: str,
        target: str = "",
        tool: str = "",
        result: str = "",
        operator: str = "nexus",
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Append an immutable audit entry."""
        with self._lock:
            entry: dict[str, Any] = {
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
            raw = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
            entry_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            entry["hash"] = entry_hash

            line = json.dumps(entry, separators=(",", ":"), default=str) + "\n"
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
            self._prev_hash = entry_hash

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the entire audit chain integrity.

        Returns (is_valid, entry_count).
        """
        with self._lock:
            if not self._path.is_file():
                return True, 0

            prev_hash = _GENESIS_HASH
            count = 0

            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        return False, count

                    if not isinstance(entry, dict) or entry.get("prev_hash") != prev_hash:
                        return False, count

                    # Recompute hash
                    stored_hash = entry.pop("hash", "")
                    raw = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
                    expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
                    if expected != stored_hash:
                        return False, count

                    prev_hash = stored_hash
                    count += 1

            return True, count

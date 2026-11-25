"""SQLite database layer for NEXUS — lightweight, encrypted-at-rest capable."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.db.models import (
    AttackChain,
    Credential,
    Engagement,
    EngagementPhase,
    Finding,
    Port,
    ProxyEntry,
    Severity,
    Target,
)

log = logging.getLogger("nexus.db.store")

_SCHEMA_VERSION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    name TEXT,
    target TEXT,
    scope_file TEXT,
    phase TEXT DEFAULT 'init',
    created_at TEXT,
    updated_at TEXT,
    stealth TEXT DEFAULT 'medium',
    tier TEXT DEFAULT 'minimal',
    notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    host TEXT,
    ip TEXT,
    is_live INTEGER DEFAULT 0,
    os_guess TEXT DEFAULT '',
    tech_stack TEXT DEFAULT '[]',
    waf_detected TEXT DEFAULT '',
    UNIQUE(engagement_id, host),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS ports (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    port INTEGER,
    protocol TEXT DEFAULT 'tcp',
    state TEXT DEFAULT 'open',
    service TEXT DEFAULT '',
    version TEXT DEFAULT '',
    banner TEXT DEFAULT '',
    UNIQUE(target_id, port, protocol),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    protocol TEXT DEFAULT '',
    title TEXT,
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    cvss_score REAL,
    cve_ids TEXT DEFAULT '[]',
    epss_score REAL,
    cwe_id TEXT DEFAULT '',
    owasp_category TEXT DEFAULT '',
    tool_source TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    request TEXT DEFAULT '',
    response TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    false_positive INTEGER DEFAULT 0,
    confirmed INTEGER DEFAULT 0,
    discovered_at TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    service TEXT DEFAULT '',
    username TEXT DEFAULT '',
    password TEXT DEFAULT '',
    hash_value TEXT DEFAULT '',
    source TEXT DEFAULT '',
    confirmed INTEGER DEFAULT 0,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS chains (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    name TEXT,
    description TEXT DEFAULT '',
    steps TEXT DEFAULT '[]',
    confidence REAL DEFAULT 0.0,
    impact TEXT DEFAULT 'info',
    confirmed INTEGER DEFAULT 0,
    poc_script TEXT DEFAULT '',
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS proxy_history (
    id TEXT PRIMARY KEY,
    engagement_id TEXT DEFAULT '',
    method TEXT DEFAULT 'GET',
    url TEXT DEFAULT '',
    host TEXT DEFAULT '',
    port INTEGER DEFAULT 80,
    request_headers TEXT DEFAULT '{}',
    request_body TEXT DEFAULT '',
    status_code INTEGER DEFAULT 0,
    response_headers TEXT DEFAULT '{}',
    response_body TEXT DEFAULT '',
    findings_count INTEGER DEFAULT 0,
    captured_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
CREATE INDEX IF NOT EXISTS idx_targets_engagement ON targets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_ports_target ON ports(target_id);
CREATE INDEX IF NOT EXISTS idx_credentials_engagement ON credentials(engagement_id);
CREATE INDEX IF NOT EXISTS idx_chains_engagement ON chains(engagement_id);
CREATE INDEX IF NOT EXISTS idx_proxy_engagement ON proxy_history(engagement_id);
"""


def _chmod_0600(path: Path) -> None:
    """Best-effort restrictive 0600 permissions on sensitive local files."""
    try:
        if path.exists():
            os.chmod(path, 0o600)
    except OSError:
        pass


class _SecretCipher:
    """Encrypt/decrypt sensitive credential columns at rest using Fernet or domain-separated HMAC-CTR."""

    _FERNET_PREFIX = "enc:v1:"
    _XOR_PREFIX_V2 = "enc:xor2:"
    _XOR_PREFIX_LEGACY = "enc:xor1:"

    def __init__(self, raw_key: bytes) -> None:
        self._raw_key = hashlib.sha256(raw_key).digest()
        # Separate domain-derived subkeys for fallback encryption vs authentication
        self._enc_key = hmac.new(self._raw_key, b"nexus-cred-enc-v2", hashlib.sha256).digest()
        self._mac_key = hmac.new(self._raw_key, b"nexus-cred-mac-v2", hashlib.sha256).digest()
        self._fernet = None
        try:
            from cryptography.fernet import Fernet  # type: ignore[import-untyped]

            fernet_key = base64.urlsafe_b64encode(self._raw_key)
            self._fernet = Fernet(fernet_key)
        except ImportError:
            self._fernet = None

    def encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        if self._fernet is not None:
            token = self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
            return f"{self._FERNET_PREFIX}{token}"
        return self._xor_encrypt_v2(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        if not ciphertext:
            return ""
        if ciphertext.startswith(self._FERNET_PREFIX):
            if self._fernet is None:
                raise RuntimeError(
                    "cryptography is required to decrypt Fernet-encrypted credentials"
                )
            token = ciphertext[len(self._FERNET_PREFIX) :].encode("ascii")
            return self._fernet.decrypt(token).decode("utf-8")
        if ciphertext.startswith(self._XOR_PREFIX_V2):
            return self._xor_decrypt_v2(ciphertext)
        if ciphertext.startswith(self._XOR_PREFIX_LEGACY):
            return self._xor_decrypt_legacy(ciphertext)
        # Legacy unencrypted row fallback
        return ciphertext

    def _keystream(self, key: bytes, nonce: bytes, length: int, domain: bytes = b"") -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            blk = hmac.new(
                key, domain + nonce + counter.to_bytes(4, "big"), hashlib.sha256
            ).digest()
            out.extend(blk)
            counter += 1
        return bytes(out[:length])

    def _xor_encrypt_v2(self, plaintext: str) -> str:
        nonce = secrets.token_bytes(16)
        data = plaintext.encode("utf-8")
        ks = self._keystream(self._enc_key, nonce, len(data), domain=b"ctr:")
        cipher = bytes(a ^ b for a, b in zip(data, ks))
        tag = hmac.new(self._mac_key, b"mac:" + nonce + cipher, hashlib.sha256).digest()
        blob = base64.urlsafe_b64encode(nonce + tag + cipher).decode("ascii")
        return f"{self._XOR_PREFIX_V2}{blob}"

    def _xor_decrypt_v2(self, ciphertext: str) -> str:
        raw = base64.urlsafe_b64decode(ciphertext[len(self._XOR_PREFIX_V2) :].encode("ascii"))
        if len(raw) < 48:
            raise ValueError("Truncated encrypted credential")
        nonce, tag, cipher = raw[:16], raw[16:48], raw[48:]
        expected = hmac.new(self._mac_key, b"mac:" + nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Credential integrity check failed")
        ks = self._keystream(self._enc_key, nonce, len(cipher), domain=b"ctr:")
        return bytes(a ^ b for a, b in zip(cipher, ks)).decode("utf-8")

    def _xor_decrypt_legacy(self, ciphertext: str) -> str:
        raw = base64.urlsafe_b64decode(ciphertext[len(self._XOR_PREFIX_LEGACY) :].encode("ascii"))
        nonce, tag, cipher = raw[:16], raw[16:32], raw[32:]
        expected = hmac.new(self._raw_key, nonce + cipher, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Credential integrity check failed")
        ks = self._keystream(self._raw_key, nonce, len(cipher))
        return bytes(a ^ b for a, b in zip(cipher, ks)).decode("utf-8")


class EngagementStore:
    """Lightweight SQLite storage for NEXUS engagement data."""

    def __init__(self, db_path: Path | str) -> None:
        raw_str = str(db_path)
        self._is_memory = raw_str == ":memory:"
        self._path = Path(raw_str)
        if not self._is_memory:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._cipher = _SecretCipher(self._load_or_create_key())
        self._init_db()
        if not self._is_memory:
            _chmod_0600(self._path)

    def _load_or_create_key(self) -> bytes:
        env_key = os.environ.get("NEXUS_DB_KEY", "").strip()
        if env_key:
            return env_key.encode("utf-8")
        if self._is_memory:
            return secrets.token_bytes(32)
        key_id = f"db:{self._path.resolve()}"
        try:
            import keyring  # type: ignore[import-untyped]

            stored = keyring.get_password("nexus-pt", key_id)
            if stored:
                return stored.strip().encode("utf-8")
            generated = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
            keyring.set_password("nexus-pt", key_id, generated)
            return generated.encode("utf-8")
        except Exception as exc:
            log.debug("OS keyring unavailable, using 0600 local keyfile: %s", exc)
        key_path = Path(f"{self._path}.key")
        if key_path.is_file():
            _chmod_0600(key_path)
            return key_path.read_bytes().strip()
        raw_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        key_path.write_bytes(raw_key)
        _chmod_0600(key_path)
        return raw_key

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        conn = self._connect()
        try:
            cur = conn.cursor()
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._cursor() as cur:
            cur.executescript(_SCHEMA)
            self._migrate_db(cur)

    def _migrate_db(self, cur: sqlite3.Cursor) -> None:
        """Apply idempotent schema migrations using PRAGMA user_version."""
        version = cur.execute("PRAGMA user_version").fetchone()[0]
        if version >= _SCHEMA_VERSION:
            return

        if version < 2:
            # Deduplicate targets by (engagement_id, host) and re-point child ports before indexing
            dup_groups = cur.execute(
                "SELECT engagement_id, host FROM targets GROUP BY engagement_id, host HAVING COUNT(*) > 1"
            ).fetchall()
            for grp in dup_groups:
                rows = cur.execute(
                    "SELECT id FROM targets WHERE engagement_id = ? AND host = ? ORDER BY rowid ASC",
                    (grp["engagement_id"], grp["host"]),
                ).fetchall()
                keep_id = rows[0]["id"]
                for dup in rows[1:]:
                    dup_id = dup["id"]
                    # Move non-conflicting ports to keep_id, drop conflicting duplicates
                    dup_ports = cur.execute(
                        "SELECT id, port, protocol FROM ports WHERE target_id = ?",
                        (dup_id,),
                    ).fetchall()
                    for dp in dup_ports:
                        exists = cur.execute(
                            "SELECT 1 FROM ports WHERE target_id = ? AND port = ? AND protocol = ?",
                            (keep_id, dp["port"], dp["protocol"]),
                        ).fetchone()
                        if exists:
                            cur.execute("DELETE FROM ports WHERE id = ?", (dp["id"],))
                        else:
                            cur.execute(
                                "UPDATE ports SET target_id = ? WHERE id = ?", (keep_id, dp["id"])
                            )
                    cur.execute("DELETE FROM targets WHERE id = ?", (dup_id,))

            # Deduplicate ports by (target_id, port, protocol)
            dup_port_groups = cur.execute(
                "SELECT target_id, port, protocol FROM ports GROUP BY target_id, port, protocol HAVING COUNT(*) > 1"
            ).fetchall()
            for grp in dup_port_groups:
                rows = cur.execute(
                    "SELECT id FROM ports WHERE target_id = ? AND port = ? AND protocol = ? ORDER BY rowid DESC",
                    (grp["target_id"], grp["port"], grp["protocol"]),
                ).fetchall()
                for dup in rows[1:]:
                    cur.execute("DELETE FROM ports WHERE id = ?", (dup["id"],))

            cur.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_targets_eng_host ON targets(engagement_id, host)"
            )
            cur.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_target_port_proto ON ports(target_id, port, protocol)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_credentials_engagement ON credentials(engagement_id)"
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_chains_engagement ON chains(engagement_id)")

        if version < 3:
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_proxy_engagement ON proxy_history(engagement_id)"
            )
        cur.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    # --- Engagements ---

    def create_engagement(self, eng: Engagement) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO engagements (id, name, target, scope_file, phase, created_at, updated_at, stealth, tier, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    eng.id,
                    eng.name,
                    eng.target,
                    eng.scope_file,
                    eng.phase.value,
                    eng.created_at.isoformat(),
                    eng.updated_at.isoformat(),
                    eng.stealth,
                    eng.tier,
                    eng.notes,
                ),
            )
        return eng.id

    def get_engagement(self, eng_id: str) -> Engagement | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM engagements WHERE id = ?", (eng_id,))
            row = cur.fetchone()
            if not row:
                return None
            return Engagement(**dict(row))

    def list_engagements(self) -> list[Engagement]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM engagements ORDER BY created_at DESC")
            return [Engagement(**dict(r)) for r in cur.fetchall()]

    def update_phase(self, eng_id: str, phase: EngagementPhase) -> None:
        now_iso = datetime.now(UTC).isoformat()
        with self._cursor() as cur:
            cur.execute(
                "UPDATE engagements SET phase = ?, updated_at = ? WHERE id = ?",
                (phase.value, now_iso, eng_id),
            )

    def delete_engagement(self, eng_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM chains WHERE engagement_id = ?", (eng_id,))
            cur.execute("DELETE FROM credentials WHERE engagement_id = ?", (eng_id,))
            cur.execute("DELETE FROM findings WHERE engagement_id = ?", (eng_id,))
            for row in cur.execute(
                "SELECT id FROM targets WHERE engagement_id = ?", (eng_id,)
            ).fetchall():
                cur.execute("DELETE FROM ports WHERE target_id = ?", (row["id"],))
            cur.execute("DELETE FROM targets WHERE engagement_id = ?", (eng_id,))
            cur.execute("DELETE FROM engagements WHERE id = ?", (eng_id,))

    # --- Targets ---

    def add_target(self, t: Target) -> str:
        with self._cursor() as cur:
            existing = cur.execute(
                "SELECT id FROM targets WHERE engagement_id = ? AND host = ?",
                (t.engagement_id, t.host),
            ).fetchone()
            if existing:
                t.id = existing["id"]
                cur.execute(
                    "UPDATE targets SET ip=?, is_live=?, os_guess=?, tech_stack=?, waf_detected=? WHERE id=?",
                    (
                        t.ip,
                        int(t.is_live),
                        t.os_guess,
                        json.dumps(t.tech_stack),
                        t.waf_detected,
                        t.id,
                    ),
                )
            else:
                cur.execute(
                    "INSERT INTO targets (id, engagement_id, host, ip, is_live, os_guess, tech_stack, waf_detected) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET "
                    "host=excluded.host, ip=excluded.ip, is_live=excluded.is_live, "
                    "os_guess=excluded.os_guess, tech_stack=excluded.tech_stack, "
                    "waf_detected=excluded.waf_detected",
                    (
                        t.id,
                        t.engagement_id,
                        t.host,
                        t.ip,
                        int(t.is_live),
                        t.os_guess,
                        json.dumps(t.tech_stack),
                        t.waf_detected,
                    ),
                )
        return t.id

    def get_targets(self, eng_id: str) -> list[Target]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM targets WHERE engagement_id = ?", (eng_id,))
            results = []
            for r in cur.fetchall():
                d = dict(r)
                d["is_live"] = bool(d["is_live"])
                d["tech_stack"] = json.loads(d.get("tech_stack") or "[]")
                results.append(Target(**d))
            return results

    # --- Ports ---

    def add_port(self, p: Port) -> str:
        with self._cursor() as cur:
            existing = cur.execute(
                "SELECT id FROM ports WHERE target_id = ? AND port = ? AND protocol = ?",
                (p.target_id, p.port, p.protocol),
            ).fetchone()
            if existing:
                p.id = existing["id"]
                cur.execute(
                    "UPDATE ports SET state=?, service=?, version=?, banner=? WHERE id=?",
                    (p.state, p.service, p.version, p.banner, p.id),
                )
            else:
                cur.execute(
                    "INSERT INTO ports (id, target_id, port, protocol, state, service, version, banner) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET "
                    "target_id=excluded.target_id, port=excluded.port, protocol=excluded.protocol, "
                    "state=excluded.state, service=excluded.service, version=excluded.version, banner=excluded.banner",
                    (
                        p.id,
                        p.target_id,
                        p.port,
                        p.protocol,
                        p.state,
                        p.service,
                        p.version,
                        p.banner,
                    ),
                )
        return p.id

    def get_ports(self, target_id: str) -> list[Port]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM ports WHERE target_id = ?", (target_id,))
            return [Port(**dict(r)) for r in cur.fetchall()]

    # --- Findings ---

    def add_finding(self, f: Finding) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO findings "
                "(id, engagement_id, host, port, protocol, title, description, severity, "
                "cvss_score, cve_ids, epss_score, cwe_id, owasp_category, tool_source, "
                "evidence, request, response, remediation, false_positive, confirmed, discovered_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f.id,
                    f.engagement_id,
                    f.host,
                    f.port,
                    f.protocol,
                    f.title,
                    f.description,
                    f.severity.value,
                    f.cvss_score,
                    json.dumps(f.cve_ids),
                    f.epss_score,
                    f.cwe_id,
                    f.owasp_category,
                    f.tool_source,
                    f.evidence,
                    f.request,
                    f.response,
                    f.remediation,
                    int(f.false_positive),
                    int(f.confirmed),
                    f.discovered_at.isoformat(),
                ),
            )
        return f.id

    def get_findings(self, eng_id: str, severity: Severity | None = None) -> list[Finding]:
        with self._cursor() as cur:
            sql = "SELECT * FROM findings WHERE engagement_id = ?"
            params: list[Any] = [eng_id]
            if severity:
                sql += " AND severity = ?"
                params.append(severity.value)
            sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
            cur.execute(sql, params)
            results = []
            for r in cur.fetchall():
                d = dict(r)
                d["cve_ids"] = json.loads(d.get("cve_ids") or "[]")
                d["false_positive"] = bool(d["false_positive"])
                d["confirmed"] = bool(d["confirmed"])
                results.append(Finding(**d))
            return results

    def count_findings_by_severity(self, eng_id: str) -> dict[str, int]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings WHERE engagement_id = ? AND false_positive = 0 GROUP BY severity",
                (eng_id,),
            )
            return {r["severity"]: r["cnt"] for r in cur.fetchall()}

    def replace_findings(self, eng_id: str, findings: list[Finding]) -> None:
        """Atomically replace all findings for an engagement (e.g., post-correlation)."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM findings WHERE engagement_id = ?", (eng_id,))
            for f in findings:
                cur.execute(
                    "INSERT INTO findings "
                    "(id, engagement_id, host, port, protocol, title, description, severity, "
                    "cvss_score, cve_ids, epss_score, cwe_id, owasp_category, tool_source, "
                    "evidence, request, response, remediation, false_positive, confirmed, discovered_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        f.id,
                        eng_id,
                        f.host,
                        f.port,
                        f.protocol,
                        f.title,
                        f.description,
                        f.severity.value,
                        f.cvss_score,
                        json.dumps(f.cve_ids),
                        f.epss_score,
                        f.cwe_id,
                        f.owasp_category,
                        f.tool_source,
                        f.evidence,
                        f.request,
                        f.response,
                        f.remediation,
                        int(f.false_positive),
                        int(f.confirmed),
                        f.discovered_at.isoformat(),
                    ),
                )

    # --- Credentials ---

    def add_credential(self, c: Credential) -> str:
        enc_pw = self._cipher.encrypt(c.password)
        enc_hash = self._cipher.encrypt(c.hash_value)
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO credentials "
                "(id, engagement_id, host, port, service, username, password, hash_value, source, confirmed) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    c.id,
                    c.engagement_id,
                    c.host,
                    c.port,
                    c.service,
                    c.username,
                    enc_pw,
                    enc_hash,
                    c.source,
                    int(c.confirmed),
                ),
            )
        return c.id

    def get_credentials(self, eng_id: str) -> list[Credential]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM credentials WHERE engagement_id = ?", (eng_id,))
            results = []
            for r in cur.fetchall():
                d = dict(r)
                d["confirmed"] = bool(d["confirmed"])
                d["password"] = self._cipher.decrypt(d.get("password") or "")
                d["hash_value"] = self._cipher.decrypt(d.get("hash_value") or "")
                results.append(Credential(**d))
            return results

    # --- Attack Chains ---

    def add_chain(self, c: AttackChain) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO chains "
                "(id, engagement_id, name, description, steps, confidence, impact, confirmed, poc_script) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    c.id,
                    c.engagement_id,
                    c.name,
                    c.description,
                    json.dumps([s.model_dump() for s in c.steps]),
                    c.confidence,
                    c.impact.value,
                    int(c.confirmed),
                    c.poc_script,
                ),
            )
        return c.id

    def replace_chains(self, eng_id: str, chains: list[AttackChain]) -> None:
        """Atomically replace all attack chains for an engagement."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM chains WHERE engagement_id = ?", (eng_id,))
            for c in chains:
                cur.execute(
                    "INSERT INTO chains "
                    "(id, engagement_id, name, description, steps, confidence, impact, confirmed, poc_script) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        c.id,
                        eng_id,
                        c.name,
                        c.description,
                        json.dumps([s.model_dump() for s in c.steps]),
                        c.confidence,
                        c.impact.value,
                        int(c.confirmed),
                        c.poc_script,
                    ),
                )

    def get_chains(self, eng_id: str) -> list[AttackChain]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM chains WHERE engagement_id = ?", (eng_id,))
            results = []
            for r in cur.fetchall():
                d = dict(r)
                d["steps"] = json.loads(d.get("steps") or "[]")
                d["confirmed"] = bool(d["confirmed"])
                results.append(AttackChain(**d))
            return results

    # --- Proxy History ---

    def add_proxy_entry(self, entry: ProxyEntry) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO proxy_history "
                "(id, engagement_id, method, url, host, port, request_headers, request_body, "
                "status_code, response_headers, response_body, findings_count, captured_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.id,
                    entry.engagement_id,
                    entry.method,
                    entry.url,
                    entry.host,
                    entry.port,
                    json.dumps(entry.request_headers),
                    entry.request_body[:16000],
                    entry.status_code,
                    json.dumps(entry.response_headers),
                    entry.response_body[:32000],
                    entry.findings_count,
                    entry.captured_at.isoformat(),
                ),
            )
        return entry.id

    def get_proxy_history(self, eng_id: str = "", limit: int = 200) -> list[ProxyEntry]:
        with self._cursor() as cur:
            if eng_id:
                cur.execute(
                    "SELECT * FROM proxy_history WHERE engagement_id = ? ORDER BY captured_at DESC LIMIT ?",
                    (eng_id, max(1, limit)),
                )
            else:
                cur.execute(
                    "SELECT * FROM proxy_history ORDER BY captured_at DESC LIMIT ?",
                    (max(1, limit),),
                )
            results: list[ProxyEntry] = []
            for r in cur.fetchall():
                d = dict(r)
                d["request_headers"] = json.loads(d.get("request_headers") or "{}")
                d["response_headers"] = json.loads(d.get("response_headers") or "{}")
                results.append(ProxyEntry(**d))
            return results

    def get_proxy_entry(self, entry_id: str) -> ProxyEntry | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM proxy_history WHERE id = ?", (entry_id,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["request_headers"] = json.loads(d.get("request_headers") or "{}")
            d["response_headers"] = json.loads(d.get("response_headers") or "{}")
            return ProxyEntry(**d)

    # --- Export ---

    def export_engagement_json(self, eng_id: str) -> dict[str, Any]:
        """Export full engagement data as a JSON-serializable dict."""
        eng = self.get_engagement(eng_id)
        if not eng:
            return {}
        targets = self.get_targets(eng_id)
        all_ports: list[dict] = []
        for t in targets:
            for p in self.get_ports(t.id):
                all_ports.append(p.model_dump(mode="json"))

        redacted_creds = []
        for c in self.get_credentials(eng_id):
            d = c.model_dump(mode="json")
            d["password"] = "***REDACTED***" if c.password else ""
            d["hash_value"] = "***REDACTED***" if c.hash_value else ""
            redacted_creds.append(d)

        return {
            "engagement": eng.model_dump(mode="json"),
            "targets": [t.model_dump(mode="json") for t in targets],
            "ports": all_ports,
            "findings": [f.model_dump(mode="json") for f in self.get_findings(eng_id)],
            "credentials": redacted_creds,
            "chains": [c.model_dump(mode="json") for c in self.get_chains(eng_id)],
            "severity_counts": self.count_findings_by_severity(eng_id),
        }


def create_store(db_path: Path | str, db_url: str | None = None) -> Any:
    """Factory returning PostgresEngagementStore when db_url is postgresql://, else SQLite."""
    url = (db_url or os.environ.get("NEXUS_DB_URL") or "").strip()
    if url.startswith(("postgresql://", "postgres://")):
        from nexus.db.pg_store import PostgresEngagementStore

        return PostgresEngagementStore(url)
    return EngagementStore(db_path)

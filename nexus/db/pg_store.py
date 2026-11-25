"""Optional PostgreSQL storage backend for multi-tester NEXUS engagements.

Requires optional dependency: ``pip install nexus-pt[postgres]`` (psycopg v3).
Activated when ``NEXUS_DB_URL`` or ``config.db_url`` starts with ``postgresql://``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from contextlib import contextmanager
from datetime import UTC, datetime
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
from nexus.db.store import _SecretCipher

log = logging.getLogger("nexus.db.pg_store")

_PG_SCHEMA = """
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
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    host TEXT,
    ip TEXT,
    is_live INTEGER DEFAULT 0,
    os_guess TEXT DEFAULT '',
    tech_stack TEXT DEFAULT '[]',
    waf_detected TEXT DEFAULT '',
    UNIQUE(engagement_id, host)
);

CREATE TABLE IF NOT EXISTS ports (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    port INTEGER,
    protocol TEXT DEFAULT 'tcp',
    state TEXT DEFAULT 'open',
    service TEXT DEFAULT '',
    version TEXT DEFAULT '',
    banner TEXT DEFAULT '',
    UNIQUE(target_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    host TEXT,
    port INTEGER,
    protocol TEXT DEFAULT '',
    title TEXT,
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    cvss_score DOUBLE PRECISION,
    cve_ids TEXT DEFAULT '[]',
    epss_score DOUBLE PRECISION,
    cwe_id TEXT DEFAULT '',
    owasp_category TEXT DEFAULT '',
    tool_source TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    request TEXT DEFAULT '',
    response TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    false_positive INTEGER DEFAULT 0,
    confirmed INTEGER DEFAULT 0,
    discovered_at TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    host TEXT,
    port INTEGER,
    service TEXT DEFAULT '',
    username TEXT DEFAULT '',
    password TEXT DEFAULT '',
    hash_value TEXT DEFAULT '',
    source TEXT DEFAULT '',
    confirmed INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS chains (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    name TEXT,
    description TEXT DEFAULT '',
    steps TEXT DEFAULT '[]',
    confidence DOUBLE PRECISION DEFAULT 0.0,
    impact TEXT DEFAULT 'info',
    confirmed INTEGER DEFAULT 0,
    poc_script TEXT DEFAULT ''
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

CREATE INDEX IF NOT EXISTS idx_pg_findings_eng ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_pg_targets_eng ON targets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_pg_ports_target ON ports(target_id);
CREATE INDEX IF NOT EXISTS idx_pg_proxy_eng ON proxy_history(engagement_id);
"""


class PostgresEngagementStore:
    """PostgreSQL backend implementing the EngagementStore CRUD contract."""

    def __init__(self, dsn: str, *, _psycopg_mod: Any = None) -> None:
        self._dsn = dsn.strip()
        if _psycopg_mod is not None:
            self._psycopg = _psycopg_mod
        else:
            try:
                import psycopg  # type: ignore[import-untyped]

                self._psycopg = psycopg
            except ImportError as exc:
                raise ImportError(
                    "PostgreSQL backend requires psycopg. Install with: pip install 'nexus-pt[postgres]'"
                ) from exc

        env_key = os.environ.get("NEXUS_DB_KEY", "").strip()
        if env_key:
            raw_key = env_key.encode("utf-8")
        else:
            # Derive deterministic app-scoped key if NEXUS_DB_KEY omitted, preferring OS keyring
            raw_key = self._load_keyring_or_ephemeral()
        self._cipher = _SecretCipher(raw_key)
        self._init_db()

    def _load_keyring_or_ephemeral(self) -> bytes:
        key_id = f"pg:{hashlib.sha256(self._dsn.encode('utf-8')).hexdigest()[:16]}"
        try:
            import keyring  # type: ignore[import-untyped]

            existing = keyring.get_password("nexus-pt", key_id)
            if existing:
                return existing.strip().encode("utf-8")
            generated = secrets.token_hex(32)
            keyring.set_password("nexus-pt", key_id, generated)
            return generated.encode("utf-8")
        except Exception:
            return hashlib.sha256(self._dsn.encode("utf-8")).digest()

    @contextmanager
    def _cursor(self):
        kwargs: dict[str, Any] = {}
        try:
            from psycopg.rows import dict_row  # type: ignore[import-untyped]

            kwargs["row_factory"] = dict_row
        except ImportError:
            pass
        conn = self._psycopg.connect(self._dsn, **kwargs)
        try:
            with conn.cursor() as cur:
                yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._cursor() as cur:
            for stmt in _PG_SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    cur.execute(s)

    def create_engagement(self, eng: Engagement) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO engagements (id, name, target, scope_file, phase, created_at, updated_at, stealth, tier, notes) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
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
            cur.execute("SELECT * FROM engagements WHERE id = %s", (eng_id,))
            row = cur.fetchone()
            return Engagement(**dict(row)) if row else None

    def list_engagements(self) -> list[Engagement]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM engagements ORDER BY created_at DESC")
            return [Engagement(**dict(r)) for r in cur.fetchall()]

    def update_phase(self, eng_id: str, phase: EngagementPhase) -> None:
        now_iso = datetime.now(UTC).isoformat()
        with self._cursor() as cur:
            cur.execute(
                "UPDATE engagements SET phase = %s, updated_at = %s WHERE id = %s",
                (phase.value, now_iso, eng_id),
            )

    def delete_engagement(self, eng_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM chains WHERE engagement_id = %s", (eng_id,))
            cur.execute("DELETE FROM credentials WHERE engagement_id = %s", (eng_id,))
            cur.execute("DELETE FROM findings WHERE engagement_id = %s", (eng_id,))
            cur.execute(
                "DELETE FROM ports WHERE target_id IN (SELECT id FROM targets WHERE engagement_id = %s)",
                (eng_id,),
            )
            cur.execute("DELETE FROM targets WHERE engagement_id = %s", (eng_id,))
            cur.execute("DELETE FROM engagements WHERE id = %s", (eng_id,))

    def add_target(self, t: Target) -> str:
        with self._cursor() as cur:
            cur.execute(
                "SELECT id FROM targets WHERE engagement_id = %s AND host = %s",
                (t.engagement_id, t.host),
            )
            existing = cur.fetchone()
            if existing:
                t.id = existing["id"]
                cur.execute(
                    "UPDATE targets SET ip=%s, is_live=%s, os_guess=%s, tech_stack=%s, waf_detected=%s WHERE id=%s",
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
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
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
            cur.execute("SELECT * FROM targets WHERE engagement_id = %s", (eng_id,))
            out: list[Target] = []
            for r in cur.fetchall():
                d = dict(r)
                d["is_live"] = bool(d["is_live"])
                d["tech_stack"] = json.loads(d.get("tech_stack") or "[]")
                out.append(Target(**d))
            return out

    def add_port(self, p: Port) -> str:
        with self._cursor() as cur:
            cur.execute(
                "SELECT id FROM ports WHERE target_id = %s AND port = %s AND protocol = %s",
                (p.target_id, p.port, p.protocol),
            )
            existing = cur.fetchone()
            if existing:
                p.id = existing["id"]
                cur.execute(
                    "UPDATE ports SET state=%s, service=%s, version=%s, banner=%s WHERE id=%s",
                    (p.state, p.service, p.version, p.banner, p.id),
                )
            else:
                cur.execute(
                    "INSERT INTO ports (id, target_id, port, protocol, state, service, version, banner) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
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
            cur.execute("SELECT * FROM ports WHERE target_id = %s", (target_id,))
            return [Port(**dict(r)) for r in cur.fetchall()]

    def add_finding(self, f: Finding) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO findings (id, engagement_id, host, port, protocol, title, description, severity, "
                "cvss_score, cve_ids, epss_score, cwe_id, owasp_category, tool_source, evidence, request, "
                "response, remediation, false_positive, confirmed, discovered_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, "
                "severity=EXCLUDED.severity, evidence=EXCLUDED.evidence, remediation=EXCLUDED.remediation, "
                "false_positive=EXCLUDED.false_positive, confirmed=EXCLUDED.confirmed",
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
            sql = "SELECT * FROM findings WHERE engagement_id = %s"
            params: list[Any] = [eng_id]
            if severity:
                sql += " AND severity = %s"
                params.append(severity.value)
            sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
            cur.execute(sql, tuple(params))
            out: list[Finding] = []
            for r in cur.fetchall():
                d = dict(r)
                d["cve_ids"] = json.loads(d.get("cve_ids") or "[]")
                d["false_positive"] = bool(d["false_positive"])
                d["confirmed"] = bool(d["confirmed"])
                out.append(Finding(**d))
            return out

    def count_findings_by_severity(self, eng_id: str) -> dict[str, int]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings WHERE engagement_id = %s AND false_positive = 0 GROUP BY severity",
                (eng_id,),
            )
            return {r["severity"]: r["cnt"] for r in cur.fetchall()}

    def replace_findings(self, eng_id: str, findings: list[Finding]) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM findings WHERE engagement_id = %s", (eng_id,))
        for f in findings:
            f.engagement_id = eng_id
            self.add_finding(f)

    def add_credential(self, c: Credential) -> str:
        enc_pw = self._cipher.encrypt(c.password)
        enc_hash = self._cipher.encrypt(c.hash_value)
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO credentials (id, engagement_id, host, port, service, username, password, hash_value, source, confirmed) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET password=EXCLUDED.password, hash_value=EXCLUDED.hash_value",
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
            cur.execute("SELECT * FROM credentials WHERE engagement_id = %s", (eng_id,))
            out: list[Credential] = []
            for r in cur.fetchall():
                d = dict(r)
                d["confirmed"] = bool(d["confirmed"])
                d["password"] = self._cipher.decrypt(d.get("password") or "")
                d["hash_value"] = self._cipher.decrypt(d.get("hash_value") or "")
                out.append(Credential(**d))
            return out

    def add_chain(self, c: AttackChain) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO chains (id, engagement_id, name, description, steps, confidence, impact, confirmed, poc_script) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET steps=EXCLUDED.steps, confidence=EXCLUDED.confidence",
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
        with self._cursor() as cur:
            cur.execute("DELETE FROM chains WHERE engagement_id = %s", (eng_id,))
        for c in chains:
            c.engagement_id = eng_id
            self.add_chain(c)

    def get_chains(self, eng_id: str) -> list[AttackChain]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM chains WHERE engagement_id = %s", (eng_id,))
            out: list[AttackChain] = []
            for r in cur.fetchall():
                d = dict(r)
                d["steps"] = json.loads(d.get("steps") or "[]")
                d["confirmed"] = bool(d["confirmed"])
                out.append(AttackChain(**d))
            return out

    def add_proxy_entry(self, entry: ProxyEntry) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO proxy_history (id, engagement_id, method, url, host, port, request_headers, "
                "request_body, status_code, response_headers, response_body, findings_count, captured_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET status_code=EXCLUDED.status_code, findings_count=EXCLUDED.findings_count",
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
                    "SELECT * FROM proxy_history WHERE engagement_id = %s ORDER BY captured_at DESC LIMIT %s",
                    (eng_id, max(1, limit)),
                )
            else:
                cur.execute(
                    "SELECT * FROM proxy_history ORDER BY captured_at DESC LIMIT %s",
                    (max(1, limit),),
                )
            out: list[ProxyEntry] = []
            for r in cur.fetchall():
                d = dict(r)
                d["request_headers"] = json.loads(d.get("request_headers") or "{}")
                d["response_headers"] = json.loads(d.get("response_headers") or "{}")
                out.append(ProxyEntry(**d))
            return out

    def get_proxy_entry(self, entry_id: str) -> ProxyEntry | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM proxy_history WHERE id = %s", (entry_id,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["request_headers"] = json.loads(d.get("request_headers") or "{}")
            d["response_headers"] = json.loads(d.get("response_headers") or "{}")
            return ProxyEntry(**d)

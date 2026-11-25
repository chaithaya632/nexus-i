"""SQLite database layer for NEXUS — lightweight, encrypted-at-rest capable."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

from nexus.db.models import (
    AttackChain,
    Credential,
    Engagement,
    EngagementPhase,
    Finding,
    Port,
    Severity,
    Target,
)

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

CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
CREATE INDEX IF NOT EXISTS idx_targets_engagement ON targets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_ports_target ON ports(target_id);
"""


class EngagementStore:
    """Lightweight SQLite storage for NEXUS engagement data."""

    def __init__(self, db_path: Path | str) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

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

    # --- Engagements ---

    def create_engagement(self, eng: Engagement) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO engagements (id, name, target, scope_file, phase, created_at, updated_at, stealth, tier, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (eng.id, eng.name, eng.target, eng.scope_file, eng.phase.value,
                 eng.created_at.isoformat(), eng.updated_at.isoformat(),
                 eng.stealth, eng.tier, eng.notes),
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
        with self._cursor() as cur:
            cur.execute(
                "UPDATE engagements SET phase = ?, updated_at = datetime('now') WHERE id = ?",
                (phase.value, eng_id),
            )

    def delete_engagement(self, eng_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM chains WHERE engagement_id = ?", (eng_id,))
            cur.execute("DELETE FROM credentials WHERE engagement_id = ?", (eng_id,))
            cur.execute("DELETE FROM findings WHERE engagement_id = ?", (eng_id,))
            for row in cur.execute("SELECT id FROM targets WHERE engagement_id = ?", (eng_id,)).fetchall():
                cur.execute("DELETE FROM ports WHERE target_id = ?", (row["id"],))
            cur.execute("DELETE FROM targets WHERE engagement_id = ?", (eng_id,))
            cur.execute("DELETE FROM engagements WHERE id = ?", (eng_id,))

    # --- Targets ---

    def add_target(self, t: Target) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO targets (id, engagement_id, host, ip, is_live, os_guess, tech_stack, waf_detected) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "host=excluded.host, ip=excluded.ip, is_live=excluded.is_live, "
                "os_guess=excluded.os_guess, tech_stack=excluded.tech_stack, "
                "waf_detected=excluded.waf_detected",
                (t.id, t.engagement_id, t.host, t.ip, int(t.is_live),
                 t.os_guess, json.dumps(t.tech_stack), t.waf_detected),
            )
        return t.id

    def get_targets(self, eng_id: str) -> list[Target]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM targets WHERE engagement_id = ?", (eng_id,))
            results = []
            for r in cur.fetchall():
                d = dict(r)
                d["is_live"] = bool(d["is_live"])
                d["tech_stack"] = json.loads(d.get("tech_stack", "[]"))
                results.append(Target(**d))
            return results

    # --- Ports ---

    def add_port(self, p: Port) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO ports (id, target_id, port, protocol, state, service, version, banner) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (p.id, p.target_id, p.port, p.protocol, p.state,
                 p.service, p.version, p.banner),
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
                (f.id, f.engagement_id, f.host, f.port, f.protocol,
                 f.title, f.description, f.severity.value, f.cvss_score,
                 json.dumps(f.cve_ids), f.epss_score, f.cwe_id, f.owasp_category,
                 f.tool_source, f.evidence, f.request, f.response, f.remediation,
                 int(f.false_positive), int(f.confirmed), f.discovered_at.isoformat()),
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
                d["cve_ids"] = json.loads(d.get("cve_ids", "[]"))
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
                    (f.id, eng_id, f.host, f.port, f.protocol,
                     f.title, f.description, f.severity.value, f.cvss_score,
                     json.dumps(f.cve_ids), f.epss_score, f.cwe_id, f.owasp_category,
                     f.tool_source, f.evidence, f.request, f.response, f.remediation,
                     int(f.false_positive), int(f.confirmed), f.discovered_at.isoformat()),
                )

    # --- Credentials ---

    def add_credential(self, c: Credential) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO credentials "
                "(id, engagement_id, host, port, service, username, password, hash_value, source, confirmed) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (c.id, c.engagement_id, c.host, c.port, c.service,
                 c.username, c.password, c.hash_value, c.source, int(c.confirmed)),
            )
        return c.id

    def get_credentials(self, eng_id: str) -> list[Credential]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM credentials WHERE engagement_id = ?", (eng_id,))
            results = []
            for r in cur.fetchall():
                d = dict(r)
                d["confirmed"] = bool(d["confirmed"])
                results.append(Credential(**d))
            return results

    # --- Attack Chains ---

    def add_chain(self, c: AttackChain) -> str:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO chains "
                "(id, engagement_id, name, description, steps, confidence, impact, confirmed, poc_script) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (c.id, c.engagement_id, c.name, c.description,
                 json.dumps([s.model_dump() for s in c.steps]),
                 c.confidence, c.impact.value, int(c.confirmed), c.poc_script),
            )
        return c.id

    def get_chains(self, eng_id: str) -> list[AttackChain]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM chains WHERE engagement_id = ?", (eng_id,))
            results = []
            for r in cur.fetchall():
                d = dict(r)
                d["steps"] = json.loads(d.get("steps", "[]"))
                d["confirmed"] = bool(d["confirmed"])
                results.append(AttackChain(**d))
            return results

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

        return {
            "engagement": eng.model_dump(mode="json"),
            "targets": [t.model_dump(mode="json") for t in targets],
            "ports": all_ports,
            "findings": [f.model_dump(mode="json") for f in self.get_findings(eng_id)],
            "credentials": [c.model_dump(mode="json") for c in self.get_credentials(eng_id)],
            "chains": [c.model_dump(mode="json") for c in self.get_chains(eng_id)],
            "severity_counts": self.count_findings_by_severity(eng_id),
        }

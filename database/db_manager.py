"""
database/db_manager.py
========================
SQLite persistence layer for wamiqsec/ReconMind.

Stores findings across sessions so scan history persists.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from contextlib import contextmanager

from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)

SCHEMA_VERSION = 3

CREATE_TABLES_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    target_count INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES scan_sessions(id),
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    scheme TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    param_count INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    http_status INTEGER,
    UNIQUE(session_id, url)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES scan_sessions(id),
    target_id INTEGER REFERENCES targets(id),
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    parameter TEXT NOT NULL,
    param_type TEXT NOT NULL,
    module TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER DEFAULT 0,
    context TEXT,
    payload TEXT,
    evidence TEXT,
    reasons TEXT,
    recommendations TEXT,
    notes TEXT,
    raw_data TEXT,
    discovered_at TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    UNIQUE(url, parameter, module, payload)
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
"""


class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._ensure_directory()
        self._init_schema()
        self._current_session_id: Optional[int] = None

    def _ensure_directory(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as exc:
            conn.rollback()
            log.error("Database error: %s", exc)
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(CREATE_TABLES_SQL)
                cursor = conn.execute("SELECT MAX(version) as v FROM schema_version")
                row = cursor.fetchone()
                current_version = row["v"] if row and row["v"] else 0
                if current_version < SCHEMA_VERSION:
                    conn.execute(
                        "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                        (SCHEMA_VERSION, datetime.utcnow().isoformat()),
                    )
        except Exception as exc:
            log.error("Failed to initialize database: %s", exc)

    def start_session(self, notes: str = "") -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scan_sessions (started_at, notes) VALUES (?, ?)",
                (datetime.utcnow().isoformat(), notes),
            )
            session_id = cursor.lastrowid
            self._current_session_id = session_id
            log.info("Scan session started: id=%d", session_id)
            return session_id

    def end_session(self, session_id: int, target_count: int, finding_count: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scan_sessions SET ended_at=?, target_count=?, finding_count=? WHERE id=?",
                (datetime.utcnow().isoformat(), target_count, finding_count, session_id),
            )
        log.info("Session %d complete: %d targets, %d findings", session_id, target_count, finding_count)

    def save_target(self, url: str, host: str, scheme: str, session_id: int,
                     param_count: int = 0, http_status: int = 0) -> int:
        with self._connect() as conn:
            try:
                cursor = conn.execute(
                    """INSERT OR REPLACE INTO targets
                       (session_id, url, host, scheme, scanned_at, param_count, http_status)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (session_id, url, host, scheme, datetime.utcnow().isoformat(), param_count, http_status),
                )
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                cursor = conn.execute("SELECT id FROM targets WHERE session_id=? AND url=?", (session_id, url))
                row = cursor.fetchone()
                return row["id"] if row else 0

    def save_finding(self, finding_obj: Any, module: str,
                      session_id: Optional[int] = None, target_id: Optional[int] = None) -> bool:
        sid = session_id or self._current_session_id or 0
        url = getattr(finding_obj, "url", "")
        host = self._extract_host(url)
        parameter = getattr(finding_obj, "parameter", "")
        param_type = getattr(finding_obj, "param_type", "UNKNOWN")
        severity = getattr(finding_obj, "severity", "INFO")
        score = getattr(finding_obj, "confidence", getattr(finding_obj, "score", 0))
        context = getattr(finding_obj, "context_type", getattr(finding_obj, "context", ""))
        payload = getattr(finding_obj, "confirmed_payload", getattr(finding_obj, "payload", ""))
        evidence = str(getattr(finding_obj, "evidence_lines", getattr(finding_obj, "evidence", "")))
        notes = getattr(finding_obj, "notes", [])

        try:
            raw_data = json.dumps(finding_obj.__dict__, default=str)
        except Exception:
            raw_data = "{}"

        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO findings
                       (session_id, target_id, url, host, parameter, param_type, module,
                        severity, score, context, payload, evidence, reasons,
                        recommendations, notes, raw_data, discovered_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (sid, target_id, url, host, parameter, param_type, module, severity,
                     score, context, payload, evidence, "[]", "[]",
                     json.dumps(notes), raw_data, datetime.utcnow().isoformat()),
                )
            return True
        except sqlite3.IntegrityError:
            return False
        except Exception as exc:
            log.error("Failed to save finding: %s", exc)
            return False

    def get_findings(self, severity: Optional[str] = None, module: Optional[str] = None,
                      host: Optional[str] = None, session_id: Optional[int] = None,
                      limit: int = 500) -> List[Dict]:
        conditions, params = [], []
        if severity:
            conditions.append("severity = ?"); params.append(severity.upper())
        if module:
            conditions.append("module = ?"); params.append(module.upper())
        if host:
            conditions.append("host LIKE ?"); params.append(f"%{host}%")
        if session_id:
            conditions.append("session_id = ?"); params.append(session_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT * FROM findings {where}
            ORDER BY CASE severity
                WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
                discovered_at DESC LIMIT ?
        """
        params.append(limit)
        try:
            with self._connect() as conn:
                cursor = conn.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as exc:
            log.error("Failed to query findings: %s", exc)
            return []

    def get_summary_stats(self, session_id: Optional[int] = None) -> Dict:
        where = "WHERE session_id = ?" if session_id else ""
        params = [session_id] if session_id else []
        try:
            with self._connect() as conn:
                sev_cursor = conn.execute(f"SELECT severity, COUNT(*) as cnt FROM findings {where} GROUP BY severity", params)
                by_severity = {row["severity"]: row["cnt"] for row in sev_cursor}
                mod_cursor = conn.execute(f"SELECT module, COUNT(*) as cnt FROM findings {where} GROUP BY module", params)
                by_module = {row["module"]: row["cnt"] for row in mod_cursor}
                total_cursor = conn.execute(f"SELECT COUNT(*) as cnt FROM findings {where}", params)
                total = total_cursor.fetchone()["cnt"]
        except Exception as exc:
            log.error("Failed to get stats: %s", exc)
            return {}
        return {"total": total, "by_severity": by_severity, "by_module": by_module}

    @staticmethod
    def _extract_host(url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url).hostname or url
        except Exception:
            return url


DB = DatabaseManager(CONFIG.database.db_path)

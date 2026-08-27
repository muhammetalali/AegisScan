"""مدير البيانات الموحد — DataManager (SQLite + Knowledge Graph).

الإصلاحات:
- استعلامات مُعاملة (Parameterized) بالكامل — لا SQL Injection.
- تشفير اختياري لحقل raw_data الحساس أثناء التخزين (enc: prefix).
- فهارس على أعمدة البحث الرئيسية.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

import networkx as nx

from aegis.core.crypto import decrypt_text, encrypt_text, is_encrypted
from aegis.core.exceptions import DataManagerError

logger = logging.getLogger("aegis.data_manager")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT DEFAULT 'mixed',
    root_path TEXT,
    repo_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    target TEXT NOT NULL,
    scan_type TEXT DEFAULT 'full',
    status TEXT DEFAULT 'pending',
    triggered_by TEXT DEFAULT 'cli',
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    evidence_count INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS evidences (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    category TEXT DEFAULT 'unknown',
    description TEXT NOT NULL,
    location TEXT,
    raw_data TEXT,
    confidence_weight REAL DEFAULT 0.5,
    context TEXT DEFAULT '{}',
    content_hash TEXT,
    timestamp TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence_score REAL NOT NULL,
    status TEXT DEFAULT 'detected',
    category TEXT DEFAULT 'unknown',
    description TEXT NOT NULL,
    root_cause TEXT,
    attack_path TEXT,
    remediation_suggestion TEXT,
    exploit_proof TEXT,
    context TEXT DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (finding_id, evidence_id),
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (evidence_id) REFERENCES evidences(id)
);
CREATE TABLE IF NOT EXISTS remediations (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    generated_patch TEXT NOT NULL,
    old_code_snippet TEXT,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    method TEXT DEFAULT 'pattern_based',
    confidence REAL DEFAULT 0.5,
    test_results TEXT DEFAULT '[]',
    status TEXT DEFAULT 'generated',
    pull_request_url TEXT,
    applied_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    name TEXT NOT NULL,
    asset_type TEXT DEFAULT 'unknown',
    criticality TEXT DEFAULT 'medium',
    value TEXT NOT NULL,
    metadata TEXT DEFAULT '{}',
    tags TEXT DEFAULT '[]',
    discovered_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);
CREATE INDEX IF NOT EXISTS idx_evidences_scan ON evidences(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidences_hash ON evidences(content_hash);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
"""


def _iso(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


class DataManager:
    """واجهة موحدة للتخزين العلائقي والبياني."""

    def __init__(
        self,
        db_path: str = "aegis.db",
        key: Optional[bytes] = None,
        encrypt_raw_data: bool = False,
    ) -> None:
        self.db_path = db_path
        self._key = key
        self._encrypt_raw = bool(encrypt_raw_data and key)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self.graph: nx.DiGraph = nx.DiGraph()
        self._init_db()

    # ─── التهيئة ──────────────────────────────────────────────

    def _init_db(self) -> None:
        try:
            with self._lock:
                self._conn = sqlite3.connect(
                    ":memory:" if self.db_path == ":memory:" else str(self.db_path),
                    check_same_thread=False,
                )
                self._conn.row_factory = sqlite3.Row
                self._conn.executescript(_SCHEMA)
                self._conn.commit()
                logger.info("قاعدة البيانات جاهزة: %s", self.db_path)
        except sqlite3.Error as exc:
            raise DataManagerError(f"فشل تهيئة قاعدة البيانات: {exc}") from exc

    # ─── تنفيذ عام ────────────────────────────────────────────

    def execute_query(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute(query, params)
                return [dict(row) for row in cur.fetchall()]
            except sqlite3.Error as exc:
                raise DataManagerError(f"خطأ في الاستعلام: {exc}") from exc

    def execute_write(self, query: str, params: tuple = ()) -> int:
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute(query, params)
                self._conn.commit()
                return cur.lastrowid if cur.lastrowid is not None else cur.rowcount
            except sqlite3.Error as exc:
                raise DataManagerError(f"خطأ في الكتابة: {exc}") from exc

    # ─── الأدلة ───────────────────────────────────────────────

    def save_evidence(self, evidence: Dict[str, Any]) -> str:
        raw = evidence.get("raw_data")
        stored_raw = raw
        if raw and self._encrypt_raw:
            stored_raw = encrypt_text(raw, self._key)

        self.execute_write(
            """
            INSERT OR REPLACE INTO evidences
            (id, scan_id, source_tool, evidence_type, category, description,
             location, raw_data, confidence_weight, context, content_hash, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence.get("id"),
                evidence.get("scan_id"),
                evidence.get("source_tool"),
                evidence.get("evidence_type", "unknown"),
                evidence.get("category", "unknown"),
                evidence.get("description"),
                evidence.get("location"),
                stored_raw,
                evidence.get("confidence_weight", 0.5),
                json.dumps(evidence.get("context", {}), ensure_ascii=False),
                evidence.get("content_hash") or evidence.get("hash"),
                _iso(evidence.get("timestamp")),
            ),
        )
        return evidence["id"]

    def get_evidences_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        rows = self.execute_query(
            "SELECT * FROM evidences WHERE scan_id = ? ORDER BY timestamp",
            (scan_id,),
        )
        for row in rows:
            if isinstance(row.get("raw_data"), str) and is_encrypted(row["raw_data"]):
                row["raw_data"] = decrypt_text(row["raw_data"], self._key or b"")
            try:
                row["context"] = json.loads(row.get("context") or "{}")
            except (json.JSONDecodeError, TypeError):
                row["context"] = {}
        return rows

    # ─── الثغرات ──────────────────────────────────────────────

    def save_finding(self, finding: Dict[str, Any]) -> str:
        ctx = finding.get("context", {})
        self.execute_write(
            """
            INSERT OR REPLACE INTO findings
            (id, scan_id, title, severity, confidence_score, status, category,
             description, root_cause, attack_path, remediation_suggestion,
             exploit_proof, context)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.get("id"),
                finding.get("scan_id"),
                finding.get("title"),
                finding.get("severity"),
                finding.get("confidence_score"),
                finding.get("status", "detected"),
                finding.get("category", "unknown"),
                finding.get("description"),
                finding.get("root_cause"),
                finding.get("attack_path"),
                finding.get("remediation_suggestion"),
                finding.get("exploit_proof"),
                json.dumps(ctx, ensure_ascii=False),
            ),
        )
        for evidence_id in finding.get("evidence_ids", []):
            self.execute_write(
                "INSERT OR REPLACE INTO finding_evidence "
                "(finding_id, evidence_id) VALUES (?, ?)",
                (finding["id"], evidence_id),
            )
        return finding["id"]

    def get_findings_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        return self.execute_query(
            "SELECT * FROM findings WHERE scan_id = ? "
            "ORDER BY confidence_score DESC",
            (scan_id,),
        )

    def list_findings(
        self, severity: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        if severity:
            return self.execute_query(
                "SELECT * FROM findings WHERE severity = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (severity, limit),
            )
        return self.execute_query(
            "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,)
        )

    # ─── الفحوصات ─────────────────────────────────────────────

    def save_scan(self, scan: Dict[str, Any]) -> str:
        self.execute_write(
            """
            INSERT OR REPLACE INTO scans
            (id, project_id, target, scan_type, status, triggered_by,
             started_at, finished_at, evidence_count, finding_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan.get("id"),
                scan.get("project_id"),
                scan.get("target"),
                scan.get("scan_type", "full"),
                scan.get("status", "pending"),
                scan.get("triggered_by", "cli"),
                _iso(scan.get("started_at")),
                _iso(scan.get("finished_at")),
                scan.get("evidence_count", 0),
                scan.get("finding_count", 0),
            ),
        )
        return scan["id"]

    # ─── الرسم البياني ────────────────────────────────────────

    def add_node(self, node_id: str, node_type: str, **attrs: Any) -> None:
        self.graph.add_node(node_id, type=node_type, **attrs)

    def add_edge(self, source: str, target: str, relation: str, **attrs: Any) -> None:
        self.graph.add_node(source, type="unknown")
        self.graph.add_node(target, type="unknown")
        self.graph.add_edge(source, target, relation=relation, **attrs)

    # ─── الإحصائيات والإغلاق ─────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        stats: Dict[str, Any] = {}
        for table in ("projects", "scans", "evidences", "findings", "remediations", "assets"):
            row = self.execute_query(f"SELECT COUNT(*) AS c FROM {table}")  # nosec B608 - table is selected from a fixed allowlist
            stats[table] = row[0]["c"] if row else 0
        stats["graph_nodes"] = self.graph.number_of_nodes()
        stats["graph_edges"] = self.graph.number_of_edges()
        return stats

    def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    def __enter__(self) -> "DataManager":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

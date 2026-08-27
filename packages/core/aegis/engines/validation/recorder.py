"""Action Recorder — مسجل الإجراءات.

يُسجّل كل إجراء تم تنفيذه مع الوقت والمدخلات والمخرجات.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.validation.recorder")


class ActionRecorder:
    """مسجّل الإجراءات — يخزن سجل كل ما حدث في قاعدة بيانات."""

    name = "ActionRecorder"

    def __init__(
        self,
        event_bus: EventBus,
        db_path: str = ":memory:",
    ) -> None:
        self.event_bus = event_bus
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        """تهيئة قاعدة البيانات."""
        self._conn = sqlite3.connect(self._db_path)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS action_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL,
                plan_id TEXT,
                action_type TEXT NOT NULL,
                level TEXT NOT NULL,
                target TEXT,
                parameters TEXT,
                result TEXT,
                error TEXT,
                success INTEGER,
                duration_seconds REAL,
                recorded_at TEXT NOT NULL
            )
        """)
        self._conn.commit()

    async def record_action(
        self,
        action_id: str,
        plan_id: Optional[str],
        action_type: str,
        level: str,
        target: str,
        parameters: Dict[str, Any],
        result: Any = None,
        error: Optional[str] = None,
        success: bool = True,
        duration_seconds: float = 0.0,
    ) -> None:
        """تسجيل إجراء واحد."""
        now = datetime.now(timezone.utc).isoformat()

        self._conn.execute(
            """
            INSERT INTO action_log
            (action_id, plan_id, action_type, level, target,
             parameters, result, error, success, duration_seconds, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action_id, plan_id, action_type, level, target,
                json.dumps(parameters, default=str),
                json.dumps(result, default=str) if result else None,
                error,
                1 if success else 0,
                duration_seconds,
                now,
            ),
        )
        self._conn.commit()

        # نشر عبر EventBus
        await self.event_bus.publish(
            topic="action.recorded",
            payload={
                "action_id": action_id,
                "plan_id": plan_id,
                "success": success,
                "recorded_at": now,
            },
            source=self.name,
        )

    def get_log(
        self,
        plan_id: Optional[str] = None,
        action_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """استرجاع سجل الإجراءات."""
        query = "SELECT * FROM action_log WHERE 1=1"
        params: list = []

        if plan_id:
            query += " AND plan_id = ?"
            params.append(plan_id)
        if action_id:
            query += " AND action_id = ?"
            params.append(action_id)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor = self._conn.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_summary(self) -> Dict[str, Any]:
        """ملخص السجل."""
        cursor = self._conn.execute(
            "SELECT COUNT(*), SUM(success), SUM(duration_seconds) FROM action_log"
        )
        row = cursor.fetchone()
        return {
            "total_actions": row[0] or 0,
            "successful": row[1] or 0,
            "failed": (row[0] or 0) - (row[1] or 0),
            "total_duration": round(row[2] or 0, 2),
        }

    def close(self) -> None:
        """إغلاق قاعدة البيانات."""
        if self._conn:
            self._conn.close()

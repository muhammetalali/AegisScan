"""مستودعات البيانات — Data Repositories.

يفصل DataManager إلى مستودعات مخصصة لكل نوع بيانات.
كل محرك يستخدم المستودع الخاص به فقط — لا اعتماد على DataManager الكامل.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from aegis.core.crypto import decrypt_text, encrypt_text, is_encrypted
from aegis.core.data_manager import DataManager, _iso

logger = logging.getLogger("aegis.repositories")


class EvidenceRepository:
    """مستودع الأدلة — يدير تخزين واسترجاع الأدلة."""

    def __init__(self, data_manager: DataManager) -> None:
        self._dm = data_manager

    def save(self, evidence: Dict[str, Any]) -> str:
        """حفظ دليل واحد."""
        return self._dm.save_evidence(evidence)

    def get_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """استرجاع كل أدلة فحص معين."""
        return self._dm.get_evidences_by_scan(scan_id)

    def count(self, scan_id: Optional[str] = None) -> int:
        """عدد الأدلة (للفحص أو الإجمالي)."""
        if scan_id:
            rows = self._dm.execute_query(
                "SELECT COUNT(*) AS c FROM evidences WHERE scan_id = ?",
                (scan_id,),
            )
        else:
            rows = self._dm.execute_query("SELECT COUNT(*) AS c FROM evidences")
        return rows[0]["c"] if rows else 0

    def get_by_hash(self, content_hash: str) -> Optional[Dict[str, Any]]:
        """استرجاع دليل بالبصمة (للتحقق من التكرار)."""
        rows = self._dm.execute_query(
            "SELECT * FROM evidences WHERE content_hash = ? LIMIT 1",
            (content_hash,),
        )
        return rows[0] if rows else None


class FindingRepository:
    """مستودع الثغرات — يدير تخزين واسترجاع الثغرات."""

    def __init__(self, data_manager: DataManager) -> None:
        self._dm = data_manager

    def save(self, finding: Dict[str, Any]) -> str:
        """حفظ ثغرة واحدة."""
        return self._dm.save_finding(finding)

    def get_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """استرجاع ثغرات فحص معين."""
        return self._dm.get_findings_by_scan(scan_id)

    def list_all(
        self, severity: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """سرد الثغرات مع فلترة اختيارية."""
        return self._dm.list_findings(severity=severity, limit=limit)

    def count(self, scan_id: Optional[str] = None) -> int:
        """عدد الثغرات."""
        if scan_id:
            rows = self._dm.execute_query(
                "SELECT COUNT(*) AS c FROM findings WHERE scan_id = ?",
                (scan_id,),
            )
        else:
            rows = self._dm.execute_query("SELECT COUNT(*) AS c FROM findings")
        return rows[0]["c"] if rows else 0

    def get_by_evidence(self, evidence_id: str) -> List[Dict[str, Any]]:
        """استرجاع الثغرات المرتبطة بدليل معين."""
        return self._dm.execute_query(
            "SELECT f.* FROM findings f "
            "JOIN finding_evidence fe ON f.id = fe.finding_id "
            "WHERE fe.evidence_id = ?",
            (evidence_id,),
        )


class ScanRepository:
    """مستودع الفحوصات — يدير تخزين واسترجاع جلسات الفحص."""

    def __init__(self, data_manager: DataManager) -> None:
        self._dm = data_manager

    def save(self, scan: Dict[str, Any]) -> str:
        """حفظ فحص واحد."""
        return self._dm.save_scan(scan)

    def get(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """استرجاع فحص بالمعرف."""
        rows = self._dm.execute_query(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        )
        return rows[0] if rows else None

    def count(self) -> int:
        """عدد الفحوصات."""
        rows = self._dm.execute_query("SELECT COUNT(*) AS c FROM scans")
        return rows[0]["c"] if rows else 0

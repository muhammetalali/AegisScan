"""سجل التدقيق المشفر — Encrypted Audit Logger.

الإصلاحان الحرجان:
1. المفتاح دائم (ملف) وليس عشوائياً كل تشغيل — السجلات تبقى مقروءة.
2. الفشل الافتراضي هو تحذير لا استثناء — فشل تدقيق لا يُسقط الفحص
   (وضع صارم اختياري audit_strict=True للمؤسسات التي تريد Fail-Closed).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from aegis.core.crypto import load_or_create_key
from aegis.core.exceptions import AuditError

logger = logging.getLogger("aegis.audit")


class AuditLogger:
    """سجل تدقيق مشفر لكل عملية حساسة (خاصة الهجومية)."""

    def __init__(
        self,
        log_file: str = "audit.log",
        key_file: str = ".aegis_audit.key",
        key: Optional[bytes] = None,
        strict: bool = False,
    ) -> None:
        from cryptography.fernet import Fernet

        self.log_file = Path(log_file)
        self.strict = strict
        self._key = key if key is not None else load_or_create_key(key_file)
        self._cipher = Fernet(self._key)
        self._entry_count = 0
        logger.info("سجل التدقيق جاهز: %s", self.log_file)

    def log(
        self,
        user_id: str,
        action: str,
        target: str,
        result: str,
        ip: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> None:
        """تسجيل عملية حساسة. لا يرفع استثناء إلا في الوضع الصارم."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "action": action,
            "target": target,
            "result": result,
            "ip": ip or "unknown",
            "extra": extra or {},
        }
        try:
            encrypted = self._cipher.encrypt(
                json.dumps(entry, ensure_ascii=False).encode("utf-8")
            )
            with open(self.log_file, "ab") as f:
                f.write(encrypted + b"\n")
            self._entry_count += 1
        except Exception as exc:
            logger.error("فشل كتابة سجل التدقيق: %s", exc)
            if self.strict:
                raise AuditError(f"فشل كتابة التدقيق: {exc}") from exc

    def read_logs(self, limit: int = 100) -> List[dict]:
        """قراءة آخر `limit` سجل مفكوكاً."""
        if not self.log_file.exists():
            return []
        entries: List[dict] = []
        lines = self.log_file.read_bytes().splitlines()
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(self._cipher.decrypt(line).decode("utf-8")))
            except Exception as exc:
                logger.warning("تخطي سجل غير قابل للفك: %s", exc)
        return entries

    def search(
        self, action: Optional[str] = None, user_id: Optional[str] = None
    ) -> List[dict]:
        results = [
            entry
            for entry in self.read_logs(limit=10_000)
            if (action is None or entry.get("action") == action)
            and (user_id is None or entry.get("user_id") == user_id)
        ]
        return results

    @property
    def key(self) -> bytes:
        """المفتاح — انقله إلى Vault واحتفظ به آمناً."""
        return self._key

    def __repr__(self) -> str:
        return f"AuditLogger(file={self.log_file}, entries={self._entry_count})"

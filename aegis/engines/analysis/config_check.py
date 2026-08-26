"""Configuration Check Engine — محرك فحص الإعدادات الأمنية.

يحلل ملفات الإعدادات (config files, env, docker-compose, .env)
لاكتشاف إعدادات غير آمنة.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List

from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.analysis.config")

# قواعد فحص الإعدادات
CONFIG_RULES: List[Dict[str, Any]] = [
    {
        "pattern": r"(?i)(?:DEBUG|debug)\s*[=:]\s*(?:true|1|yes|on)",
        "severity": "medium",
        "category": EvidenceCategory.UNKNOWN,
        "desc": "وضع التشخيص مفعّل — يجب تعطيله في الإنتاج",
        "rule_id": "CONFIG_DEBUG_MODE",
    },
    {
        "pattern": r"(?i)(?:SECRET_KEY|SECRET|TOKEN)\s*[=:]\s*['\"]?[\w\-=+/]{16,}['\"]?",
        "severity": "high",
        "category": EvidenceCategory.SECRETS,
        "desc": "مفتاح سري مكتوب في ملف الإعدادات — يجب استخدام متغيرات البيئة",
        "rule_id": "CONFIG_SECRET_IN_FILE",
    },
    {
        "pattern": r"(?i)ALLOWED_HOSTS\s*[=:]\s*\[?\s*['\"]?\*['\"]?\s*\]?",
        "severity": "high",
        "category": EvidenceCategory.AUTHORIZATION,
        "desc": "جميع المضيفين مسموح بهم (*) — خطر على HTTP Host Injection",
        "rule_id": "CONFIG_OPEN_HOSTS",
    },
    {
        "pattern": r"(?i)(?:CORS|Access-Control-Allow-Origin)\s*[=:]\s*['\"]?\*['\"]?",
        "severity": "medium",
        "category": EvidenceCategory.AUTHORIZATION,
        "desc": "CORS يسمح لكل_origins — خطر على CSRF",
        "rule_id": "CONFIG_OPEN_CORS",
    },
    {
        "pattern": r"(?i)(?:bind|host)\s*[=:]\s*['\"]?0\.0\.0\.0['\"]?",
        "severity": "medium",
        "category": EvidenceCategory.CONFIGURATION,
        "desc": "الخدمة تستمع على كل الواجهات (0.0.0.0) — تأكد من الجدار الناري",
        "rule_id": "CONFIG_BIND_ALL",
    },
    {
        "pattern": r"(?i)(?:password|passwd)\s*[=:]\s*['\"]?[\w\-=+/!@#$%^&*]{4,}['\"]?",
        "severity": "high",
        "category": EvidenceCategory.SECRETS,
        "desc": "كلمة مرور مكتوبة في ملف الإعدادات",
        "rule_id": "CONFIG_PASSWORD_IN_FILE",
    },
    {
        "pattern": r"(?i)SSL_VERIFY\s*[=:]\s*(?:false|0|no|off)",
        "severity": "high",
        "category": EvidenceCategory.CRYPTOGRAPHY,
        "desc": "التحقق من SSL معطّل — خطر على Man-in-the-Middle",
        "rule_id": "CONFIG_SSL_DISABLED",
    },
    {
        "pattern": r"(?i)(?:REDIS|MYSQL|POSTGRES|DB)_URL\s*[=:]\s*['\"]?\w+://[^/\s]+@",
        "severity": "medium",
        "category": EvidenceCategory.SECRETS,
        "desc": "رابط قاعدة بيانات يحتوي كلمة مرور مكشوفة",
        "rule_id": "CONFIG_DB_URL_CREDENTIALS",
    },
    {
        "pattern": r"(?i)(?:ADMIN|root)\s*(?:password|passwd|pass)\s*[=:]\s*['\"]?.{4,}",
        "severity": "critical",
        "category": EvidenceCategory.AUTHENTICATION,
        "desc": "كلمة مرور administrator/root في ملف الإعدادات",
        "rule_id": "CONFIG_ADMIN_PASSWORD",
    },
]


class ConfigurationCheckEngine:
    """محرك فحص الإعدادات — يحلل ملفات الإعدادات والبيئة."""

    name = "ConfigurationCheckEngine"

    # الامتدادات المدعومة
    CONFIG_EXTENSIONS = {
        ".env", ".ini", ".cfg", ".conf", ".yaml", ".yml",
        ".toml", ".json", ".docker-compose", ".docker-compose.yml",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    }

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus

    async def check_config(
        self,
        project_path: str,
        scan_id: str,
    ) -> List[Evidence]:
        """فحص إعدادات المشروع."""
        path = Path(project_path)
        config_files = self._find_config_files(path)
        if not config_files:
            logger.warning("لم يتم العثور على ملفات إعدادات في %s", project_path)
            return []

        evidences: List[Evidence] = []
        for cfg_file in config_files:
            evs = self._check_single_file(cfg_file, scan_id)
            evidences.extend(evs)

        for ev in evidences:
            await self.event_bus.publish(
                topic="evidence.new", payload=ev.to_dict(), source=self.name
            )

        logger.info("فحص الإعدادات: %d ملف → %d أدلة", len(config_files), len(evidences))
        return evidences

    def _find_config_files(self, path: Path) -> List[Path]:
        """البحث عن ملفات الإعدادات."""
        files: List[Path] = []
        checked: set = set()

        # ملفات مباشرة في الجذر
        for item in path.iterdir():
            if item.is_file() and self._is_config_file(item):
                files.append(item)
                checked.add(str(item))

        # .env files
        for f in path.glob(".env*"):
            if str(f) not in checked:
                files.append(f)
                checked.add(str(f))

        # docker-compose
        for f in path.glob("docker-compose*.y*ml"):
            if str(f) not in checked:
                files.append(f)
                checked.add(str(f))

        # Dockerfile
        for f in path.glob("Dockerfile*"):
            if str(f) not in checked:
                files.append(f)
                checked.add(str(f))

        return files

    def _is_config_file(self, path: Path) -> bool:
        """تحديد ما إذا كان الملف ملف إعدادات."""
        name = path.name.lower()
        suffix = path.suffix.lower()
        return (
            suffix in {".env", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".toml"}
            or "config" in name
            or "settings" in name
            or name in {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}
        )

    def _check_single_file(self, file_path: Path, scan_id: str) -> List[Evidence]:
        """فحص ملف واحد."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        evidences: List[Evidence] = []

        for rule in CONFIG_RULES:
            for m in re.finditer(rule["pattern"], content, re.IGNORECASE):
                line_no = content[:m.start()].count("\n") + 1
                evidences.append(Evidence(
                    scan_id=scan_id,
                    source_tool="ConfigCheck.rule",
                    evidence_type=EvidenceType.LOG,
                    category=rule["category"],
                    description=f"{rule['desc']} ({file_path.name}:{line_no})",
                    location=str(file_path),
                    context={
                        "file": str(file_path),
                        "line": line_no,
                        "rule_id": rule["rule_id"],
                        "severity": rule["severity"],
                        "matched": m.group()[:100],
                    },
                ))

        return evidences

"""مدير الإعدادات — Config Manager (YAML + متغيرات البيئة).

الإصلاح الأمني: لا أسرار في الملفات — تُستبدل ${VAR} من البيئة،
والقيم الافتراضية الآمنة (gui.debug=false).
يعمل حتى لو لم تتوفر مكتبة yaml (يستخدم الافتراضيات فقط).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("aegis.config")

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except ImportError:  # pragma: no cover
    _HAS_YAML = False
    logger.warning("مكتبة PyYAML غير مثبتة — سيتم استخدام الإعدادات الافتراضية فقط")


def _defaults() -> Dict[str, Any]:
    return {
        "database": {"path": "aegis.db"},
        "logging": {"level": "INFO", "file": "aegis.log"},
        "plugins": {"directory": "aegis/plugins", "auto_load": True},
        "storage": {
            "encrypt_raw_data": False,
            "key_file": ".aegis.key",
        },
        "security": {
            "audit_log_file": "audit.log",
            "audit_key_file": ".aegis_audit.key",
            "audit_strict": False,
            "max_concurrent_scans": 3,
        },
        "twin": {
            "sandbox_dir": "aegis_sandbox",
            "sync_interval_hours": 6,
            "max_drift_threshold": 5.0,
            "network_isolation": True,
        },
        "correlation": {
            "confidence_threshold": 0.60,
        },
        "integrations": {
            "slack_webhook": "${AEGIS_SLACK_WEBHOOK}",
            "teams_webhook": "${AEGIS_TEAMS_WEBHOOK}",
        },
        "gui": {"host": "127.0.0.1", "port": 5000, "debug": False},
    }


class ConfigManager:
    """قراءة الإعدادات مع وصول هرمي: config.get("database.path")."""

    def __init__(self, config_path: str = "config.yaml") -> None:
        self.config_path = Path(config_path)
        self._config: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not _HAS_YAML:
            self._config = _defaults()
            return

        if not self.config_path.exists():
            self._config = _defaults()
            self._save()
            return

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
        except Exception as exc:
            logger.error("فشل قراءة ملف الإعدادات (%s) — استخدام الافتراضيات", exc)
            self._config = _defaults()
            return

        merged = _defaults()
        _deep_merge(merged, loaded)
        self._config = self._substitute_env_vars(merged)

    def _save(self) -> None:
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                yaml.dump(self._config, f, default_flow_style=False,
                          allow_unicode=True, sort_keys=False)
        except Exception as exc:
            logger.error("فشل حفظ ملف الإعدادات: %s", exc)

    @staticmethod
    def _substitute_env_vars(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: ConfigManager._substitute_env_vars(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [ConfigManager._substitute_env_vars(v) for v in obj]
        if (
            isinstance(obj, str)
            and obj.startswith("${")
            and obj.endswith("}")
        ):
            env_value = os.getenv(obj[2:-1])
            if env_value is None:
                logger.warning("متغير بيئة غير معرّف: %s", obj)
                return obj
            return env_value
        return obj

    def get(self, key: str, default: Any = None) -> Any:
        value: Any = self._config
        for part in key.split("."):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        parts = key.split(".")
        node = self._config
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def save(self) -> None:
        self._save()

    @property
    def all(self) -> Dict[str, Any]:
        return self._config.copy()

    def __repr__(self) -> str:
        return f"ConfigManager(path={self.config_path}, keys={len(self._config)})"


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> None:
    for key, value in override.items():
        if (
            key in base
            and isinstance(base[key], dict)
            and isinstance(value, dict)
        ):
            _deep_merge(base[key], value)
        else:
            base[key] = value

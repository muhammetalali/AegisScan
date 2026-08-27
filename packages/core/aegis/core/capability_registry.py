"""سجل قدرات المحركات — Capability Registry.

كل محرك يُسجّل هنا بmetadta واضحة: الاسم، الإصدار، المدخلات، المخرجات، الصحة.
يُستخدم لاكتشاف المحركات وتوسيع النظام بدون تعديل المنسق.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("aegis.capability_registry")


class EngineType(str, Enum):
    """أنواع المحركات المدعومة."""
    INTELLIGENCE = "intelligence"
    ANALYSIS = "analysis"
    CORRELATION = "correlation"
    STORY = "story"
    INFERENCE = "inference"
    EXTERNAL_INTEL = "external_intel"
    VALIDATION = "validation"
    OFFENSIVE = "offensive"
    REMEDIATION = "remediation"


@dataclass
class EngineCapability:
    """بيانات قدرة محرك واحد."""
    name: str
    version: str
    engine_type: EngineType
    description: str = ""
    input_types: Set[str] = field(default_factory=set)
    output_types: Set[str] = field(default_factory=set)
    event_topics: Set[str] = field(default_factory=set)
    health: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


class CapabilityRegistry:
    """سجل مركزي لقدرات كل محرك."""

    def __init__(self) -> None:
        self._engines: Dict[str, EngineCapability] = {}

    def register(self, capability: EngineCapability) -> None:
        """تسجيل محرك جديد."""
        if capability.name in self._engines:
            logger.warning(
                "المحرك '%s' مسجل مسبقاً — يتم التحديث", capability.name
            )
        self._engines[capability.name] = capability
        logger.info(
            "محرك مسجل: %s v%s (%s)",
            capability.name, capability.version, capability.engine_type.value,
        )

    def get(self, name: str) -> Optional[EngineCapability]:
        """استرجاع محرك بالاسم."""
        return self._engines.get(name)

    def list_all(self) -> List[EngineCapability]:
        """سرد كل المحركات المسجلة."""
        return list(self._engines.values())

    def list_by_type(self, engine_type: EngineType) -> List[EngineCapability]:
        """filtration by type."""
        return [
            c for c in self._engines.values()
            if c.engine_type == engine_type
        ]

    def remove(self, name: str) -> bool:
        """إزالة محرك من السجل."""
        if name in self._engines:
            del self._engines[name]
            return True
        return False

    def health_check(self) -> Dict[str, str]:
        """فحص صحة كل المحركات."""
        return {name: cap.health for name, cap in self._engines.items()}

    def summary(self) -> Dict[str, Any]:
        """ملخص السجل."""
        by_type: Dict[str, int] = {}
        for cap in self._engines.values():
            t = cap.engine_type.value
            by_type[t] = by_type.get(t, 0) + 1
        return {
            "total": len(self._engines),
            "by_type": by_type,
            "engines": [
                {"name": c.name, "version": c.version, "type": c.engine_type.value}
                for c in self._engines.values()
            ],
        }

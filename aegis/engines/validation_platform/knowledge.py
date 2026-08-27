"""Knowledge Engine — محرك إدارة المعرفة.

المرحلة السادسة: كل عملية تحقق تتحول إلى معرفة قابلة لإعادة الاستخدام عبر Knowledge Graph.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.knowledge")


class KnowledgeType(str, Enum):
    LESSON_LEARNED = "lesson_learned"
    BEST_PRACTICE = "best_practice"
    REMEDIATION_PATTERN = "remediation_pattern"
    FALSE_POSITIVE_PATTERN = "false_positive_pattern"
    ATTACK_PATTERN = "attack_pattern"
    DEFENSE_GAP = "defense_gap"
    VALIDATION_RESULT = "validation_result"


@dataclass
class KnowledgeItem:
    """عنصر معرفة."""
    item_id: str
    knowledge_type: KnowledgeType
    title: str
    description: str
    confidence: float = 0.5
    source_scans: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    related_items: List[str] = field(default_factory=list)
    times_applied: int = 0
    success_rate: float = 0.0
    created_at: Optional[datetime] = None
    last_applied: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KnowledgeQueryResult:
    """نتيجة استعلام المعرفة."""
    items: List[KnowledgeItem]
    total: int = 0
    relevance_scores: Dict[str, float] = field(default_factory=dict)


class KnowledgeEngine:
    """محرك إدارة المعرفة — يحفظ ويسترجع ويتعلم."""

    name = "KnowledgeEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._items: Dict[str, KnowledgeItem] = {}
        self._by_type: Dict[str, List[str]] = {}
        self._by_tag: Dict[str, List[str]] = {}

    async def add_knowledge(
        self,
        knowledge_type: KnowledgeType,
        title: str,
        description: str,
        confidence: float = 0.5,
        source_scan: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> KnowledgeItem:
        """إضافة عنصر معرفة."""
        item_id = hashlib.sha256(
            f"{knowledge_type.value}:{title}:{description[:50]}".encode()
        ).hexdigest()[:12]

        item = KnowledgeItem(
            item_id=f"ki_{item_id}",
            knowledge_type=knowledge_type,
            title=title,
            description=description,
            confidence=confidence,
            source_scans=[source_scan] if source_scan else [],
            tags=tags or [],
            created_at=datetime.now(timezone.utc),
        )

        self._items[item.item_id] = item
        self._by_type.setdefault(knowledge_type.value, []).append(item.item_id)
        for tag in item.tags:
            self._by_tag.setdefault(tag, []).append(item.item_id)

        await self.event_bus.publish(
            topic="knowledge.added",
            payload={"item_id": item.item_id, "type": knowledge_type.value},
            source=self.name,
        )
        return item

    async def query(
        self,
        knowledge_type: Optional[KnowledgeType] = None,
        tags: Optional[List[str]] = None,
        min_confidence: float = 0.0,
    ) -> KnowledgeQueryResult:
        """استعلام المعرفة."""
        candidates = list(self._items.values())

        if knowledge_type:
            candidates = [
                i for i in candidates if i.knowledge_type == knowledge_type
            ]

        if tags:
            tag_set = set(tags)
            candidates = [
                i for i in candidates if tag_set.intersection(i.tags)
            ]

        candidates = [i for i in candidates if i.confidence >= min_confidence]

        # حساب الأهمية
        scores: Dict[str, float] = {}
        for item in candidates:
            score = item.confidence * 0.5 + min(item.times_applied / 10, 0.3) + 0.2
            scores[item.item_id] = round(score, 3)

        candidates.sort(key=lambda i: scores.get(i.item_id, 0), reverse=True)

        return KnowledgeQueryResult(
            items=candidates,
            total=len(candidates),
            relevance_scores=scores,
        )

    async def apply_knowledge(
        self, item_id: str, scan_id: str, success: bool = True
    ) -> None:
        """تطبيق معرفة وتسجيل النتيجة."""
        item = self._items.get(item_id)
        if not item:
            return

        item.times_applied += 1
        item.last_applied = datetime.now(timezone.utc).isoformat()

        # تحديث نسبة النجاح
        total = item.times_applied
        current_successes = item.success_rate * (total - 1)
        item.success_rate = (current_successes + (1.0 if success else 0.0)) / total

        await self.event_bus.publish(
            topic="knowledge.applied",
            payload={
                "item_id": item_id,
                "success": success,
                "times_applied": item.times_applied,
            },
            source=self.name,
        )

    async def find_similar(
        self, title: str, description: str, max_results: int = 5
    ) -> List[KnowledgeItem]:
        """البحث عن معرفة مشابهة."""
        keywords = set(title.lower().split() + description.lower().split())

        scored = []
        for item in self._items.values():
            item_words = set(item.title.lower().split() + item.description.lower().split())
            overlap = len(keywords.intersection(item_words))
            if overlap > 0:
                scored.append((item, overlap))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [item for item, _ in scored[:max_results]]

    async def get_lessons_learned(self) -> List[KnowledgeItem]:
        """استرجاع الدروس المستفادة."""
        return [
            i for i in self._items.values()
            if i.knowledge_type == KnowledgeType.LESSON_LEARNED
        ]

    async def get_remediation_patterns(self) -> List[KnowledgeItem]:
        """استرجاع أنماط الإصلاح."""
        return [
            i for i in self._items.values()
            if i.knowledge_type == KnowledgeType.REMEDIATION_PATTERN
        ]

    def get_item(self, item_id: str) -> Optional[KnowledgeItem]:
        return self._items.get(item_id)

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for i in self._items.values():
            by_type[i.knowledge_type.value] = by_type.get(i.knowledge_type.value, 0) + 1
        avg_success = (
            sum(i.success_rate for i in self._items.values())
            / max(len(self._items), 1)
        )
        return {
            "total_items": len(self._items),
            "by_type": by_type,
            "avg_success_rate": round(avg_success, 2),
        }

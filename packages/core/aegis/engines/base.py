"""بروتوكولات المحركات — Engine Protocols.

كل محرك داخل Aegis يجب أن يطبق البروتوكول المناسب لنوعه.
هذا الملف يُعرّف العقود بين المحركات — لا التنفيذ.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from aegis.models.evidence import Evidence
from aegis.models.finding import Finding
from aegis.models.soc import AttackStory


@runtime_checkable
class IntelligenceEngine(Protocol):
    """محرك جمع البيانات والتحليل الأولي (الطبقة 1)."""

    @property
    def name(self) -> str:
        """اسم فريد للمحرك."""
        ...

    async def analyze(
        self, target: str, scan_id: str
    ) -> List[Evidence]:
        """تحليل الهدف وإرجاع قائمة الأدلة."""
        ...


@runtime_checkable
class CorrelationProtocol(Protocol):
    """محرك ربط الأدلة وحساب الثقة (الطبقة 2)."""

    @property
    def name(self) -> str:
        ...

    async def correlate(
        self, scan_id: str
    ) -> List[Finding]:
        """ربط الأدلة وإرجاع الثغرات المؤكدة."""
        ...


@runtime_checkable
class StoryEngine(Protocol):
    """محرك بناء القصص والسرد (الطبقة 2)."""

    @property
    def name(self) -> str:
        ...

    async def build_story(
        self, scan_id: str, findings: List[Dict[str, Any]]
    ) -> Optional[AttackStory]:
        """بناء قصة هجوم موحدة."""
        ...


@runtime_checkable
class AnalysisEngine(Protocol):
    """محرك تحليل متخصص (الطبقة 2 — أنواع متعددة)."""

    @property
    def name(self) -> str:
        ...

    async def analyze(
        self, target: str, scan_id: str
    ) -> List[Evidence]:
        """تحليل وإرجاع الأدلة."""
        ...


@runtime_checkable
class InferenceEngine(Protocol):
    """محرك استدلال (الطبقة 4 — Knowledge Graph, Why, Confidence, Risk)."""

    @property
    def name(self) -> str:
        ...

    async def infer(
        self, scan_id: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """استدلال وإرجاع النتائج."""
        ...


@runtime_checkable
class ExternalIntelEngine(Protocol):
    """محرك الاستخبارات الخارجية (الطبقة 3)."""

    @property
    def name(self) -> str:
        ...

    async def collect(
        self, target: str, scan_id: str
    ) -> List[Evidence]:
        """جمع الاستخبارات من مصادر خارجية."""
        ...


@runtime_checkable
class ValidationEngine(Protocol):
    """محرك التحقق المنضبط (الطبقة 5)."""

    @property
    def name(self) -> str:
        ...

    async def validate(
        self, finding: Finding, scan_id: str
    ) -> Dict[str, Any]:
        """التحقق من ثغرة وإرجاع تقرير التحقق."""
        ...

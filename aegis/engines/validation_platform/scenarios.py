"""Scenario Library — مكتبة السيناريوهات.

 مجموعة سيناريوهات اختبار جاهزة لاستخدامها في التحقق.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.scenario_library")


@dataclass
class Scenario:
    """سيناريو اختبار."""
    scenario_id: str
    name: str
    description: str
    category: str
    severity: str
    attack_vector: str
    expected_detection: bool = True
    control_types: List[str] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    reference: str = ""


class ScenarioLibrary:
    """مكتبة السيناريوهات — مجموعة جاهزة."""

    name = "ScenarioLibrary"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._scenarios: Dict[str, Scenario] = {}
        self._by_category: Dict[str, List[str]] = {}
        self._load_defaults()

    def _load_defaults(self) -> None:
        """تحميل السيناريوهات الافتراضية."""
        defaults = [
            Scenario(
                scenario_id="sc_sql_injection",
                name="حقن SQL",
                description="محاولة حقن استعلامات SQL عبر مدخلات المستخدم",
                category="injection",
                severity="critical",
                attack_vector="web_application",
                expected_detection=True,
                control_types=["waf", "ids_ips"],
                steps=[
                    "إرسال استعلام SQL عبر حقل الإدخال",
                    "مراقبة استجابة التطبيق",
                    "فحص السجلات لاكتشاف الكشف",
                ],
                tags=["owasp_top_10", "injection"],
                reference="https://owasp.org/Top10/A03_2021-Injection/",
            ),
            Scenario(
                scenario_id="sc_xss",
                name="Cross-Site Scripting",
                description="حقن JavaScript في صفحات الويب",
                category="injection",
                severity="high",
                attack_vector="web_application",
                expected_detection=True,
                control_types=["waf", "edr"],
                steps=[
                    "حقن سكريبت في حقل الإدخال",
                    "التحقق من التنفيذ",
                    "فحص كشف المتصفح/الضابط",
                ],
                tags=["owasp_top_10", "xss"],
            ),
            Scenario(
                scenario_id="sc_brute_force",
                name="هجوم القوة الغاشمة",
                description="محاولة تخمين كلمات المرور بشكل متكرر",
                category="authentication",
                severity="high",
                attack_vector="network",
                expected_detection=True,
                control_types=["ids_ips", "siem"],
                steps=[
                    "إرسال محاولات دخول متعددة",
                    "مراقبة قفل الحساب",
                    "فحص التنبيهات",
                ],
                tags=["authentication", "brute_force"],
            ),
            Scenario(
                scenario_id="sc_privilege_escalation",
                name="ترقي الصلاحيات",
                description="محاولة الحصول على صلاحيات أعلى",
                category="authorization",
                severity="critical",
                attack_vector="local",
                expected_detection=True,
                control_types=["edr", "siem"],
                steps=[
                    "استغلال ثغرة ترقي صلاحيات",
                    "التحقق من تغير المستوى",
                    "فحص كشف EDR",
                ],
                tags=["privilege_escalation"],
            ),
            Scenario(
                scenario_id="sc_data_exfiltration",
                name="تسريب البيانات",
                description="محاولة نقل بيانات خارج الشبكة",
                category="data_loss",
                severity="critical",
                attack_vector="network",
                expected_detection=True,
                control_types=["dlp", "ids_ips", "firewall"],
                steps=[
                    "إنشاء اتصال خارجي",
                    "نقل بيانات",
                    "مراقبة حركة الشبكة",
                ],
                tags=["data_exfiltration", "dlp"],
            ),
            Scenario(
                scenario_id="sc_lateral_movement",
                name="الحركة الجانبية",
                description="التنقل بين الأنظمة داخل الشبكة",
                category="network",
                severity="high",
                attack_vector="network",
                expected_detection=True,
                control_types=["edr", "ids_ips", "network_segmentation"],
                steps=[
                    "الاتصال بآخر نظام",
                    "نقل أوراق تعريف",
                    "تنفيذ أوامر على النظام الجديد",
                ],
                tags=["lateral_movement"],
            ),
        ]

        for s in defaults:
            self._scenarios[s.scenario_id] = s
            self._by_category.setdefault(s.category, []).append(s.scenario_id)

    async def add_scenario(self, scenario: Scenario) -> None:
        """إضافة سيناريو."""
        self._scenarios[scenario.scenario_id] = scenario
        self._by_category.setdefault(scenario.category, []).append(scenario.scenario_id)

    def get_scenario(self, scenario_id: str) -> Optional[Scenario]:
        return self._scenarios.get(scenario_id)

    def get_by_category(self, category: str) -> List[Scenario]:
        ids = self._by_category.get(category, [])
        return [self._scenarios[sid] for sid in ids if sid in self._scenarios]

    def get_by_severity(self, severity: str) -> List[Scenario]:
        return [s for s in self._scenarios.values() if s.severity == severity]

    def get_by_control_type(self, control_type: str) -> List[Scenario]:
        return [
            s for s in self._scenarios.values()
            if control_type in s.control_types
        ]

    def get_all(self) -> List[Scenario]:
        return list(self._scenarios.values())

    def search(self, query: str) -> List[Scenario]:
        """بحث نصي."""
        query_lower = query.lower()
        return [
            s for s in self._scenarios.values()
            if query_lower in s.name.lower()
            or query_lower in s.description.lower()
            or query_lower in " ".join(s.tags).lower()
        ]

    def summary(self) -> Dict[str, Any]:
        return {
            "total": len(self._scenarios),
            "categories": list(self._by_category.keys()),
        }

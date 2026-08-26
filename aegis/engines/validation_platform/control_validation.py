"""Security Control Validation Engine — محرك قياس فعالية الضوابط.

يقيس فعالية أدوات الحماية: WAF, EDR, IDS, SIEM, Firewall, etc.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.control_validation")


class ControlType(str, Enum):
    WAF = "waf"
    EDR = "edr"
    IDS_IPS = "ids_ips"
    SIEM = "siem"
    FIREWALL = "firewall"
    DLP = "dlp"
    IAM = "iam"
    EMAIL_SECURITY = "email_security"
    NETWORK_SEGMENTATION = "network_segmentation"
    BACKUP = "backup"
    OTHER = "other"


class ControlEffectiveness(str, Enum):
    EFFECTIVE = "effective"           # الضابط يعمل بكفاءة
    PARTIALLY_EFFECTIVE = "partial"   # يعمل بشكل جزئي
    INEFFECTIVE = "ineffective"       # لا يعمل
    NOT_DEPLOYED = "not_deployed"     # غير مُنشر
    UNKNOWN = "unknown"               # غير معروف


class TestVector(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    MALICIOUS_FILE = "malicious_file"
    C2_COMMUNICATION = "c2_communication"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_THEFT = "credential_theft"


@dataclass
class ControlTest:
    """اختبار ضابط أمني."""
    test_id: str
    control_type: ControlType
    control_name: str
    test_vector: TestVector
    target: str
    expected_detection: bool = True
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ControlTestResult:
    """نتيجة اختبار الضابط."""
    test_id: str
    control_type: ControlType
    control_name: str
    test_vector: TestVector
    detected: bool
    detection_time_ms: float = 0.0
    alert_generated: bool = False
    blocked: bool = False
    logged: bool = False
    effectiveness: ControlEffectiveness = ControlEffectiveness.UNKNOWN
    details: str = ""
    tested_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ControlProfile:
    """ملف تعريف ضابط أمني."""
    control_id: str
    control_type: ControlType
    name: str
    version: str = ""
    deployment_date: str = ""
    last_test_date: str = ""
    test_results: List[ControlTestResult] = field(default_factory=list)
    effectiveness_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecurityControlValidationEngine:
    """محرك قياس فعالية الضوابط — يختبر ويقيّم أدوات الحماية."""

    name = "SecurityControlValidationEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._controls: Dict[str, ControlProfile] = {}
        self._results: Dict[str, ControlTestResult] = {}
        self._history: List[Dict[str, Any]] = []

    async def register_control(
        self,
        control_id: str,
        control_type: ControlType,
        name: str,
        version: str = "",
    ) -> ControlProfile:
        """تسجيل ضابط أمني."""
        profile = ControlProfile(
            control_id=control_id,
            control_type=control_type,
            name=name,
            version=version,
        )
        self._controls[control_id] = profile
        logger.info("تم تسجيل الضابط: %s (%s)", name, control_type.value)
        return profile

    async def test_control(
        self,
        control_id: str,
        test_vector: TestVector,
        target: str,
        expected_detection: bool = True,
    ) -> ControlTestResult:
        """اختبار ضابط ب”—inning محدد."""
        profile = self._controls.get(control_id)
        if not profile:
            raise ValueError(f"ضابط غير موجود: {control_id}")

        test_id = f"ct_{control_id}_{test_vector.value}"

        # محاكاة التحقق من الضابط
        result = self._evaluate_control(profile, test_vector, target)

        profile.test_results.append(result)
        profile.last_test_date = datetime.now(timezone.utc).isoformat()
        profile.effectiveness_score = self._calc_effectiveness(profile)

        self._results[test_id] = result
        self._history.append({
            "control_id": control_id,
            "test_vector": test_vector.value,
            "detected": result.detected,
            "effectiveness": result.effectiveness.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        await self.event_bus.publish(
            topic="control.tested",
            payload={
                "control_id": control_id,
                "test_vector": test_vector.value,
                "detected": result.detected,
                "effectiveness": result.effectiveness.value,
            },
            source=self.name,
        )
        return result

    async def test_all_controls(
        self, test_vector: TestVector, target: str
    ) -> List[ControlTestResult]:
        """اختبار كل الضوابط ضد ن乂 محدد."""
        results = []
        for control_id in self._controls:
            result = await self.test_control(
                control_id, test_vector, target
            )
            results.append(result)
        return results

    async def assess_coverage(
        self, test_vectors: List[TestVector]
    ) -> Dict[str, Any]:
        """تقييم تغطية الضوابط."""
        coverage: Dict[str, Dict[str, Any]] = {}
        for tv in test_vectors:
            detected = 0
            total = len(self._controls)
            for profile in self._controls.values():
                tv_results = [
                    r for r in profile.test_results
                    if r.test_vector == tv and r.detected
                ]
                if tv_results:
                    detected += 1
            coverage[tv.value] = {
                "detected_by": detected,
                "total_controls": total,
                "coverage_rate": detected / max(total, 1),
            }
        return coverage

    def get_control(self, control_id: str) -> Optional[ControlProfile]:
        """استرجاع ملف ضابط."""
        return self._controls.get(control_id)

    def get_ineffective_controls(self) -> List[ControlProfile]:
        """استرجاع الضوابط غير الفعّالة."""
        return [
            p for p in self._controls.values()
            if p.effectiveness_score < 0.5
        ]

    def summary(self) -> Dict[str, Any]:
        """ملخص الضوابط."""
        total_controls = len(self._controls)
        avg_effectiveness = (
            sum(p.effectiveness_score for p in self._controls.values())
            / max(total_controls, 1)
        )
        by_type: Dict[str, int] = {}
        for p in self._controls.values():
            by_type[p.control_type.value] = by_type.get(p.control_type.value, 0) + 1
        return {
            "total_controls": total_controls,
            "by_type": by_type,
            "avg_effectiveness": round(avg_effectiveness, 2),
            "ineffective_count": len(self.get_ineffective_controls()),
        }

    def _evaluate_control(
        self,
        profile: ControlProfile,
        test_vector: TestVector,
        target: str,
    ) -> ControlTestResult:
        """تقييم ضابط — منطق افتراضي."""
        # في بيئة حقيقية: يتفاعل مع الضابط فعلياً
        # هنا: نmwazi بناءً على نوع الضابط
        effectiveness_map = {
            ControlType.WAF: {
                TestVector.SQL_INJECTION: True,
                TestVector.XSS: True,
                TestVector.PATH_TRAVERSAL: True,
            },
            ControlType.EDR: {
                TestVector.MALICIOUS_FILE: True,
                TestVector.PRIVILEGE_ESCALATION: True,
                TestVector.LATERAL_MOVEMENT: True,
            },
            ControlType.IDS_IPS: {
                TestVector.BRUTE_FORCE: True,
                TestVector.C2_COMMUNICATION: True,
                TestVector.DATA_EXFILTRATION: True,
            },
        }

        type_effects = effectiveness_map.get(profile.control_type, {})
        detected = type_effects.get(test_vector, False)

        effectiveness = (
            ControlEffectiveness.EFFECTIVE if detected
            else ControlEffectiveness.INEFFECTIVE
        )

        return ControlTestResult(
            test_id=f"ct_{profile.control_id}_{test_vector.value}",
            control_type=profile.control_type,
            control_name=profile.name,
            test_vector=test_vector,
            detected=detected,
            alert_generated=detected,
            blocked=detected and profile.control_type in (
                ControlType.WAF, ControlType.FIREWALL
            ),
            logged=detected,
            effectiveness=effectiveness,
            details=f"الضابط {profile.name}: {'اكتشف' if detected else 'لم يكتشف'} {test_vector.value}",
            tested_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _calc_effectiveness(profile: ControlProfile) -> float:
        """حساب درجة الفعالية."""
        if not profile.test_results:
            return 0.0
        detected = sum(1 for r in profile.test_results if r.detected)
        return detected / len(profile.test_results)

"""Why Engine — محرك التفسير.

يولّد شروحاً واضحة ومبسّطة لكل قرار أمني:
لماذا هذه الثغرة خطيرة؟ كيف تم اكتشافها؟ ما الأدلة الداعمة؟
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory
from aegis.models.finding import Finding, Severity

logger = logging.getLogger("aegis.inference.why")

CATEGORY_LABELS = {
    EvidenceCategory.INJECTION: "حقن",
    EvidenceCategory.AUTHENTICATION: "مصادقة",
    EvidenceCategory.AUTHORIZATION: "تفويض",
    EvidenceCategory.CRYPTOGRAPHY: "تشفير",
    EvidenceCategory.BUSINESS_LOGIC: "منطق الأعمال",
    EvidenceCategory.PRIVILEGE: "صلاحيات",
    EvidenceCategory.SECRETS: "أسرار",
    EvidenceCategory.CONFIGURATION: "إعدادات",
    EvidenceCategory.DEPENDENCY: "تبعيات",
    EvidenceCategory.INFORMATION_DISCLOSURE: "تسريب معلومات",
    EvidenceCategory.UNKNOWN: "غير محدد",
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "حرج",
    Severity.HIGH: "عالي",
    Severity.MEDIUM: "متوسط",
    Severity.LOW: "منخفض",
    Severity.INFO: "معلومة",
}


class WhyEngine:
    """محرك التفسير — يشرح كل قرار أمني بطريقة واضحة."""

    name = "WhyEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus

    async def explain_finding(
        self,
        finding: Finding,
        evidences: List[Evidence],
        risk_assessment: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """توليد شرح كامل لثغرة."""
        sev_exp = self._explain_severity(finding.severity)
        cat_label = CATEGORY_LABELS.get(getattr(finding, 'category', None), "غير محدد")
        cat_exp = self._explain_category(cat_label, finding)
        ev_exp = self._explain_evidence(evidences)
        risk_exp = self._explain_risk(risk_assessment) if risk_assessment else "لم يتم تقييم المخاطرة بعد"
        recommendation = self._generate_recommendation(finding, evidences)
        full = self._build_full_explanation(
            finding, sev_exp, cat_exp, ev_exp, risk_exp, recommendation
        )

        result = {
            "finding_id": finding.id,
            "title": finding.title,
            "severity_explanation": sev_exp,
            "category_explanation": cat_exp,
            "evidence_summary": ev_exp,
            "risk_explanation": risk_exp,
            "recommendation": recommendation,
            "full_explanation": full,
        }

        await self.event_bus.publish(
            topic="why.explained",
            payload={"finding_id": finding.id, "explanation": full[:500]},
            source=self.name,
        )
        logger.info("شرح %s: %s", finding.id, full[:100])
        return result

    async def explain_risk_level(
        self,
        assessed_findings: List[Dict[str, Any]],
    ) -> str:
        """توليد شرح لمستوى المخاطرة الكلي."""
        critical = sum(1 for f in assessed_findings if f.get("risk_level") == "critical")
        high = sum(1 for f in assessed_findings if f.get("risk_level") == "high")
        total = len(assessed_findings)
        avg_score = (
            sum(f.get("risk_score", 0) for f in assessed_findings) / total
            if total else 0
        )

        if critical > 0:
            return (
                f"النظام في حالة خطر حرج: {critical} ثغرات حرجة، "
                f"{high} عالية الخطورة. متوسط درجة المخاطرة: {avg_score:.1f}/100. "
                f"يجب التدخل فوراً."
            )
        if high > 0:
            return (
                f"يوجد {high} ثغرات عالية الخطورة. "
                f"متوسط درجة المخاطرة: {avg_score:.1f}/100. "
                f"يُنصح بإصلاحها في أقرب وقت."
            )
        if total == 0:
            return "لم يتم اكتشاف ثغرات. يبدو أن النظام آمن نسبياً."
        return (
            f"تم اكتشاف {total} ثغرات بدرجة مخاطرة متوسطة/منخفضة. "
            f"متوسط الدرجة: {avg_score:.1f}/100. "
            f"يُنصح بمراجعة الأفضل."
        )

    def _explain_severity(self, severity: Severity) -> str:
        """شرح الخطورة."""
        label = SEVERITY_LABELS.get(severity, "غير معروف")
        explanations = {
            Severity.CRITICAL: (
                f"هذه ثغرة {label} الخطورة — يمكن استغلالها للحصول على وصول كامل "
                f"للنظام أو سرقة بيانات حساسة. تتطلب تدخلاً فورياً."
            ),
            Severity.HIGH: (
                f"هذه ثغرة {label} الخطورة — يمكن أن تسبب أضراراً كبيرة "
                f"لكنها تتطلب شروطاً معينة للاستغلال."
            ),
            Severity.MEDIUM: (
                f"هذه ثغرة {label} الخطورة — قد تسمح بجمع معلومات "
                f"أو تعقيد الهجوم ولكن لا تسبب أضراراً مباشرة."
            ),
            Severity.LOW: (
                f"هذه ثغرة {label} الخطورة — مشكلة معمارية أو إعدادات "
                f"لا تشكل تهديداً مباشراً لكن تُحسّن الأمان."
            ),
            Severity.INFO: (
                f"هذه معلومة أمنية {label} — ليست ثغرة فعلية لكنها "
                f"مفيدة للفهم العام."
            ),
        }
        return explanations.get(severity, f"خطورة {label}")

    def _explain_category(self, cat_label: str, finding: Finding) -> str:
        """شرح التصنيف."""
        return (
            f"الثغرة تندرج تحت تصنيف '{cat_label}' — "
            f"تتعلق بـ {self._category_detail(cat_label)}."
        )

    _category_detail_map: dict = {
        "حقن": "حقن كود خبيث في استعلامات أو أوامر",
        "مصادقة": "نظام تسجيل الدخول أو التحقق من الهوية",
        "تفويض": "صلاحيات الوصول والتحكم في الأذونات",
        "تشفير": "خوارزميات التشفير وحماية البيانات",
        "أسرار": "كلمات المرور والمفاتيح السرية المكشوفة",
        "إعدادات": "تكوين النظام والبرامج",
        "تبعيات": "المكتبات والبرامج الخارجية المستخدمة",
        "صلاحيات": "تصعيد الصلاحيات والتحكم بالوصول",
        "منطق الأعمال": "المنطق الحاكم في التطبيق",
        "تسريب معلومات": "معلومات حساسة مكشوفة",
    }

    def _category_detail(self, cat_label: str) -> str:
        """تفاصيل التصنيف."""
        return self._category_detail_map.get(cat_label, "جانب أمني عام")

    def _explain_evidence(self, evidences: List[Evidence]) -> str:
        """شرح الأدلة."""
        if not evidences:
            return "لا توجد أدلة داعمة — قد يكون الاكتشاف على أساس غير كافٍ."

        sources = set(e.source_tool for e in evidences)
        categories = set(e.category.value for e in evidences)

        return (
            f"يوجد {len(evidences)} أدلة من {len(sources)} مصدر مستقل: "
            f"{', '.join(sources)}. "
            f"التصنيفات المكتشفة: {', '.join(categories)}."
        )

    def _explain_risk(self, risk: Dict[str, Any]) -> str:
        """شرح المخاطرة."""
        level = risk.get("risk_level", "unknown")
        score = risk.get("risk_score", 0)
        sev = risk.get("severity", "unknown")
        conf = risk.get("confidence", 0)

        level_ar = {
            "critical": "حرج", "high": "عالي",
            "medium": "متوسط", "low": "منخفض", "info": "معلومة",
        }.get(level, level)

        return (
            f"درجة المخاطرة: {score}/100 ({level_ar}). "
            f"الخطورة: {sev}، الثقة: {conf:.0%}."
        )

    def _generate_recommendation(
        self, finding: Finding, evidences: List[Evidence]
    ) -> str:
        """توليد توصية مرتبطة بالخطورة والتصنيف والأدلة."""
        sev = finding.severity
        cat_label = CATEGORY_LABELS.get(getattr(finding, "category", None), "غير محدد")
        category_actions = {
            "حقن": "راجع الاستعلامات والمدخلات، وطبّق parameterization وoutput encoding.",
            "مصادقة": "شدّد التحقق من الهوية، إدارة الجلسات، وسياسات كلمات المرور.",
            "تفويض": "راجع authorization boundaries وتحقق من صلاحيات الكائنات على الخادم.",
            "تشفير": "استبدل الخوارزميات أو الإعدادات الضعيفة بمعايير تشفير مدعومة حالياً.",
            "أسرار": "دوّر السر المكشوف فوراً وأزله من الشفرة والتاريخ وسجل الوصول.",
            "إعدادات": "صحّح الإعدادات غير الآمنة وفعّل الإعداد الآمن الافتراضي.",
            "تبعيات": "حدّث التبعية إلى إصدار مدعوم وثبّت الإصدار مع provenance موثوق.",
            "صلاحيات": "خفّض الامتيازات وتحقق من مسارات privilege escalation.",
            "منطق الأعمال": "راجع مسار العمل والقيود وطبّق تحققاً خادمياً على الحالات الحساسة.",
            "تسريب معلومات": "قلّل البيانات المكشوفة وأضف redaction وaccess controls مناسبة.",
        }
        action = category_actions.get(cat_label, "راجع السبب الجذري للعثور وطبّق الضبط الوقائي المناسب.")

        if sev == Severity.CRITICAL:
            prefix = "توصية فورية: إصلاح الثغرة الآن، مع عزل النظام المتأثر عند الحاجة."
        elif sev == Severity.HIGH:
            prefix = "توصية عاجلة: إصلاح الثغرة في أقرب دورة صيانة مع تحقق لاحق."
        elif sev == Severity.MEDIUM:
            prefix = "توصية: جدولة الإصلاح وإجراء تحقق موجّه."
        else:
            prefix = "توصية: معالجة المشكلة ضمن دورة التحسين القادمة."

        evidence_note = (
            f" الأدلة المتاحة: {len(evidences)} من {len(set(e.source_tool for e in evidences))} مصادر."
            if evidences else " لا توجد أدلة داعمة كافية؛ يجب جمع دليل أقوى قبل إغلاق الحالة."
        )
        return f"{prefix} {action}{evidence_note}"

    def _build_full_explanation(
        self,
        finding: Finding,
        sev_exp: str,
        cat_exp: str,
        ev_exp: str,
        risk_exp: str,
        recommendation: str,
    ) -> str:
        """بناء الشرح الكامل."""
        parts = [
            f"الثغرة: {finding.title}",
            "",
            f"الخطورة: {sev_exp}",
            f"التصنيف: {cat_exp}",
            f"الأدلة: {ev_exp}",
            f"المخاطرة: {risk_exp}",
            "",
            f"التوصية: {recommendation}",
        ]
        return "\n".join(parts)

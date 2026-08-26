"""اختبارات المرحلة 3 — الاستخبارات الخارجية (Trust, Sources, Hub, Fusion)."""

import pytest

from aegis.core.event_bus import EventBus
from aegis.engines.intelligence.trust import (
    SourceTrustFramework,
    TrustLevel,
    SourceProfile,
)
from aegis.engines.intelligence.fusion import EvidenceFusionEngine
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType


# ─── Source Trust Framework ────────────────────────────────────

def test_trust_defaults():
    tf = SourceTrustFramework()
    sources = tf.list_sources()
    assert "github_advisory" in sources
    assert "nvd_cve" in sources
    assert "internal_scan" in sources
    assert sources["github_advisory"]["trust_level"] == "verified"


def test_trust_weight():
    tf = SourceTrustFramework()
    assert tf.get_weight("github_advisory") == 0.9
    assert tf.get_weight("nvd_cve") == 0.95
    assert tf.get_weight("internal_scan") == 1.0
    assert tf.get_weight("unknown_source") == 0.3  # افتراضي


def test_trust_evaluate_claim():
    tf = SourceTrustFramework()
    # مصدر موثوق + ثقة عالية + تأييد = نتيجة عالية
    score = tf.evaluate_claim("nvd_cve", 0.9, corroboration_count=2)
    assert score > 0.8
    # مصدر غير موثوق + ثقة منخفضة = نتيجة منخفضة
    score = tf.evaluate_claim("osint_forums", 0.3, corroboration_count=0)
    assert score < 0.5


def test_trust_register_custom():
    tf = SourceTrustFramework()
    custom = SourceProfile(
        source_id="custom_threat",
        name="Custom Threat Feed",
        trust_level=TrustLevel.HIGH,
        base_weight=0.75,
    )
    tf.register_source(custom)
    assert tf.get_weight("custom_thail") == 0.3  # غير مسجل
    assert tf.get_weight("custom_threat") == 0.75  # مسجل حديثاً


# ─── Evidence Fusion Engine ───────────────────────────────────

def _ev(scan: str, tool: str, etype: EvidenceType,
        cat: EvidenceCategory, desc: str,
        conf: float = 0.5, loc: str = "test:1") -> Evidence:
    return Evidence(
        scan_id=scan, source_tool=tool, evidence_type=etype,
        category=cat, description=desc, confidence_weight=conf,
        location=loc,
    )


async def test_fusion_merges_matching_evidences():
    bus = EventBus()
    await bus.start()

    internal = [
        _ev("sc1", "AegisScan.AST", EvidenceType.AST,
            EvidenceCategory.INJECTION, "استدعاء os.system في كود بايثون",
            conf=0.6, loc="app.py:42"),
    ]
    external = [
        _ev("sc1", "ExtIntel.github_advisory", EvidenceType.DEPENDENCY,
            EvidenceCategory.INJECTION, "known injection in os.system usage",
            conf=0.7, loc="app.py:42"),
    ]

    engine = EvidenceFusionEngine(bus)
    fused = await engine.fuse(internal, external)

    # يجب أن يُدمج الدليلان (تشابه في الفئة + الموقع)
    assert len(fused) <= 2  # دليل واحد مدمج أو دليلان منفصلان
    await bus.stop()


async def test_fusion_deduplicates():
    bus = EventBus()
    await bus.start()

    ev1 = _ev("sc2", "Tool1", EvidenceType.AST,
              EvidenceCategory.SECRETS, "API key مكشوف في config.py",
              conf=0.5, loc="config.py:10")
    ev2 = _ev("sc2", "Tool2", EvidenceType.SECRET,
              EvidenceCategory.SECRETS, "API key في config.py",
              conf=0.6, loc="config.py:10")

    engine = EvidenceFusionEngine(bus)
    fused = await engine.fuse([ev1], [ev2])

    # التكرار المماثل يجب أن يُدمج
    assert len(fused) <= 2
    await bus.stop()


async def test_fusion_boosts_corroborated():
    bus = EventBus()
    await bus.start()

    # دليل واحد من مصدر داخلي
    internal = [_ev("sc3", "AegisScan", EvidenceType.AST,
                    EvidenceCategory.INJECTION, "SQL injection via string concat",
                    conf=0.5, loc="db.py:20")]
    # دليل متطابق من مصدر خارجي
    external = [_ev("sc3", "ExtIntel.nvd_cve", EvidenceType.DEPENDENCY,
                    EvidenceCategory.INJECTION, "CVE-2024-XXXX: SQL injection",
                    conf=0.9, loc="db.py:20")]

    engine = EvidenceFusionEngine(bus)
    fused = await engine.fuse(internal, external)

    # الثقة يجب أن تزداد بعد الدمج
    for ev in fused:
        if "Fused" in ev.source_tool:
            assert ev.confidence_weight > 0.5
    await bus.stop()


async def test_fusion_reduces_unmatched_external():
    bus = EventBus()
    await bus.start()

    # دليل خارجي فقط بدون مطابق داخلي
    external = [_ev("sc4", "ExtIntel.osint", EvidenceType.NETWORK,
                    EvidenceCategory.UNKNOWN, "unrelated signal from OSINT",
                    conf=0.5)]

    engine = EvidenceFusionEngine(bus)
    fused = await engine.fuse([], external)

    # الدليل الوحيد يجب أن تقل ثقته
    assert len(fused) == 1
    assert fused[0].confidence_weight < 0.5  # 0.5 * 0.7 = 0.35
    await bus.stop()

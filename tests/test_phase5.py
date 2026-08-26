"""اختبارات المرحلة 5 — محركات الاستدلال (KG, Confidence, Risk, Why)."""

import pytest
from aegis.core.event_bus import EventBus
from aegis.engines.inference.knowledge_graph import KnowledgeGraphEngine
from aegis.engines.inference.confidence import ConfidenceScoringEngine
from aegis.engines.inference.risk import RiskAssessmentEngine
from aegis.engines.inference.why_engine import WhyEngine
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType
from aegis.models.finding import Finding, Severity


# ─── fixtures ──────────────────────────────────────────────

@pytest.fixture
async def bus():
    b = EventBus()
    await b.start()
    yield b
    await b.stop()


def _ev(scan="sc1", tool="Tool1", cat=EvidenceCategory.INJECTION,
        conf=0.6, desc="SQL injection in query", loc="db.py:10"):
    return Evidence(
        scan_id=scan, source_tool=tool, evidence_type=EvidenceType.AST,
        category=cat, description=desc, confidence_weight=conf, location=loc,
    )


def _finding(title="SQL Injection", sev=Severity.HIGH, evidence_ids=None):
    return Finding(
        scan_id="sc1", title=title, severity=sev, confidence_score=0.7,
        description="Test finding for phase 5 inference testing",
        evidence_ids=evidence_ids or ["ev_1", "ev_2"],
    )


# ─── Knowledge Graph ──────────────────────────────────────

async def test_kg_add_evidence_and_finding(bus):
    kg = KnowledgeGraphEngine(bus)
    ev1 = _ev(tool="Tool1")
    ev2 = _ev(tool="Tool2")
    await kg.add_evidence(ev1)
    await kg.add_evidence(ev2)

    f = _finding(evidence_ids=[ev1.id, ev2.id])
    await kg.add_finding(f)

    stats = kg.summary()
    assert stats["nodes"] >= 5  # scan + 2 evidence + category + finding
    assert stats["edges"] >= 4


async def test_kg_get_evidence_for_finding(bus):
    kg = KnowledgeGraphEngine(bus)
    ev1 = _ev(tool="Tool1")
    ev2 = _ev(tool="Tool2")
    await kg.add_evidence(ev1)
    await kg.add_evidence(ev2)

    f = _finding(evidence_ids=[ev1.id, ev2.id])
    await kg.add_finding(f)

    evs = kg.get_evidence_for_finding(f.id)
    assert len(evs) == 2


async def test_kg_asset_finding_link(bus):
    kg = KnowledgeGraphEngine(bus)
    await kg.add_asset("srv1", "server", "web-server-01")
    f = _finding()
    await kg.add_finding(f)
    await kg.link_asset_finding("srv1", f.id)

    findings = kg.get_findings_for_asset("srv1")
    assert len(findings) == 1


async def test_kg_high_confidence_findings(bus):
    kg = KnowledgeGraphEngine(bus)
    f1 = _finding(title="High Vuln", sev=Severity.CRITICAL)
    f1.confidence_score = 0.9
    await kg.add_finding(f1)

    f2 = _finding(title="Low Vuln", sev=Severity.LOW)
    f2.confidence_score = 0.3
    await kg.add_finding(f2)

    high = kg.get_high_confidence_findings(threshold=0.7)
    assert len(high) == 1
    assert high[0]["title"] == "High Vuln"


# ─── Confidence Scoring ───────────────────────────────────

async def test_confidence_base_score(bus):
    cs = ConfidenceScoringEngine(bus)
    f = _finding()
    evs = [_ev(conf=0.5)]
    score = await cs.score_finding(f, evs)
    assert 0.3 <= score <= 0.6  # base 0.45 ± small adjustments


async def test_confidence_boosted_by_multiple_sources(bus):
    cs = ConfidenceScoringEngine(bus)
    f = _finding()
    evs = [
        _ev(tool="Tool1", conf=0.7),
        _ev(tool="Tool2", conf=0.7),
        _ev(tool="Tool3", conf=0.7),
    ]
    score = await cs.score_finding(f, evs)
    # مصادر متعددة = زيادة
    assert score > 0.5


async def test_confidence_with_behavioral_evidence(bus):
    cs = ConfidenceScoringEngine(bus)
    f = _finding()
    evs = [
        _ev(conf=0.6),
        Evidence(
            scan_id="sc1", source_tool="BTE",
            evidence_type=EvidenceType.BEHAVIORAL,
            category=EvidenceCategory.INJECTION,
            description="Anomalous execution pattern",
            confidence_weight=0.8,
        ),
    ]
    score = await cs.score_finding(f, evs)
    assert score > 0.5


# ─── Risk Assessment ──────────────────────────────────────

async def test_risk_critical_high_confidence(bus):
    ra = RiskAssessmentEngine(bus)
    f = _finding(sev=Severity.CRITICAL)
    result = await ra.assess_finding(f, confidence=0.9)
    assert result["risk_score"] >= 75
    assert result["risk_level"] == "critical"


async def test_risk_low_low_confidence(bus):
    ra = RiskAssessmentEngine(bus)
    f = _finding(sev=Severity.LOW)
    result = await ra.assess_finding(f, confidence=0.3)
    assert result["risk_score"] < 15
    assert result["risk_level"] in ("low", "info")


async def test_risk_summary(bus):
    ra = RiskAssessmentEngine(bus)
    assessed = [
        {"risk_level": "critical", "risk_score": 90},
        {"risk_level": "high", "risk_score": 60},
        {"risk_level": "low", "risk_score": 10},
    ]
    summary = ra.get_risk_summary(assessed)
    assert summary["total"] == 3
    assert summary["critical"] == 1
    assert summary["average_score"] == 53.3


# ─── Why Engine ────────────────────────────────────────────

async def test_why_explain_finding(bus):
    wy = WhyEngine(bus)
    f = _finding(sev=Severity.HIGH)
    evs = [_ev(tool="AegisScan"), _ev(tool="BTE")]
    explanation = await wy.explain_finding(f, evs, risk_assessment={
        "risk_level": "high", "risk_score": 60,
        "severity": "high", "confidence": 0.8,
    })
    assert "full_explanation" in explanation
    assert "SQL Injection" in explanation["title"]
    assert len(explanation["full_explanation"]) > 50


async def test_why_explain_risk_level(bus):
    wy = WhyEngine(bus)
    assessed = [
        {"risk_level": "critical", "risk_score": 90},
        {"risk_level": "high", "risk_score": 60},
    ]
    explanation = await wy.explain_risk_level(assessed)
    assert "حرج" in explanation
    assert "ثغرات حرجة" in explanation


async def test_why_no_evidence_warning(bus):
    wy = WhyEngine(bus)
    f = _finding()
    explanation = await wy.explain_finding(f, [])
    assert "لا توجد أدلة" in explanation["evidence_summary"]

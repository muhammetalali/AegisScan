"""اختبارات الطبقة 0 + التكامل (EventBus, Models, DataManager, Audit, Correlation)."""

import asyncio

import pytest

from aegis.core.audit_logger import AuditLogger
from aegis.core.crypto import load_or_create_key
from aegis.core.data_manager import DataManager
from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType
from aegis.models.finding import Finding, Severity


# ─── EventBus ─────────────────────────────────────────────────

async def test_bus_roundtrip_and_drain():
    bus = EventBus()
    received = []

    async def handler(event):
        received.append(event)

    bus.subscribe("evidence.new", handler)
    await bus.start()
    await bus.publish("evidence.new", {"k": 1})
    # الإصلاح #4: stop يفرّغ الطابور أولاً ولا يعلق
    await bus.stop(drain=True)

    assert len(received) == 1
    assert received[0].payload == {"k": 1}


async def test_bus_error_isolation():
    bus = EventBus()
    ok = []

    async def bad(event):
        raise RuntimeError("boom")

    async def good(event):
        ok.append(True)

    bus.subscribe("t", bad)
    bus.subscribe("t", good)
    await bus.start()
    await bus.publish("t", {})
    await bus.stop(drain=True)

    assert ok == [True]
    assert bus.stats["errors"] >= 1


# ─── Models ───────────────────────────────────────────────────

def test_evidence_auto_hash():
    ev = Evidence(
        scan_id="s1", source_tool="X", evidence_type=EvidenceType.AST,
        category=EvidenceCategory.INJECTION,
        description="استدعاء خطر مع دمج نصوص", location="a.py:10",
    )
    assert ev.content_hash and len(ev.content_hash) == 16


def test_finding_requires_two_evidences():
    with pytest.raises(Exception):
        Finding(
            scan_id="s1", title="ثغرة بدليل واحد فقط",
            severity=Severity.HIGH, confidence_score=0.8,
            description="وصف كافٍ للتحقق من القاعدة الصارمة",
            evidence_ids=["ev_1"],
        )


def test_finding_accepts_two():
    f = Finding(
        scan_id="s1", title="ثغرة بدليلين مستقلين",
        severity=Severity.CRITICAL, confidence_score=0.9,
        description="وصف كافٍ للتحقق من قبول الدليلين",
        evidence_ids=["ev_1", "ev_2"],
    )
    assert f.evidence_count == 2


# ─── Crypto / Audit (الإصلاح الحرج #1) ────────────────────────

def test_key_persistent(tmp_path):
    kf = tmp_path / "k.key"
    k1 = load_or_create_key(str(kf))
    k2 = load_or_create_key(str(kf))
    assert k1 == k2  # نفس المفتاح عبر التشغيلات — السجلات تبقى مقروءة


def test_audit_readable_across_instances(tmp_path):
    log_file = tmp_path / "audit.log"
    key = load_or_create_key(str(tmp_path / "audit.key"))

    a1 = AuditLogger(str(log_file), key=key)
    a1.log("u1", "scan.started", "target-x", "in_progress")

    # نسخة جديدة بنفس المفتاح (محاكاة إعادة تشغيل) يجب أن تقرأ السجل
    a2 = AuditLogger(str(log_file), key=key)
    logs = a2.read_logs()
    assert len(logs) == 1
    assert logs[0]["action"] == "scan.started"


# ─── DataManager ──────────────────────────────────────────────

def _ev(scan: str, tool: str, etype: EvidenceType,
        cat: EvidenceCategory = EvidenceCategory.INJECTION) -> dict:
    e = Evidence(
        scan_id=scan, source_tool=tool, evidence_type=etype, category=cat,
        description=f"دليل اختباري من {tool} طويل بما يكفي",
    )
    return e.to_dict()


def test_data_manager_roundtrip():
    dm = DataManager(":memory:")
    e1 = _ev("sc1", "AST-Tool", EvidenceType.AST)
    e2 = _ev("sc1", "BTE-Tool", EvidenceType.BEHAVIORAL)
    dm.save_evidence(e1)
    dm.save_evidence(e2)

    got = dm.get_evidences_by_scan("sc1")
    assert len(got) == 2

    f = Finding(
        scan_id="sc1", title="ثغرة حقن مؤكدة بالاختبار",
        severity=Severity.CRITICAL, confidence_score=0.75,
        description="ثغرة مبنية من دليلين لاختبار التخزين",
        evidence_ids=[e1["id"], e2["id"]],
    )
    dm.save_finding(f.to_dict())
    rows = dm.get_findings_by_scan("sc1")
    assert len(rows) == 1
    assert rows[0]["severity"] == "critical"
    dm.close()


def test_data_manager_encrypted_raw(tmp_path):
    from aegis.core.crypto import load_or_create_key as lk
    key = lk(str(tmp_path / "db.key"))
    dm = DataManager(str(tmp_path / "db.sqlite"), key=key, encrypt_raw_data=True)

    e = _ev("sx", "T", EvidenceType.SECRET)
    e["raw_data"] = "SECRET_VALUE_123"
    dm.save_evidence(e)

    raw_stored = dm.execute_query(
        "SELECT raw_data FROM evidences WHERE id=?", (e["id"],)
    )[0]["raw_data"]
    assert raw_stored.startswith("enc:")          # مشفر على القرص
    back = dm.get_evidences_by_scan("sx")[0]      # شفاف عند القراءة
    assert back["raw_data"] == "SECRET_VALUE_123"
    dm.close()


# ─── Correlation (المعادلة المصححة) ───────────────────────────

async def test_correlation_produces_finding(tmp_path):
    from aegis.engines.operational.correlation import CorrelationEngine

    bus = EventBus()
    findings_events = []

    async def on_finding(event):
        findings_events.append(event.payload)

    bus.subscribe("finding.new", on_finding)

    dm = DataManager(":memory:")
    dm.save_evidence(_ev("sc9", "AegisScan.AST", EvidenceType.AST))
    dm.save_evidence(_ev("sc9", "BTE", EvidenceType.BEHAVIORAL))

    engine = CorrelationEngine(bus, dm, confidence_threshold=0.60)
    await bus.start()
    findings = await engine.correlate_scan("sc9")
    await bus.wait_until_idle()

    # المعادلة: 0.45 + 0.15 + 0.15 = 0.75 >= 0.60 ✓
    assert len(findings) == 1
    assert findings[0].confidence_score == pytest.approx(0.75, abs=0.01)
    assert len(findings_events) == 1
    await bus.stop()
    dm.close()


async def test_correlation_rejects_single_source(tmp_path):
    from aegis.engines.operational.correlation import CorrelationEngine

    bus = EventBus()
    dm = DataManager(":memory:")
    dm.save_evidence(_ev("sc10", "OnlyTool", EvidenceType.AST))

    engine = CorrelationEngine(bus, dm)
    findings = await engine.correlate_scan("sc10")
    assert findings == []   # مصدر واحد → رفض (المادة 1)
    dm.close()

"""اختبارات الطبقات القابلة للتدقيق التي أضيفت في المراجعة."""

import pytest

from aegis.core.feedback import FeedbackWeights
from aegis.core.immutable_audit import ImmutableAuditChain
from aegis.core.scan_state_machine import ScanPhase, ScanStateMachine
from aegis.engines.inference.contextual_enrichment import ContextualEnricher
from aegis.engines.inference.smart_aggregator import SmartAggregator
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType
from aegis.models.finding import Finding


def _evidence(tool: str, confidence: float = 0.7) -> Evidence:
    return Evidence(
        scan_id='scan_test',
        source_tool=tool,
        evidence_type=EvidenceType.AST,
        category=EvidenceCategory.INJECTION,
        description='دليل اختبار واضح على مسار إدخال غير آمن',
        confidence_weight=confidence,
    )


def test_provenance_is_serialized_on_finding() -> None:
    finding = Finding(
        scan_id='scan_test',
        title='ثغرة حقن في واجهة الإدخال',
        confidence_score=0.8,
        description='وصف اختبار طويل بما يكفي لنموذج الثغرة الموحد',
        evidence_ids=['ev_a', 'ev_b'],
    )
    assert finding.decision_trail == []
    assert 'decision_trail' in finding.to_dict()


def test_smart_aggregator_dampens_correlated_sources() -> None:
    result = SmartAggregator({'semgrep': 'static-analysis', 'bandit': 'static-analysis'}).aggregate([
        _evidence('semgrep'),
        _evidence('bandit'),
        _evidence('nmap', 0.6),
    ])
    assert result.confidence == pytest.approx(0.88, abs=0.01)
    assert result.correlated_groups['static-analysis'] == ['semgrep', 'bandit']


def test_scan_state_machine_pause_resume_and_restart() -> None:
    machine = ScanStateMachine()
    machine.transition(ScanPhase.PREPARING)
    machine.transition(ScanPhase.SCANNING)
    machine.pause()
    machine.resume()
    machine.transition(ScanPhase.CORRELATING)
    machine.transition(ScanPhase.TESTING)
    machine.transition(ScanPhase.REPORTING)
    machine.transition(ScanPhase.DONE)
    machine.restart_from(ScanPhase.TESTING)
    assert machine.phase == ScanPhase.TESTING
    assert len(machine.history) == 9


def test_context_priority_and_feedback_weight() -> None:
    finding = Finding(
        scan_id='scan_test',
        title='ثغرة عالية الأهمية في أصل حرج',
        confidence_score=0.9,
        description='وصف اختبار طويل بما يكفي لنموذج الثغرة الموحد',
        evidence_ids=['ev_a', 'ev_b'],
    )
    enriched = ContextualEnricher().enrich(finding, {'id': 'asset-1', 'criticality': 1.0})
    assert enriched.priority == 'urgent'
    weights = FeedbackWeights()
    assert weights.record('semgrep', True) > weights.record('bandit', False)


def test_immutable_audit_chain_detects_tampering() -> None:
    chain = ImmutableAuditChain()
    chain.append('scan.started', {'scan_id': 'scan_test'})
    chain.append('finding.confirmed', {'finding_id': 'finding_test'})
    assert chain.verify()
    chain._entries[0]['payload']['scan_id'] = 'tampered'  # noqa: SLF001
    assert not chain.verify()

from __future__ import annotations

import hashlib
import json
from typing import Any

from django_project.vulnerabilities.models import Vulnerability
from enterprise.models import AttackPath, FindingIntelligence, RiskCorrelationSnapshot

ANALYSIS_VERSION = '1.1'
WEIGHTS = {
    'base_risk': 0.40,
    'epss_percent': 0.25,
    'attack_path_risk': 0.15,
    'intelligence_confidence': 0.10,
    'evidence_strength': 0.10,
}
KEV_BOOST = 15.0


def _clamp(value: float) -> float:
    return min(100.0, max(0.0, float(value)))


def _epss_probability(payload: dict[str, Any]) -> float:
    rows = payload.get('data') if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows:
        return 0.0
    try:
        return min(1.0, max(0.0, float((rows[0] or {}).get('epss') or 0.0)))
    except (TypeError, ValueError, AttributeError):
        return 0.0


def _known_exploited(payload: dict[str, Any]) -> bool:
    return bool(payload.get('known_exploited')) if isinstance(payload, dict) else False


def _priority(score: float) -> str:
    if score >= 90:
        return RiskCorrelationSnapshot.Priority.P0_CRITICAL
    if score >= 75:
        return RiskCorrelationSnapshot.Priority.P1_HIGH
    if score >= 55:
        return RiskCorrelationSnapshot.Priority.P2_MEDIUM
    return RiskCorrelationSnapshot.Priority.P3_LOW


def _evidence_signal(finding: Vulnerability) -> dict[str, int]:
    total = 0
    supporting = 0
    contradicting = 0
    neutral = 0

    for evidence in finding.evidence_records.all():
        total += 1
        metadata = evidence.metadata if isinstance(evidence.metadata, dict) else {}

        if evidence.evidence_type == 'validation_output':
            finding_present = metadata.get('finding_present')
            if finding_present is True:
                supporting += 1
            elif finding_present is False:
                contradicting += 1
            else:
                neutral += 1
            continue

        if evidence.evidence_type == 'exploitability_proof':
            try:
                proven_count = int(metadata.get('proven_count') or 0)
            except (TypeError, ValueError):
                proven_count = 0
            if proven_count > 0:
                supporting += 1
            else:
                neutral += 1
            continue

        # Scanner findings and other direct finding evidence continue to support
        # the detection unless a dedicated validation outcome explicitly
        # contradicts it.
        supporting += 1

    return {
        'total': total,
        'supporting': supporting,
        'contradicting': contradicting,
        'neutral': neutral,
    }


def _attack_path_for_finding(finding: Vulnerability) -> AttackPath | None:
    if not finding.asset_id:
        return None
    asset_id = str(finding.asset_id)
    paths = (
        AttackPath.objects
        .filter(project_id=finding.project_id)
        .exclude(status=AttackPath.Status.CLOSED)
        .order_by('-risk_score', '-discovered_at', '-id')
    )
    return next(
        (path for path in paths if asset_id in {str(node) for node in (path.steps or [])}),
        None,
    )


def correlate_finding(
    finding: Vulnerability,
    *,
    actor_id: str,
) -> tuple[RiskCorrelationSnapshot, bool]:
    """Create or reuse one immutable, deterministic finding-priority snapshot.

    This consumes already-persisted finding intelligence. It does not perform
    live provider calls, mutate the scanner risk score, or reinterpret CVSS.
    """

    intel = (
        FindingIntelligence.objects
        .select_related('source_snapshot')
        .filter(vulnerability=finding)
        .first()
    )
    if not intel or not intel.source_snapshot_id:
        raise ValueError('Risk correlation requires persisted finding intelligence lineage')

    source_snapshot = intel.source_snapshot
    if len(source_snapshot.snapshot_sha256 or '') != 64:
        raise ValueError('Risk correlation requires a valid immutable intelligence snapshot SHA256')

    attack_path = _attack_path_for_finding(finding)
    base_risk = _clamp(float(finding.risk_score or 0.0))
    epss = _epss_probability(intel.epss or {})
    epss_percent = _clamp(epss * 100.0)
    confidence = _clamp(float(intel.confidence or 0.0))
    attack_path_risk = _clamp(float(attack_path.risk_score or 0.0)) if attack_path else 0.0
    evidence_signal = _evidence_signal(finding)
    evidence_count = evidence_signal['total']
    supporting_evidence_count = evidence_signal['supporting']
    contradicting_evidence_count = evidence_signal['contradicting']
    neutral_evidence_count = evidence_signal['neutral']
    evidence_strength = _clamp(50.0 + min(10, supporting_evidence_count) * 5.0)
    known_exploited = _known_exploited(intel.cisa_kev or {})

    contributions = {
        'base_risk': round(base_risk * WEIGHTS['base_risk'], 4),
        'epss_percent': round(epss_percent * WEIGHTS['epss_percent'], 4),
        'attack_path_risk': round(attack_path_risk * WEIGHTS['attack_path_risk'], 4),
        'intelligence_confidence': round(confidence * WEIGHTS['intelligence_confidence'], 4),
        'evidence_strength': round(evidence_strength * WEIGHTS['evidence_strength'], 4),
        'cisa_kev_boost': KEV_BOOST if known_exploited else 0.0,
    }
    score = round(_clamp(sum(contributions.values())), 2)

    components = {
        'base_risk': base_risk,
        'epss_probability': round(epss, 8),
        'epss_percent': round(epss_percent, 4),
        'cisa_kev': known_exploited,
        'intelligence_confidence': confidence,
        'intelligence_conflict': bool(intel.conflict),
        'attack_path_risk': attack_path_risk,
        'evidence_strength': evidence_strength,
        'evidence_count': evidence_count,
        'supporting_evidence_count': supporting_evidence_count,
        'contradicting_evidence_count': contradicting_evidence_count,
        'neutral_evidence_count': neutral_evidence_count,
        'weights': WEIGHTS,
        'contributions': contributions,
        'kev_boost': KEV_BOOST,
    }

    lineage = {
        'analysis_version': ANALYSIS_VERSION,
        'project_id': str(finding.project_id),
        'finding_id': str(finding.id),
        'finding_intelligence_id': str(intel.pk),
        'source_snapshot_id': str(source_snapshot.id),
        'source_snapshot_sha256': source_snapshot.snapshot_sha256,
        'attack_path_id': str(attack_path.id) if attack_path else None,
        'attack_path_risk': attack_path_risk,
        'evidence_count': evidence_count,
        'components': components,
        'score': score,
        'priority': _priority(score),
    }
    canonical = json.dumps(
        lineage,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')
    correlation_sha256 = hashlib.sha256(canonical).hexdigest()

    snapshot, created = RiskCorrelationSnapshot.objects.get_or_create(
        correlation_sha256=correlation_sha256,
        defaults={
            'project_id': finding.project_id,
            'vulnerability': finding,
            'finding_intelligence': intel,
            'source_snapshot': source_snapshot,
            'attack_path': attack_path,
            'analysis_version': ANALYSIS_VERSION,
            'score': score,
            'priority': _priority(score),
            'components': components,
            'evidence_count': evidence_count,
            'source_snapshot_sha256': source_snapshot.snapshot_sha256,
            'created_by_id': actor_id,
        },
    )
    return snapshot, created

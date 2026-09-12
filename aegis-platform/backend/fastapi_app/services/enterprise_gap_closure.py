from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from typing import Any

from django.db import transaction
from django.utils import timezone

from enterprise.models import (
    AdaptiveWeightProfile,
    ArtifactIntegrityRecord,
    BlastRadiusSnapshot,
    EvidenceGraphEdge,
    EvidenceGraphNode,
    FindingDecisionProvenance,
    FormalPolicyProof,
    InvestigationCase,
    InvestigationCaseEvent,
    ScanControlCheckpoint,
    TenantProject,
)
from django_project.evidence.models import Evidence
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory


DEFAULT_PRIORITY_WEIGHTS = {
    'severity': 0.20,
    'cvss': 0.15,
    'criticality': 0.18,
    'exploitability': 0.14,
    'business_impact': 0.12,
    'intel': 0.11,
    'evidence': 0.05,
    'validation': 0.05,
}
CRITICALITY = {'low': 20.0, 'medium': 45.0, 'high': 75.0, 'critical': 100.0}
SEVERITY = {'info': 10.0, 'low': 30.0, 'medium': 55.0, 'high': 80.0, 'critical': 100.0}


def _tenant_for_project(project):
    link = TenantProject.objects.select_related('organization').filter(project=project).first()
    if link is None:
        raise ValueError('project is not bound to an enterprise organization')
    return link.organization


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')


@transaction.atomic
def append_finding_decision(
    *,
    vulnerability_id: str,
    actor_id: str,
    decision: str,
    policy_ref: str,
    reason: str,
    evidence_refs: list[str],
    new_status: str | None = None,
    validation_id: str | None = None,
) -> FindingDecisionProvenance:
    if not decision.strip() or not policy_ref.strip() or not reason.strip():
        raise ValueError('decision, policy_ref and reason are required')
    vulnerability = Vulnerability.objects.select_for_update().select_related('project').get(pk=vulnerability_id)
    organization = _tenant_for_project(vulnerability.project)
    ids = sorted(set(str(value) for value in evidence_refs))
    if ids and Evidence.objects.filter(pk__in=ids, finding=vulnerability).count() != len(ids):
        raise ValueError('every evidence reference must exist and belong to the finding')
    if validation_id and not vulnerability.validation_runs.filter(pk=validation_id).exists():
        raise ValueError('validation does not belong to finding')
    old_status = vulnerability.status
    if new_status is not None and new_status not in {value for value, _ in Vulnerability.Status.choices}:
        raise ValueError('invalid finding status')
    last = FindingDecisionProvenance.objects.filter(vulnerability=vulnerability).order_by('-created_at', '-id').first()
    previous_hash = last.entry_hash if last else ''
    record_id = uuid.uuid4()
    created_at = timezone.now()
    payload = {
        'id': str(record_id),
        'organization': str(organization.id),
        'project': str(vulnerability.project_id),
        'vulnerability': str(vulnerability.id),
        'validation': str(validation_id or ''),
        'actor': str(actor_id),
        'decision': decision.strip(),
        'old_status': old_status,
        'new_status': new_status or old_status,
        'policy_ref': policy_ref.strip(),
        'reason': reason.strip(),
        'evidence_refs': ids,
        'previous_hash': previous_hash,
        'created_at': created_at.isoformat(),
    }
    row = FindingDecisionProvenance.objects.create(
        id=record_id,
        organization=organization,
        project=vulnerability.project,
        vulnerability=vulnerability,
        validation_id=validation_id,
        actor_id=actor_id,
        decision=payload['decision'],
        old_status=old_status,
        new_status=payload['new_status'],
        policy_ref=payload['policy_ref'],
        reason=payload['reason'],
        evidence_refs=ids,
        previous_hash=previous_hash,
        entry_hash=hashlib.sha256(_canonical(payload)).hexdigest(),
        created_at=created_at,
    )
    if new_status is not None and new_status != old_status:
        vulnerability.status = new_status
        vulnerability.save(update_fields=['status', 'updated_at'])
        VulnerabilityStatusHistory.objects.create(
            vulnerability=vulnerability,
            old_status=old_status,
            new_status=new_status,
            changed_by_id=actor_id,
            reason=f'{decision}: {reason}',
        )
    return row


def verify_finding_decision_chain(vulnerability_id: str) -> dict[str, Any]:
    rows = list(FindingDecisionProvenance.objects.filter(vulnerability_id=vulnerability_id).order_by('created_at', 'id'))
    previous = ''
    for row in rows:
        if row.previous_hash != previous:
            return {'valid': False, 'entries': len(rows), 'broken_at': str(row.id), 'reason': 'previous_hash'}
        payload = {
            'id': str(row.id), 'organization': str(row.organization_id), 'project': str(row.project_id),
            'vulnerability': str(row.vulnerability_id), 'validation': str(row.validation_id or ''),
            'actor': str(row.actor_id), 'decision': row.decision, 'old_status': row.old_status,
            'new_status': row.new_status, 'policy_ref': row.policy_ref, 'reason': row.reason,
            'evidence_refs': sorted(set(str(value) for value in row.evidence_refs)),
            'previous_hash': row.previous_hash, 'created_at': row.created_at.isoformat(),
        }
        expected = hashlib.sha256(_canonical(payload)).hexdigest()
        if expected != row.entry_hash:
            return {'valid': False, 'entries': len(rows), 'broken_at': str(row.id), 'reason': 'entry_hash'}
        previous = row.entry_hash
    return {'valid': True, 'entries': len(rows), 'head': previous}


def contextual_priority(vulnerability: Vulnerability, weights: dict[str, float] | None = None) -> dict[str, Any]:
    weights = {**DEFAULT_PRIORITY_WEIGHTS, **(weights or {})}
    asset_criticality = CRITICALITY.get(str(getattr(vulnerability.asset, 'criticality', 'medium')).lower(), 45.0)
    intel = 0.0
    try:
        info = vulnerability.intelligence
    except Exception:
        info = None
    if info is not None:
        epss = info.epss if isinstance(info.epss, dict) else {}
        kev = info.cisa_kev if isinstance(info.cisa_kev, dict) else {}
        epss_score = float(epss.get('score') or epss.get('epss') or 0) * 100.0
        kev_score = 100.0 if kev and not kev.get('not_found') else 0.0
        intel = max(epss_score, kev_score)
    factors = {
        'severity': SEVERITY.get(vulnerability.severity, 50.0),
        'cvss': min(100.0, max(0.0, float(vulnerability.cvss_score or 0) * 10.0)),
        'criticality': asset_criticality,
        'exploitability': min(100.0, max(0.0, float(vulnerability.exploitability or 0))),
        'business_impact': min(100.0, max(0.0, float(vulnerability.business_impact or 0))),
        'intel': min(100.0, max(0.0, intel)),
        'evidence': min(100.0, float(vulnerability.verified_evidence_count or 0) * 25.0 + float(vulnerability.evidence_count or 0) * 5.0),
        'validation': 100.0 if vulnerability.validation_status in {'confirmed', 'validated'} else 35.0 if vulnerability.validation_status else 0.0,
    }
    denominator = sum(max(0.0, float(value)) for value in weights.values()) or 1.0
    score = sum(factors[name] * max(0.0, float(weights.get(name, 0))) for name in factors) / denominator
    return {'priority': round(max(0.0, min(100.0, score)), 2), 'factors': factors, 'weights': weights}


@transaction.atomic
def enrich_finding_priority(vulnerability_id: str) -> dict[str, Any]:
    vulnerability = Vulnerability.objects.select_for_update().select_related('asset').get(pk=vulnerability_id)
    latest = AdaptiveWeightProfile.objects.filter(project=vulnerability.project).order_by('-version').first()
    result = contextual_priority(vulnerability, latest.weights if latest else None)
    vulnerability.risk_score = result['priority']
    vulnerability.raw_data = {**(vulnerability.raw_data or {}), 'priority_enrichment': result}
    vulnerability.save(update_fields=['risk_score', 'raw_data', 'updated_at'])
    return result


@transaction.atomic
def update_feedback_weights(*, project, features: dict[str, float], reward: float, learning_rate: float = 0.08) -> AdaptiveWeightProfile:
    if not -1.0 <= float(reward) <= 1.0:
        raise ValueError('reward must be between -1 and 1')
    if not 0 < float(learning_rate) <= 0.5:
        raise ValueError('learning_rate must be in (0, 0.5]')
    organization = _tenant_for_project(project)
    latest = AdaptiveWeightProfile.objects.select_for_update().filter(project=project).order_by('-version').first()
    weights = dict(latest.weights if latest else DEFAULT_PRIORITY_WEIGHTS)
    for name in DEFAULT_PRIORITY_WEIGHTS:
        feature = max(0.0, min(1.0, float(features.get(name, 0.0))))
        weights[name] = max(0.01, min(2.0, float(weights.get(name, DEFAULT_PRIORITY_WEIGHTS[name])) + float(learning_rate) * float(reward) * feature))
    total = sum(weights.values())
    weights = {key: round(value / total, 8) for key, value in weights.items()}
    learned_from = (latest.learned_from if latest else 0) + 1
    previous_mean = latest.reward_mean if latest else 0.0
    reward_mean = previous_mean + (float(reward) - previous_mean) / learned_from
    return AdaptiveWeightProfile.objects.create(
        organization=organization, project=project, version=(latest.version + 1 if latest else 1),
        weights=weights, learned_from=learned_from, reward_mean=reward_mean,
    )


def predict_novel_exposure(features: dict[str, float], coefficients: dict[str, float] | None = None) -> dict[str, Any]:
    names = ('novelty','surface_change','unpatched_age','privilege','reachability','control_gap','telemetry_gap')
    defaults = {'novelty':1.25,'surface_change':0.95,'unpatched_age':0.75,'privilege':1.05,'reachability':1.10,'control_gap':1.20,'telemetry_gap':0.85}
    weights = {**defaults, **(coefficients or {})}
    normalized = {name:max(0.0,min(1.0,float(features.get(name,0.0)))) for name in names}
    z = -2.6 + sum(weights[name] * normalized[name] for name in names)
    probability = 1.0 / (1.0 + math.exp(-z))
    return {
        'probability': round(probability, 6),
        'risk_score': round(probability * 100.0, 2),
        'features': normalized,
        'model': 'novel-exposure-logistic-v1',
        'claim': 'exposure-risk-estimate-not-zero-day-discovery',
    }


@transaction.atomic
def record_artifact_integrity(
    *, project, user_id: str, artifact_type: str, name: str, source_ref: str, sha256: str,
    signature_verified: bool, provenance_verified: bool, package_namespace: str = '',
    metadata: dict[str, Any] | None = None, trusted_namespaces: list[str] | None = None,
) -> ArtifactIntegrityRecord:
    if not re.fullmatch(r'[0-9a-f]{64}', sha256):
        raise ValueError('sha256 must be a lowercase 64-character digest')
    organization = _tenant_for_project(project)
    trusted_namespaces = trusted_namespaces or []
    suspicious_namespace = bool(package_namespace and trusted_namespaces and not any(
        package_namespace == prefix or package_namespace.startswith(prefix + '/') for prefix in trusted_namespaces
    ))
    reasons = []
    if not signature_verified: reasons.append('signature-not-verified')
    if not provenance_verified: reasons.append('provenance-not-verified')
    if suspicious_namespace: reasons.append('namespace-outside-trusted-boundary')
    state = ArtifactIntegrityRecord.State.TRUSTED
    if reasons:
        state = ArtifactIntegrityRecord.State.QUARANTINED if suspicious_namespace or (not signature_verified and not provenance_verified) else ArtifactIntegrityRecord.State.REVIEW
    return ArtifactIntegrityRecord.objects.create(
        organization=organization, project=project, artifact_type=artifact_type, name=name,
        source_ref=source_ref, sha256=sha256, signature_verified=signature_verified,
        provenance_verified=provenance_verified, package_namespace=package_namespace,
        state=state, quarantine_reason=','.join(reasons), metadata=metadata or {}, created_by_id=user_id,
    )


@transaction.atomic
def create_investigation_case(
    *, project, owner_id: str, title: str, description: str = '',
    finding_ids: list[str] | None = None, evidence_ids: list[str] | None = None,
) -> InvestigationCase:
    organization = _tenant_for_project(project)
    finding_ids = list(dict.fromkeys(finding_ids or []))
    evidence_ids = list(dict.fromkeys(evidence_ids or []))
    findings = list(Vulnerability.objects.filter(project=project, pk__in=finding_ids))
    evidences = list(Evidence.objects.filter(scan__project=project, pk__in=evidence_ids))
    if len(findings) != len(finding_ids):
        raise ValueError('one or more findings are outside the case project')
    if len(evidences) != len(evidence_ids):
        raise ValueError('one or more evidence records are outside the case project')
    case = InvestigationCase.objects.create(
        organization=organization, project=project, owner_id=owner_id, title=title, description=description,
    )
    case.findings.set(findings)
    case.evidence.set(evidences)
    InvestigationCaseEvent.objects.create(
        case=case, actor_id=owner_id, event_type='case.created',
        payload={'finding_ids':finding_ids,'evidence_ids':evidence_ids},
    )
    return case


@transaction.atomic
def persist_evidence_graph(*, project, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    organization = _tenant_for_project(project)
    node_map: dict[str, EvidenceGraphNode] = {}
    valid_kinds = {value for value, _ in EvidenceGraphNode.Kind.choices}
    for item in nodes:
        kind = str(item['kind'])
        external_ref = str(item['external_ref'])
        if kind not in valid_kinds:
            raise ValueError(f'unsupported graph node kind: {kind}')
        node, _ = EvidenceGraphNode.objects.update_or_create(
            project=project, kind=kind, external_ref=external_ref,
            defaults={'organization':organization,'label':str(item.get('label') or external_ref)[:300],
                      'confidence':float(item.get('confidence',1.0)),'properties':item.get('properties') or {}},
        )
        node_map[external_ref] = node
    count = 0
    for item in edges:
        source = node_map.get(str(item['source'])); target = node_map.get(str(item['target']))
        if source is None or target is None:
            raise ValueError('graph edge references an unknown node')
        EvidenceGraphEdge.objects.update_or_create(
            project=project, source=source, target=target, edge_type=str(item['edge_type']),
            defaults={'organization':organization,'weight':float(item.get('weight',1.0)),
                      'evidence_refs':item.get('evidence_refs') or [],'properties':item.get('properties') or {}},
        )
        count += 1
    return {'nodes':len(node_map),'edges':count}


@transaction.atomic
def persist_blast_radius(
    *, project, root_ref: str, impacted_nodes: list[dict[str, Any]], crown_jewel_refs: list[str],
    evidence_refs: list[str], attack_path_id: str | None = None,
) -> BlastRadiusSnapshot:
    organization = _tenant_for_project(project)
    crown = set(str(value) for value in crown_jewel_refs)
    total = 0.0
    for node in impacted_nodes:
        risk = max(0.0,min(100.0,float(node.get('risk',0))))
        distance = max(1,int(node.get('distance',1)))
        multiplier = 1.35 if str(node.get('id')) in crown else 1.0
        total += (risk / distance) * multiplier
    score = min(100.0, total / max(1,len(impacted_nodes)))
    return BlastRadiusSnapshot.objects.create(
        organization=organization, project=project, attack_path_id=attack_path_id, root_ref=root_ref,
        crown_jewel_refs=sorted(crown), impacted_nodes=impacted_nodes, score=round(score,2),
        evidence_refs=sorted(set(evidence_refs)),
    )


@transaction.atomic
def checkpoint_scan(scan: Scan, *, state: str | None = None, metadata: dict[str, Any] | None = None) -> ScanControlCheckpoint:
    latest = ScanControlCheckpoint.objects.select_for_update().filter(scan=scan).order_by('-sequence').first()
    return ScanControlCheckpoint.objects.create(
        scan=scan, sequence=(latest.sequence + 1 if latest else 1), state=state or scan.status,
        phase=scan.current_phase or '', engine=scan.current_engine or '', progress=scan.progress,
        task_id=scan.celery_task_id or '', metadata=metadata or {},
    )


def verify_policy_constraints(*, project, proof_type: str, facts: dict[str, bool]) -> FormalPolicyProof:
    try:
        import z3
    except ImportError as exc:
        raise RuntimeError('z3-solver is required for formal policy verification') from exc
    organization = _tenant_for_project(project)
    authorized=z3.Bool('authorized'); in_scope=z3.Bool('in_scope'); destructive=z3.Bool('destructive')
    privileged=z3.Bool('privileged'); approval=z3.Bool('explicit_approval')
    solver=z3.Solver()
    solver.add(z3.Implies(authorized,in_scope))
    solver.add(z3.Not(destructive))
    solver.add(z3.Implies(privileged,approval))
    bindings={'authorized':authorized,'in_scope':in_scope,'destructive':destructive,'privileged':privileged,'explicit_approval':approval}
    for key,var in bindings.items():
        solver.add(var == bool(facts.get(key,False)))
    status=solver.check()
    satisfiable=status==z3.sat
    model={}
    if satisfiable:
        solved=solver.model()
        model={key:bool(z3.is_true(solved.eval(var,model_completion=True))) for key,var in bindings.items()}
    payload={'proof_type':proof_type,'facts':{key:bool(value) for key,value in facts.items()}}
    return FormalPolicyProof.objects.create(
        organization=organization,project=project,proof_type=proof_type,
        input_sha256=hashlib.sha256(_canonical(payload)).hexdigest(),
        satisfiable=satisfiable,model=model,solver='z3',solver_version=z3.get_version_string(),
    )

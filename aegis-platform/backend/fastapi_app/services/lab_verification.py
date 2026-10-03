"""BAC verdicts from committed observations and a trusted runtime inspection.

The signing function is internal to the provisioner's control plane. It has no
HTTP endpoint and must never sign client-supplied inspection assertions. The
fixture holds no signing key; its self-reported revision alone proves nothing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from uuid import UUID, uuid5, NAMESPACE_URL

from django.core.signing import BadSignature, TimestampSigner
from django.db import transaction
from django.utils import timezone

from django_project.evidence.models import Evidence, ValidationRun
from django_project.system.credential_vault import CredentialVaultDenied
from django_project.vulnerabilities.models import Vulnerability
from enterprise.burp_mcp_models import BurpMCPInvocation, BurpMCPSession

POLICY = 'aegis.bac-lab-verifier.v1'
RUNTIME_SCHEMA = 'aegis.web-lab-runtime-inspection.v1'
RUNTIME_TTL = 600
FIXTURE_REVISION = 'b051e47ecb3b77c97a2b89b12cc7d98c0557ce9b330f63d301c2d70a81f21bc9'
SHA = re.compile(r'^[0-9a-f]{64}$')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError('Duplicate JSON field')
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs)


def _signer(salt=RUNTIME_SCHEMA):
    # Reuse the deployment's existing evidence HMAC key; never a target secret,
    # client key or a hard-coded development fallback.
    key = os.environ.get('AEGIS_EVIDENCE_HMAC_KEY', '')
    if len(key) < 32:
        raise CredentialVaultDenied('The trusted runtime inspector signing key is unavailable.')
    return TimestampSigner(key=key, salt=salt, fallback_keys=[])


def _inspection_shape(value):
    fields = {'schema', 'project_ref', 'asset_ref', 'target', 'instance_ref', 'process_ref',
              'fixture_revision', 'variant', 'image_id', 'container_id', 'inspected_at'}
    if not isinstance(value, dict) or set(value) != fields or value['schema'] != RUNTIME_SCHEMA:
        raise CredentialVaultDenied('Unsupported runtime inspection shape.')
    try:
        for field in ('project_ref', 'asset_ref', 'instance_ref', 'process_ref'):
            if str(UUID(value[field])) != value[field]:
                raise ValueError('Noncanonical UUID')
        if (value['fixture_revision'] != FIXTURE_REVISION
                or value['variant'] not in {'vulnerable', 'patched'}
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['image_id'])
                or not SHA.fullmatch(value['container_id'])
                or not isinstance(value['target'], str) or len(value['target']) > 500
                or type(value['inspected_at']) not in (int, float)
                or not 0 <= time.time() - value['inspected_at'] <= RUNTIME_TTL):
            raise ValueError('Invalid or expired inspection')
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        raise CredentialVaultDenied('Invalid, expired or future runtime inspection.') from exc
    return value


def record_runtime_inspection(*, asset, actor_id, inspection):
    """Internal trusted-provisioner operation, after sealed-container inspection.

    This accepts the inspector's assertions, not a remote target's assertions.
    The caller must first run scripts/inspect_web_lab_runtime.py with an expected
    immutable image ID. No public API or task can call this signing operation.
    """
    from enterprise.models import OrganizationMembership, TenantProject
    from .burp_mcp_gateway import _project_access
    link = TenantProject.objects.filter(project=asset.project, organization__is_active=True).first()
    if (not link or not _project_access(asset.project, str(actor_id))
            or not OrganizationMembership.objects.filter(organization=link.organization,
                user_id=actor_id, user__is_active=True, is_active=True,
                role__in=[OrganizationMembership.Role.OWNER, OrganizationMembership.Role.MANAGER]).exists()):
        raise CredentialVaultDenied('The runtime inspector requires current project/tenant management authority.')
    value = _inspection_shape({**inspection, 'schema': RUNTIME_SCHEMA,
                              'project_ref': str(asset.project_id), 'asset_ref': str(asset.id)})
    from .authorization_guard import asset_target
    if value['target'] != asset_target(asset):
        raise CredentialVaultDenied('Runtime inspection origin does not match the current asset.')
    envelope = {'schema': RUNTIME_SCHEMA, 'signed_inspection': _signer().sign_object(value)}
    return Evidence.objects.create(asset=asset, collected_by_id=actor_id,
        source='lab_runtime_inspector', evidence_type='lab_runtime_binding',
        raw_output=canonical(envelope), metadata={'schema': RUNTIME_SCHEMA,
            'project_id': str(asset.project_id), 'target': value['target'],
            'runtime_inspection_is_trusted_control_plane': True})


def validate_runtime_evidence(*, evidence_ref, project_id, asset_id, target):
    row = Evidence.objects.filter(pk=evidence_ref, asset_id=asset_id,
                                  asset__project_id=project_id).first()
    if (not row or row.source != 'lab_runtime_inspector'
            or row.evidence_type != 'lab_runtime_binding' or digest(row.raw_output) != row.sha256
            or len(row.raw_output) > 8192):
        raise CredentialVaultDenied('A trusted, intact runtime inspection is required in this project and asset.')
    try:
        envelope = strict_json(row.raw_output)
        if set(envelope) != {'schema', 'signed_inspection'} or envelope['schema'] != RUNTIME_SCHEMA:
            raise ValueError('Invalid signed envelope')
        value = _inspection_shape(_signer().unsign_object(envelope['signed_inspection'], max_age=RUNTIME_TTL))
    except (BadSignature, ValueError, TypeError, KeyError) as exc:
        raise CredentialVaultDenied('Runtime inspection signature is invalid or expired.') from exc
    if (value['project_ref'] != str(project_id) or value['asset_ref'] != str(asset_id)
            or value['target'] != target):
        raise CredentialVaultDenied('Runtime inspection has a different tenant, asset or origin binding.')
    return {**value, 'evidence_ref': str(row.id), 'evidence_sha256': row.sha256}


def evaluate_bac_observations(observations, *, session, runtime):
    """Independent, network-free decision from bounded immutable facts."""
    from .burp_lab_requests import VERIFIED_STEPS
    result = {'policy_version': POLICY, 'attempt_ref': str(session.scan_id),
              'definition_id': 'bac-orders-v1', 'fixture_revision': FIXTURE_REVISION,
              'instance_ref': runtime['instance_ref'], 'process_ref': runtime['process_ref'],
              'verdict': 'indeterminate', 'finding_present': None, 'lab_solved': False,
              'live_fixture_revision_verified': False, 'reason_codes': []}
    def reject(reason):
        return {**result, 'reason_codes': [reason]}
    if not isinstance(observations, list) or len(observations) != len(VERIFIED_STEPS):
        return reject('incomplete_recipe')
    for observation, (step, (identity, path)) in zip(observations, VERIFIED_STEPS.items()):
        if (not isinstance(observation, dict) or observation.get('step_ref') != step
                or observation.get('action_ref') != 'GET:' + path
                or observation.get('identity_ref') != identity
                or observation.get('attempt_ref') != str(session.scan_id)
                or observation.get('target_ref') != str(session.asset_id)
                or observation.get('definition_id') != 'bac-orders-v1'
                or observation.get('fixture_revision') != FIXTURE_REVISION
                or type(observation.get('status_code')) is not int
                or any(not isinstance(observation.get(k), str) or not SHA.fullmatch(observation[k])
                       for k in ('wire_request_sha256', 'response_sha256'))):
            return reject('observation_binding_mismatch')
    for observation in (observations[0], observations[-1]):
        expected = {k: runtime[k] for k in ('instance_ref', 'process_ref', 'fixture_revision', 'variant')}
        expected['nonce'] = str(session.id) + '-' + observation['step_ref']
        if observation['status_code'] != 200 or observation.get('instance_identity') != expected:
            return reject('runtime_identity_or_challenge_mismatch')
    result['live_fixture_revision_verified'] = True
    baseline, cross, patched, bob, anonymous, recheck = observations[1:-1]
    alice_resource = {'id': '51', 'owner_id': 'alice', 'tenant_id': 'tenant-a'}
    bob_resource = {'id': '74', 'owner_id': 'bob', 'tenant_id': 'tenant-b'}
    if any(o['status_code'] != 200 or o.get('resource') != alice_resource for o in (baseline, recheck)):
        return reject('owner_baseline_or_recheck_failed')
    if bob['status_code'] != 200 or bob.get('resource') != bob_resource:
        return reject('patched_owner_baseline_failed')
    if patched['status_code'] != 404 or patched.get('resource') is not None:
        return reject('patched_control_failed')
    if anonymous['status_code'] != 401 or anonymous.get('resource') is not None:
        return reject('anonymous_control_failed')
    if runtime['variant'] == 'patched' and cross['status_code'] == 404 and cross.get('resource') is None:
        return {**result, 'verdict': 'not_vulnerable', 'finding_present': False,
                'reason_codes': ['cross_owner_denied_with_valid_controls']}
    if runtime['variant'] == 'vulnerable' and cross['status_code'] == 200 and cross.get('resource') == bob_resource:
        return {**result, 'verdict': 'vulnerable', 'finding_present': True, 'lab_solved': True,
                'reason_codes': ['cross_owner_resource_proven_with_valid_controls']}
    return reject('cross_owner_or_variant_expectation_failed')


def verify_lab_attempt(*, session_id, actor_id):
    """Commit a verdict, validation evidence and optional OPEN finding atomically.

    Finding Confirmation remains a separate governed review. A solved fixture
    is not permission to self-confirm a finding or complete all of WSTG.
    """
    from .burp_mcp_gateway import _invocation_context, BurpMCPAuthorizationError
    from .burp_lab_requests import VERIFIED_STEPS
    from .audit_writer import add_audit_entry
    evidence_id = uuid5(NAMESPACE_URL, 'aegis:lab-verification:' + str(session_id))
    with transaction.atomic():
        context = _invocation_context(session_id, actor_id, 'burp.http_request',
                                     {'lab_step': 'instance_after'}, 'lab-verifier-context')
        session, organization, project, asset, scan, authorization = context[:6]
        contract = session.contract_snapshot.get('lab', {})
        if not contract.get('runtime_binding'):
            raise BurpMCPAuthorizationError('Observation-only sessions cannot produce a lab verdict.')
        if scan.status not in {'running', 'completed'}:
            raise BurpMCPAuthorizationError('Lab verification requires an active or reconciled completed attempt.')
        existing = Evidence.objects.filter(pk=evidence_id, scan=scan, source='lab_verification').first()
        if existing:
            try:
                signature = existing.metadata['trusted_verdict_signature']
                signed_hash = _signer(POLICY).unsign_object(signature)
                if digest(existing.raw_output) != existing.sha256 or signed_hash != existing.sha256:
                    raise ValueError('Stored result hash differs from signed verdict')
                result = strict_json(existing.raw_output)
                if (result.get('session_ref') != str(session.id) or result.get('attempt_ref') != str(scan.id)
                        or result.get('asset_ref') != str(asset.id)
                        or result.get('authorization_ref') != str(authorization.id)
                        or result.get('policy_version') != POLICY):
                    raise ValueError('Signed verdict was transplanted from another binding')
            except (KeyError, BadSignature, ValueError, TypeError) as exc:
                raise BurpMCPAuthorizationError('Stored lab verdict integrity failed.') from exc
            return result
        runtime = validate_runtime_evidence(evidence_ref=contract['runtime_binding']['evidence_ref'],
            project_id=str(project.id), asset_id=str(asset.id), target=session.target_snapshot)
        if runtime != contract['runtime_binding']:
            raise BurpMCPAuthorizationError('Pinned runtime inspection changed before verdict commit.')
        invocations = list(BurpMCPInvocation.objects.select_related('evidence', 'qualification', 'claim')
                           .filter(session=session).order_by('invocation_sequence'))
        if (len(invocations) != len(VERIFIED_STEPS)
                or session.invocation_claims.exclude(state='committed').exists()
                or session.invocation_claims.count() != len(invocations)):
            raise BurpMCPAuthorizationError('Incomplete or uncertain calls cannot support a lab verdict.')
        for sequence, invocation in enumerate(invocations, 1):
            evidence = invocation.evidence
            try:
                raw = strict_json(evidence.raw_output)
                intact = (invocation.invocation_sequence == sequence and invocation.qualification.qualified
                    and invocation.claim.state == 'committed' and invocation.claim.invocation_id == invocation.id
                    and evidence.scan_id == scan.id and evidence.asset_id == asset.id
                    and evidence.source == 'burp_mcp' and digest(evidence.raw_output) == evidence.sha256
                    and evidence.sha256 == invocation.evidence_sha256
                    and raw['result_summary'] == invocation.result_summary
                    and raw['session_id'] == str(session.id) and raw['scan_id'] == str(scan.id)
                    and raw['authorization_decision_id'] == str(authorization.id)
                    and raw['project_id'] == str(project.id) and raw['asset_id'] == str(asset.id))
            except (ValueError, KeyError, TypeError):
                intact = False
            if not intact:
                raise BurpMCPAuthorizationError('Immutable observation evidence failed lineage or integrity checks.')
        result = evaluate_bac_observations([i.result_summary for i in invocations], session=session, runtime=runtime)
        result.update(session_ref=str(session.id), asset_ref=str(asset.id), authorization_ref=str(authorization.id),
                      evidence_refs=[str(i.evidence_id) for i in invocations],
                      runtime_evidence_ref=runtime['evidence_ref'], evidence_id=str(evidence_id),
                      finding_id=None, validation_run_id=None, finding_confirmation='not_applicable')
        now = timezone.now()
        finding = validation = None
        if result['finding_present'] is True:
            finding = Vulnerability.objects.create(scan=scan, project=project, asset=asset,
                title='Cross-owner order disclosure in the pinned BAC fixture',
                description='Alice retrieved Bob\'s order; the owner, patched and anonymous controls passed.',
                severity=Vulnerability.Severity.HIGH, confidence=Vulnerability.Confidence.HIGH,
                status=Vulnerability.Status.OPEN, source_engine='burp-mcp', cwe_id='CWE-639',
                category='broken_access_control', method='GET', url=session.target_snapshot + '/vulnerable/orders/74',
                raw_data={'lab_policy_version': POLICY, 'lab_attempt_ref': str(scan.id),
                          'methodology_id': 'WSTG-v42-ATHZ-04', 'source_evidence_refs': result['evidence_refs']})
            validation = ValidationRun.objects.create(user_id=actor_id, finding=finding,
                authorization_decision=authorization, target_type='url', target_value=session.target_snapshot,
                scope=session.target_snapshot, engines=['burp-mcp-lab-verifier'], authorized=True,
                status=ValidationRun.Status.COMPLETED, progress=100, current_phase='lab-verification-completed',
                started_at=now, completed_at=now)
            result.update(finding_id=str(finding.id), validation_run_id=str(validation.id),
                          finding_confirmation='pending_independent_review')
        evidence = Evidence.objects.create(id=evidence_id, scan=scan, asset=asset, finding=finding,
            collected_by_id=actor_id, source='lab_verification',
            evidence_type='validation_output' if validation else 'lab_verdict', raw_output=canonical(result),
            metadata={'schema': POLICY, 'project_id': str(project.id), 'target': session.target_snapshot,
                'source_capability': 'burp.mcp.gateway', 'producer': 'burp_mcp', 'verifier': POLICY,
                'subject_type': 'asset', 'subject_id': str(asset.id), 'execution_ref': str(session.id),
                'authorization_decision_id': str(authorization.id),
                'validation_run_id': str(validation.id) if validation else None,
                'finding_present': result['finding_present'],
                'trusted_verdict_signature': _signer(POLICY).sign_object(digest(canonical(result)))})
        from .evidence_qualification import EvidenceQualificationPolicy, qualify_evidence
        qualification = qualify_evidence(project_id=str(project.id), organization_id=str(organization.id),
            evidence_ids=[str(evidence.id)], subject_type='asset', subject_id=str(asset.id),
            target=session.target_snapshot, authorization_ref=str(authorization.id), execution_ref=str(session.id),
            requested_by_id=str(actor_id), policy=EvidenceQualificationPolicy(policy_version=POLICY,
                evidence_types=(evidence.evidence_type,), source_capabilities=('burp.mcp.gateway',),
                require_subject=True, require_target=True, require_authorization=True, require_execution=True,
                require_producer=True, require_verifier=True))
        if not qualification.qualified:
            raise BurpMCPAuthorizationError('The independent lab verdict failed evidence qualification.')
        if validation:
            validation.result = {**result, 'tool': POLICY}
            validation.save(update_fields=['result'])
        add_audit_entry(user=str(actor_id), action='web_lab.verification.commit', target=str(evidence.id),
            project=str(project.id), resource_type='lab_verification', resource_repr=POLICY,
            metadata={'attempt_ref': str(scan.id), 'session_ref': str(session.id),
                      'verdict': result['verdict'], 'lab_solved': result['lab_solved'],
                      'qualification_id': str(qualification.evaluation.id)})
        return result

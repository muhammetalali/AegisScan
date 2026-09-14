from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Literal

from .capability_planner import Depth, plan_capabilities
from .wstg_capability_mapping import EXPECTED_GAPS, WSTGCapabilityMapping
from .wstg_catalog import PACK, WSTGCatalog

WSTGPlanStatus = Literal['planned', 'manual_required', 'inconclusive', 'blocked', 'not_applicable']

_POLICY_MODES = {
    'AUTO_EXISTING', 'ASSISTED_EXISTING', 'MANUAL_GOVERNED',
    'GAP_NATIVE_SMALL', 'CONDITIONAL_NA',
}
_KALI_REQUIREMENTS = {'required', 'manual_only', 'conditional'}
_ALLOWED_FACT = re.compile(r'^[a-z0-9]+(?:[._-][a-z0-9]+)+$')
_FLASH_TECH = re.compile(r'(^|[^a-z0-9])(adobe[ -]?flash|flash|shockwave|swf)([^a-z0-9]|$)')


@dataclass(frozen=True)
class WSTGPlanningContext:
    asset_ref: str
    authorization_ref: str
    asset_type: str
    facts: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.asset_ref.strip():
            raise ValueError('WSTG planning requires an authoritative asset_ref')
        if not self.authorization_ref.strip():
            raise ValueError('WSTG planning requires an authoritative authorization_ref')
        if not self.asset_type.strip():
            raise ValueError('WSTG planning requires an asset_type')
        if len(set(self.facts)) != len(self.facts):
            raise ValueError('WSTG planning facts must be unique')
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError('WSTG planning evidence refs must be unique')
        for fact in self.facts:
            if not _ALLOWED_FACT.fullmatch(fact):
                raise ValueError(f'Invalid WSTG planning fact: {fact}')
        for ref in self.evidence_refs:
            if not ref.strip() or len(ref) > 180:
                raise ValueError('Invalid WSTG applicability evidence ref')


@dataclass(frozen=True)
class WSTGExecutionPolicy:
    wstg_id: str
    mode: str
    runner_preference: str
    execution_backend: str
    runtime_action: str
    evidence_contract: str
    kali_requirement: str


@dataclass(frozen=True)
class WSTGPlanItem:
    wstg_id: str
    classification: str
    status: WSTGPlanStatus
    reason: str
    semantic_requirement_id: str
    provider_capability_ids: tuple[str, ...]
    support_service_refs: tuple[str, ...]
    runner_preference: str
    execution_backend: str
    runtime_action: str
    evidence_contract: str
    kali_requirement: str
    applicability_evidence_refs: tuple[str, ...]
    authorization_required: bool
    order: int

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class WSTGPlanResult:
    asset_ref: str
    authorization_ref: str
    asset_type: str
    depth: Depth
    policy_fingerprint: str
    status_counts: dict[str, int]
    items: tuple[WSTGPlanItem, ...]

    def public_dict(self) -> dict[str, Any]:
        return {
            'asset_ref': self.asset_ref,
            'authorization_ref': self.authorization_ref,
            'asset_type': self.asset_type,
            'depth': self.depth,
            'methodology': 'WSTG',
            'methodology_version': '4.2',
            'policy_fingerprint': self.policy_fingerprint,
            'status_counts': dict(self.status_counts),
            'items': [item.public_dict() for item in self.items],
        }


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate WSTG planner JSON key: {key}')
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[bytes, Any]:
    raw = path.read_bytes()
    if len(raw) > 768_000:
        raise ValueError('WSTG planner metadata exceeds size limit')
    try:
        return raw, json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ValueError(f'Invalid WSTG planner JSON: {path.name}') from exc


class WSTGExecutionPlanner:
    """Non-dispatching WSTG applicability + semantic execution planner."""

    def __init__(self, pack: Path = PACK):
        self.pack = pack
        self.catalog = WSTGCatalog(pack)
        self.mapping = WSTGCapabilityMapping(pack)
        self.policies, self.applicability = self._load_policy_pack()
        self._policies = {item.wstg_id: item for item in self.policies}

    def _load_policy_pack(self):
        _, manifest = _read_json(self.pack / 'manifest.json')
        digests = manifest.get('planner_files')
        expected = {'execution_policies.json', 'applicability.json'}
        if not isinstance(digests, dict) or set(digests) != expected:
            raise ValueError('Missing or unexpected WSTG planner files')

        payloads = {}
        for name, expected_digest in digests.items():
            if not isinstance(expected_digest, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_digest):
                raise ValueError('Invalid WSTG planner file digest')
            raw, payload = _read_json(self.pack / name)
            if hashlib.sha256(raw).hexdigest() != expected_digest:
                raise ValueError(f'WSTG planner checksum mismatch: {name}')
            payloads[name] = payload

        policy_pack = payloads['execution_policies.json']
        if not isinstance(policy_pack, dict) or set(policy_pack) != {
            'schema_version', 'matrix_source_sha256', 'runner_preferences', 'mode_semantics'
        }:
            raise ValueError('Unexpected WSTG execution policy pack fields')
        if policy_pack['schema_version'] != '1.0':
            raise ValueError('Unexpected WSTG execution policy schema version')

        design_inputs = {
            item.get('filename'): item.get('sha256')
            for item in manifest.get('design_inputs', [])
            if isinstance(item, dict)
        }
        if policy_pack['matrix_source_sha256'] != design_inputs.get(
            'AegisScan_WSTG_v42_97_Kali_Execution_Matrix_2026-09-14.xlsx'
        ):
            raise ValueError('WSTG execution policy is not bound to the approved matrix digest')

        official = {item.id: item for item in self.catalog.tests}
        runner_preferences = policy_pack['runner_preferences']
        if not isinstance(runner_preferences, dict) or set(runner_preferences) != set(official):
            raise ValueError('WSTG runner preferences must cover exactly all 97 canonical tests')
        if any(not isinstance(value, str) or not value.strip() for value in runner_preferences.values()):
            raise ValueError('Invalid WSTG runner preference')

        semantics = policy_pack['mode_semantics']
        if not isinstance(semantics, dict) or set(semantics) != _POLICY_MODES:
            raise ValueError('WSTG mode semantics must cover exactly the five approved classifications')
        required_semantics = {'execution_backend', 'runtime_action', 'evidence_contract', 'kali_requirement'}
        for mode, row in semantics.items():
            if not isinstance(row, dict) or set(row) != required_semantics:
                raise ValueError(f'Unexpected WSTG mode semantic fields: {mode}')
            expected_kali = (
                'manual_only' if mode == 'MANUAL_GOVERNED'
                else 'conditional' if mode == 'CONDITIONAL_NA'
                else 'required'
            )
            if row['kali_requirement'] != expected_kali or row['kali_requirement'] not in _KALI_REQUIREMENTS:
                raise ValueError(f'WSTG policy Kali requirement drift: {mode}')
            if any(not isinstance(row[k], str) or not row[k].strip() for k in required_semantics):
                raise ValueError(f'Invalid WSTG mode semantics: {mode}')

        policies = tuple(
            WSTGExecutionPolicy(
                wstg_id=test.id,
                mode=test.classification,
                runner_preference=runner_preferences[test.id],
                execution_backend=semantics[test.classification]['execution_backend'],
                runtime_action=semantics[test.classification]['runtime_action'],
                evidence_contract=semantics[test.classification]['evidence_contract'],
                kali_requirement=semantics[test.classification]['kali_requirement'],
            )
            for test in self.catalog.tests
        )

        applicability = payloads['applicability.json']
        if not isinstance(applicability, dict) or set(applicability) != {
            'schema_version', 'methodology', 'version', 'methodology_asset_types', 'conditional_tests'
        }:
            raise ValueError('Unexpected WSTG applicability contract fields')
        if (
            applicability['schema_version'] != '1.0'
            or applicability['methodology'] != 'WSTG'
            or applicability['version'] != '4.2'
        ):
            raise ValueError('Unexpected WSTG applicability contract version')
        asset_types = applicability['methodology_asset_types']
        if not isinstance(asset_types, list) or not asset_types or len(asset_types) != len(set(asset_types)):
            raise ValueError('Invalid WSTG methodology asset type set')
        conditional = applicability['conditional_tests']
        expected_conditional = {
            item.id for item in self.catalog.tests if item.classification == 'CONDITIONAL_NA'
        }
        if not isinstance(conditional, dict) or set(conditional) != expected_conditional:
            raise ValueError('Conditional applicability test identity set changed')
        for wstg_id, rule in conditional.items():
            if not isinstance(rule, dict) or set(rule) != {
                'positive_fact', 'negative_fact', 'applicable_reason',
                'not_applicable_reason', 'inconclusive_reason'
            }:
                raise ValueError(f'Invalid conditional applicability rule: {wstg_id}')
            if not _ALLOWED_FACT.fullmatch(str(rule['positive_fact'])):
                raise ValueError(f'Invalid positive applicability fact: {wstg_id}')
            if not _ALLOWED_FACT.fullmatch(str(rule['negative_fact'])):
                raise ValueError(f'Invalid negative applicability fact: {wstg_id}')
            if rule['positive_fact'] == rule['negative_fact']:
                raise ValueError(f'Conflicting applicability facts: {wstg_id}')
        return policies, applicability

    def _conditional_state(self, wstg_id, context):
        rule = self.applicability['conditional_tests'].get(wstg_id)
        if rule is None:
            return None, '', ()
        facts = set(context.facts)
        positive = rule['positive_fact'] in facts
        negative = rule['negative_fact'] in facts
        if positive and negative:
            return 'inconclusive', 'Conflicting authoritative applicability facts are present.', context.evidence_refs
        if negative:
            if not context.evidence_refs:
                return 'inconclusive', 'Negative applicability fact lacks evidence references.', ()
            return 'not_applicable', rule['not_applicable_reason'], context.evidence_refs
        if not positive:
            return 'inconclusive', rule['inconclusive_reason'], context.evidence_refs
        return None, rule['applicable_reason'], context.evidence_refs

    def plan(self, context: WSTGPlanningContext, depth: Depth = 'standard') -> WSTGPlanResult:
        capability_plan = {item.capability_id: item for item in plan_capabilities(context.asset_type, depth)}
        methodology_asset_types = set(self.applicability['methodology_asset_types'])
        items = []

        for order, test in enumerate(self.catalog.tests, start=1):
            requirement = self.mapping.resolve(test.id)[0]
            policy = self._policies[test.id]
            service_refs = tuple(
                binding.ref for binding in requirement.provider_bindings
                if binding.kind in {'control_plane_service', 'governed_service'}
            )
            registry_refs = tuple(
                binding.ref for binding in requirement.provider_bindings
                if binding.kind == 'registry_capability'
            )
            eligible = tuple(
                capability_id for capability_id in registry_refs
                if capability_id in capability_plan and capability_plan[capability_id].execution_ready
            )

            if context.asset_type not in methodology_asset_types:
                status = 'not_applicable'
                reason = f'WSTG v4.2 is not applicable to authoritative asset type {context.asset_type}.'
                applicability_refs = (context.asset_ref,)
                eligible = ()
            else:
                conditional_status, conditional_reason, conditional_refs = self._conditional_state(test.id, context)
                if conditional_status is not None:
                    status, reason, applicability_refs = conditional_status, conditional_reason, conditional_refs
                    eligible = ()
                elif test.classification == 'MANUAL_GOVERNED':
                    status = 'manual_required'
                    reason = 'Governed manual work item; tool output cannot self-attest or auto-pass it.'
                    applicability_refs = context.evidence_refs
                    eligible = ()
                elif test.classification == 'GAP_NATIVE_SMALL':
                    expected_native = EXPECTED_GAPS.get(test.id)
                    if expected_native and expected_native in eligible:
                        status = 'planned'
                        reason = (
                            'Reviewed bounded native validator is registered, packaged and execution-ready; '
                            'dispatch remains authorization-bound and observation-only.'
                        )
                        applicability_refs = context.evidence_refs
                        eligible = (expected_native,)
                    else:
                        status = 'blocked'
                        reason = 'Approved native validator is not execution-ready; planner fails closed.'
                        applicability_refs = context.evidence_refs
                        eligible = ()
                elif eligible or service_refs:
                    status = 'planned'
                    reason = (
                        'Authoritative provider capability/service coverage is available; '
                        'dispatch remains a separate authorization-bound control-plane action.'
                    )
                    applicability_refs = context.evidence_refs
                else:
                    status = 'blocked'
                    reason = (
                        'No mapped provider is execution-ready for this asset/depth; '
                        'planner fails closed without dispatch.'
                    )
                    applicability_refs = context.evidence_refs

            items.append(WSTGPlanItem(
                wstg_id=test.id,
                classification=test.classification,
                status=status,
                reason=reason,
                semantic_requirement_id=requirement.id,
                provider_capability_ids=eligible,
                support_service_refs=service_refs,
                runner_preference=policy.runner_preference,
                execution_backend=policy.execution_backend,
                runtime_action=policy.runtime_action,
                evidence_contract=policy.evidence_contract,
                kali_requirement=policy.kali_requirement,
                applicability_evidence_refs=tuple(applicability_refs),
                authorization_required=status not in {'not_applicable', 'inconclusive'},
                order=order,
            ))

        material = {
            'asset_ref': context.asset_ref,
            'authorization_ref': context.authorization_ref,
            'asset_type': context.asset_type,
            'depth': depth,
            'facts': sorted(context.facts),
            'evidence_refs': sorted(context.evidence_refs),
            'items': [{
                'wstg_id': item.wstg_id,
                'status': item.status,
                'semantic_requirement_id': item.semantic_requirement_id,
                'provider_capability_ids': list(item.provider_capability_ids),
                'runner_preference': item.runner_preference,
                'kali_requirement': item.kali_requirement,
            } for item in items],
        }
        fingerprint = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(',', ':')).encode()
        ).hexdigest()
        counts = Counter(item.status for item in items)
        return WSTGPlanResult(
            asset_ref=context.asset_ref,
            authorization_ref=context.authorization_ref,
            asset_type=context.asset_type,
            depth=depth,
            policy_fingerprint=fingerprint,
            status_counts=dict(sorted(counts.items())),
            items=tuple(items),
        )


def _context_from_authorized_asset(asset, authorization) -> WSTGPlanningContext:
    facts = set()
    evidence_refs = {f'asset:{asset.id}', f'authorization:{authorization.id}'}
    for technology in asset.technologies.all().only('id', 'name', 'category', 'confidence'):
        material = f'{technology.name or ""} {technology.category or ""}'.lower()
        if float(technology.confidence or 0) >= 0.5 and _FLASH_TECH.search(material):
            facts.add('technology.flash.present')
            evidence_refs.add(f'technology:{technology.id}')
    return WSTGPlanningContext(
        asset_ref=str(asset.id),
        authorization_ref=str(authorization.id),
        asset_type=str(asset.type),
        facts=tuple(sorted(facts)),
        evidence_refs=tuple(sorted(evidence_refs)),
    )


def plan_wstg_for_authorized_asset(*, project_id: str, asset_id: str, depth: Depth = 'standard'):
    """Resolve persisted asset + current immutable authorization, then plan only."""
    from django_project.assets.models import Asset
    from .authorization_guard import current_asset_authorization

    asset = Asset.objects.filter(pk=asset_id, project_id=project_id, is_active=True).first()
    if asset is None:
        raise ValueError('Active project-scoped asset not found for WSTG planning')
    authorization, reason = current_asset_authorization(asset)
    if authorization is None:
        raise PermissionError(reason)
    return WSTGExecutionPlanner().plan(_context_from_authorized_asset(asset, authorization), depth)

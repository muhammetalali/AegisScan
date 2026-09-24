from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

from .wstg_capability_mapping import CUTOVER_PROVIDER_ANCHORS, WSTGCapabilityMapping
from .wstg_catalog import WSTGCatalog

CompletionMode = Literal[
    'direct_evidence',
    'evidence_plus_governed_attestation',
    'governed_attestation',
    'applicability_attestation',
]

@dataclass(frozen=True)
class WSTGCompletionPolicyRow:
    wstg_id: str
    classification: str
    semantic_requirement_id: str
    completion_mode: CompletionMode
    completion_claim_supported: bool
    verdict_claim_supported: bool
    provider_refs: tuple[str, ...]

    def public_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload['provider_refs'] = list(self.provider_refs)
        return payload

_MODE_BY_CLASSIFICATION: dict[str, CompletionMode] = {
    'AUTO_EXISTING': 'direct_evidence',
    'ASSISTED_EXISTING': 'evidence_plus_governed_attestation',
    'MANUAL_GOVERNED': 'governed_attestation',
    'GAP_NATIVE_SMALL': 'evidence_plus_governed_attestation',
    'CONDITIONAL_NA': 'applicability_attestation',
}

def build_wstg_completion_policy() -> dict[str, Any]:
    """Return the canonical completion-claim path for all 97 WSTG tests.

    Completion means the methodology test was executed/reviewed with the required
    evidence or governed attestation. It never means "passed", "failed", or that a
    Finding lifecycle decision was made.
    """
    catalog = WSTGCatalog()
    mapping = WSTGCapabilityMapping()
    rows: list[WSTGCompletionPolicyRow] = []

    for test in catalog.tests:
        requirement = mapping.resolve(test.id)[0]
        refs = tuple(sorted(binding.ref for binding in requirement.provider_bindings))
        mode = _MODE_BY_CLASSIFICATION[test.classification]

        supported = bool(refs)
        if test.classification == 'GAP_NATIVE_SMALL':
            anchor = CUTOVER_PROVIDER_ANCHORS.get(test.id)
            bindings = {(item.kind, item.ref) for item in requirement.provider_bindings}
            supported = (
                requirement.availability == 'existing'
                and anchor is not None
                and anchor in bindings
                and not any(item.kind == 'planned_native' for item in requirement.provider_bindings)
            )

        rows.append(WSTGCompletionPolicyRow(
            wstg_id=test.id,
            classification=test.classification,
            semantic_requirement_id=requirement.id,
            completion_mode=mode,
            completion_claim_supported=supported,
            verdict_claim_supported=False,
            provider_refs=refs,
        ))

    supported_count = sum(row.completion_claim_supported for row in rows)
    gap_rows = [row for row in rows if row.classification == 'GAP_NATIVE_SMALL']
    gap_supported_count = sum(row.completion_claim_supported for row in gap_rows)
    return {
        'schema': 'aegis.wstg-completion-policy.v1',
        'methodology': 'WSTG',
        'methodology_version': '4.2',
        'total_tests': len(rows),
        'completion_claim_supported_tests': supported_count,
        'gap_native_small_tests': len(gap_rows),
        'gap_native_small_completion_supported': gap_supported_count,
        'verdict_authority': 'governed-finding-confirmation',
        'observation_alone_is_completion': False,
        'completion_is_pass_or_fail': False,
        'rows': [row.public_dict() for row in rows],
    }

def completion_ready(
    *,
    classification: str,
    has_trusted_observation: bool,
    governed_attested: bool,
    applicability_attested: bool = False,
) -> bool:
    """Evaluate whether a methodology-completion claim may be emitted.

    This function intentionally never emits a security verdict.
    """
    mode = _MODE_BY_CLASSIFICATION[classification]
    if mode == 'direct_evidence':
        return has_trusted_observation
    if mode == 'evidence_plus_governed_attestation':
        return has_trusted_observation and governed_attested
    if mode == 'governed_attestation':
        return governed_attested
    return applicability_attested

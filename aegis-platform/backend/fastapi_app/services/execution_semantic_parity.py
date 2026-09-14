from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Iterable

from .native_finding_projection import (
    api_runtime_finding_specs,
    api_schema_finding_specs,
    browser_finding_specs,
    cloud_finding_specs,
    kubernetes_finding_specs,
    native_observation_finding_specs,
)


PARITY_SCHEMA = 'aegis.execution-semantic-parity.v1'


@dataclass(frozen=True)
class SemanticParityReport:
    schema: str
    capability_id: str
    semantic_equivalent: bool
    observation_equivalent: bool
    finding_projection_applicable: bool
    finding_projection_equivalent: bool
    legacy_observation_digest: str
    candidate_observation_digest: str
    legacy_finding_digest: str
    candidate_finding_digest: str
    legacy_observation_count: int
    candidate_observation_count: int
    legacy_finding_count: int
    candidate_finding_count: int
    mismatches: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _json_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, list):
        items = [_canonical(item) for item in value]
        return sorted(items, key=_json_key)
    if isinstance(value, tuple):
        return _canonical(list(value))
    return value


def _digest(value: Any) -> str:
    payload = _json_key(_canonical(value)).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def _normalized_observations(normalized: dict[str, Any]) -> list[dict[str, Any]]:
    observations = normalized.get('observations') if isinstance(normalized, dict) else None
    if not isinstance(observations, list):
        return []
    return [dict(item) for item in observations if isinstance(item, dict)]


FINDING_PROJECTION_CAPABILITIES = frozenset({
    'browser.dom-snapshot',
    'api.openapi-contract-security',
    'api.openapi-runtime-conformance',
    'kubernetes.read-only-posture',
    'cloud.read-only-posture',
    'web.nikto',
    'code.trivy-config',
})


def _finding_projection_applicable(capability_id: str) -> bool:
    return capability_id in FINDING_PROJECTION_CAPABILITIES


def _finding_specs(capability_id: str, normalized: dict[str, Any]) -> list[dict[str, Any]]:
    if capability_id == 'browser.dom-snapshot':
        specs = browser_finding_specs(normalized)
    elif capability_id == 'api.openapi-contract-security':
        specs = api_schema_finding_specs(normalized)
    elif capability_id == 'api.openapi-runtime-conformance':
        specs = api_runtime_finding_specs(normalized)
    elif capability_id == 'kubernetes.read-only-posture':
        specs = kubernetes_finding_specs(normalized)
    elif capability_id == 'cloud.read-only-posture':
        specs = cloud_finding_specs(normalized)
    elif capability_id == 'web.nikto':
        specs = native_observation_finding_specs(
            normalized,
            observation_kind='web-vulnerability',
            category='web-vulnerability-assessment',
        )
    elif capability_id == 'code.trivy-config':
        specs = native_observation_finding_specs(
            normalized,
            observation_kind='iac-security-finding',
            category='iac-security',
        )
    else:
        specs = []
    return [asdict(spec) for spec in specs]


def _count(values: Iterable[Any]) -> int:
    return sum(1 for _ in values)


def compare_execution_semantics(
    *,
    capability_id: str,
    legacy_normalized: dict[str, Any],
    candidate_normalized: dict[str, Any],
) -> SemanticParityReport:
    """Compare backend outputs after canonical normalization, never raw stdout/provenance.

    The comparison is deliberately backend-agnostic: execution IDs, timestamps, runtime
    provider metadata, image digests and raw stdout are not inputs. A backend migration
    passes only when normalized observations and the Finding projection are equivalent.
    List ordering is non-semantic and is canonicalized recursively.
    """
    capability = str(capability_id or '').strip()
    if not capability:
        raise ValueError('capability_id is required for semantic parity')
    if not isinstance(legacy_normalized, dict) or not isinstance(candidate_normalized, dict):
        raise ValueError('normalized parity inputs must be JSON objects')

    legacy_observations = _normalized_observations(legacy_normalized)
    candidate_observations = _normalized_observations(candidate_normalized)
    legacy_findings = _finding_specs(capability, legacy_normalized)
    candidate_findings = _finding_specs(capability, candidate_normalized)

    legacy_observation_digest = _digest(legacy_observations)
    candidate_observation_digest = _digest(candidate_observations)
    legacy_finding_digest = _digest(legacy_findings)
    candidate_finding_digest = _digest(candidate_findings)

    observation_equivalent = legacy_observation_digest == candidate_observation_digest
    finding_applicable = _finding_projection_applicable(capability)
    finding_equivalent = legacy_finding_digest == candidate_finding_digest
    mismatches: list[str] = []
    if not observation_equivalent:
        mismatches.append('normalized-observation-drift')
    if not finding_equivalent:
        mismatches.append('finding-projection-drift')

    return SemanticParityReport(
        schema=PARITY_SCHEMA,
        capability_id=capability,
        semantic_equivalent=observation_equivalent and finding_equivalent,
        observation_equivalent=observation_equivalent,
        finding_projection_applicable=finding_applicable,
        finding_projection_equivalent=finding_equivalent,
        legacy_observation_digest=legacy_observation_digest,
        candidate_observation_digest=candidate_observation_digest,
        legacy_finding_digest=legacy_finding_digest,
        candidate_finding_digest=candidate_finding_digest,
        legacy_observation_count=len(legacy_observations),
        candidate_observation_count=len(candidate_observations),
        legacy_finding_count=len(legacy_findings),
        candidate_finding_count=len(candidate_findings),
        mismatches=tuple(mismatches),
    )

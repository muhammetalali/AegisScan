from __future__ import annotations

from fastapi_app.contracts.governed_operations import ActionMode
from fastapi_app.services.entity_capability_adapters import (
    EntityCapabilityNotFound,
    build_entity_capability_manifest,
)
from fastapi_app.services.governed_operations import get_action_contract

from django_project.vulnerabilities.models import Vulnerability


def build_governed_capability_manifest(
    *,
    project_id: str,
    user_id: str,
    entity_type: str,
    entity_id: str,
    request_proposer_id: str = '',
    execution_parameters: dict | None = None,
):
    """Return the authoritative capability manifest with durable CAS state.

    Authority, responsibilities, SoD, evidence and gates remain owned by the
    entity capability adapters. This bridge only binds entity-specific durable
    concurrency/state fields that must be visible to both execution and UX.
    """
    manifest = build_entity_capability_manifest(
        project_id=project_id,
        user_id=user_id,
        entity_type=entity_type,
        entity_id=entity_id,
        request_proposer_id=request_proposer_id,
        execution_parameters=execution_parameters,
    )
    normalized_type = str(entity_type or '').strip().lower()
    if normalized_type != 'finding':
        return manifest

    finding = (
        Vulnerability.objects.only('id', 'project_id', 'status', 'version')
        .filter(pk=entity_id, project_id=project_id)
        .first()
    )
    if finding is None:
        raise EntityCapabilityNotFound('Entity capability target not found.')

    lifecycle = manifest.projection.lifecycle
    if finding.status == Vulnerability.Status.FIXED:
        lifecycle = 'closed'

    projection = manifest.projection.model_copy(update={
        'lifecycle': lifecycle,
        'version': int(finding.version),
    })

    # The base Finding adapter historically prioritizes a VERIFIED remediation
    # observation over FIXED. Once closure commits, the durable Finding status
    # is authoritative and the same close action must become blocked. Preserve
    # hidden authority decisions while correcting state eligibility.
    capabilities = []
    for item in manifest.capabilities:
        contract = get_action_contract(item.action_id)
        if (
            contract is not None
            and item.mode is not ActionMode.HIDDEN
            and str(lifecycle or '') not in contract.allowed_states
        ):
            item = item.model_copy(update={
                'mode': ActionMode.BLOCKED,
                'reason_code': 'STATE_PRECONDITION_UNMET',
                'reason': 'Entity lifecycle state does not satisfy the action precondition.',
                'missing_requirements': [f'state in {contract.allowed_states}'],
            })
        capabilities.append(item)

    return manifest.model_copy(update={
        'projection': projection,
        'capabilities': capabilities,
    })

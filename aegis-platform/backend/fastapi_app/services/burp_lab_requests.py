"""Pinned GET-only BAC recipe; target credentials never become provider tokens."""
from __future__ import annotations

import hashlib
import json
import re

from django_project.system.credential_models import CredentialSecret
from django_project.system.credential_vault import CredentialVaultDenied
from .burp_http_probe import health_request_arguments
from .credential_execution import (
    authorize_credential_refs_for_execution, resolve_credential_refs_for_worker,
)

LAB_ID = 'bac-orders-v1'
FIXTURE_SHA256 = '4213a578e2751c6cbe22cc3d1166b2bfed2e89860f33b63b90b14f470800fef0'
# A caller chooses a step identifier, never a method, header, body, URL or path.
STEPS = {
    'owner_baseline': ('alice', '/vulnerable/orders/51'),
    'cross_owner_positive': ('alice', '/vulnerable/orders/74'),
    'patched_negative': ('alice', '/fixed/orders/74'),
    'patched_owner_baseline': ('bob', '/fixed/orders/74'),
    'anonymous_negative': ('anonymous', '/vulnerable/orders/74'),
    'owner_recheck': ('alice', '/vulnerable/orders/51'),
}


def lab_bindings(*, project_id, actor_id, target, refs):
    if not isinstance(refs, list) or len(refs) != 2 or len(set(refs)) != 2:
        raise CredentialVaultDenied('The BAC recipe requires two distinct target credential references.')
    rows = {str(c.id): c for c in CredentialSecret.objects.filter(project_id=project_id, id__in=refs)}
    bindings = {}
    for ref in refs:
        credential = rows.get(ref)
        scope = credential.scope if credential and isinstance(credential.scope, dict) else {}
        identity = scope.get('browser_identity_ref')
        if not credential or not isinstance(identity, str) or identity not in {'alice', 'bob'} or identity in bindings:
            raise CredentialVaultDenied('BAC target identities must bind Alice and Bob in the current project.')
        context = authorize_credential_refs_for_execution(
            project_id=project_id, actor_id=actor_id, refs=[ref], capability_id='burp.mcp.gateway',
            allowed_kinds=(CredentialSecret.Kind.TOKEN, CredentialSecret.Kind.GENERIC),
            purpose='burp-mcp:target-identity', target=target, identity_ref=identity,
        )
        bindings[identity] = {'credential_ref': ref, 'version': context['credential_refs'][0]['version']}
    return bindings


def validate_lab_bindings(session, actor_id):
    contract = session.contract_snapshot.get('lab')
    if not isinstance(contract, dict):
        raise CredentialVaultDenied('No BAC identity contract is bound to this session.')
    if (contract.get('definition_id') != LAB_ID or contract.get('fixture_revision') != FIXTURE_SHA256
            or contract.get('attempt_ref') != str(session.scan_id)):
        raise CredentialVaultDenied('The BAC attempt or fixture definition binding changed.')
    identities = contract.get('identities')
    if not isinstance(identities, dict) or set(identities) != {'alice', 'bob'}:
        raise CredentialVaultDenied('BAC identities are not bound to the session.')
    refs = [identities[name]['credential_ref'] for name in ['alice', 'bob']]
    if lab_bindings(project_id=str(session.project_id), actor_id=actor_id,
                    target=session.target_snapshot, refs=refs) != identities:
        raise CredentialVaultDenied('BAC identity versions or scope changed; start a new governed attempt.')
    return contract


def lab_request(*, session, actor_id, step):
    if step not in STEPS:
        raise ValueError('Unknown BAC recipe step.')
    contract = validate_lab_bindings(session, actor_id)
    identity, path = STEPS[step]
    arguments = health_request_arguments(session.target_snapshot)
    content = arguments['content'].replace('GET /health HTTP/1.1', f'GET {path} HTTP/1.1', 1)
    materials = ()
    if identity != 'anonymous':
        binding = contract['identities'][identity]
        materials, context = resolve_credential_refs_for_worker(
            project_id=str(session.project_id), actor_id=actor_id, refs=[binding['credential_ref']],
            capability_id='burp.mcp.gateway', allowed_kinds=(CredentialSecret.Kind.TOKEN, CredentialSecret.Kind.GENERIC),
            purpose='burp-mcp:target-request', target=session.target_snapshot, identity_ref=identity,
        )
        if context['credential_refs'][0]['version'] != binding['version']:
            raise CredentialVaultDenied('Target credential rotated during request preparation.')
        token = materials[0]['secret']
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9._~+/=-]{1,2048}', token):
            raise CredentialVaultDenied('Target bearer material has an unsupported bounded format.')
        content = content.replace('Accept: application/json\r\n', f'Accept: application/json\r\nAuthorization: Bearer {token}\r\n', 1)
    return {**arguments, 'content': content}, materials


def summarize_lab_result(payload, *, request_arguments, session, step):
    result = payload.get('mcp_result')
    blocks = result.get('content') if isinstance(result, dict) else None
    if (not isinstance(blocks, list) or len(blocks) != 1 or not isinstance(blocks[0], dict)
            or blocks[0].get('type') != 'text' or not isinstance(blocks[0].get('text'), str)):
        raise ValueError('No unambiguous bounded HTTP response.')
    raw = blocks[0]['text']
    if len(raw.encode()) > 1_048_576:
        raise ValueError('HTTP response exceeds the recipe limit.')
    response = raw
    if raw.startswith('HttpRequestResponse{'):
        prefix = 'HttpRequestResponse{httpRequest=' + request_arguments['content'] + ', httpResponse='
        suffix = ", messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
        if not raw.startswith(prefix) or not raw.endswith(suffix):
            raise ValueError('Provider wrapper does not bind the exact governed request.')
        response = raw[len(prefix):-len(suffix)]
    head, sep, body = response.partition('\r\n\r\n')
    if not sep:
        head, sep, body = response.partition('\n\n')
    first = head.splitlines()[0].split(' ', 2) if head else []
    if (not sep or len(first) < 2 or first[0] not in {'HTTP/1.0', 'HTTP/1.1', 'HTTP/2'}
            or not first[1].isdigit() or not 100 <= int(first[1]) <= 599):
        raise ValueError('Malformed HTTP response.')
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    resource = None
    if (isinstance(data, dict) and all(isinstance(data.get(k), str) for k in ('id', 'owner_id', 'tenant_id'))
            and data.get('id') in {'51', '74'}
            and data.get('owner_id') in {'alice', 'bob'} and data.get('tenant_id') in {'tenant-a', 'tenant-b'}):
        resource = {key: data[key] for key in ['id', 'owner_id', 'tenant_id']}
    identity, path = STEPS[step]
    return {
        'schema': 'aegis.burp-lab-observation.v1', 'attempt_ref': str(session.scan_id),
        'step_ref': step, 'action_ref': 'GET:' + path, 'identity_ref': identity,
        'target_ref': str(session.asset_id), 'definition_id': LAB_ID,
        'fixture_revision': FIXTURE_SHA256, 'live_fixture_revision_verified': False,
        'status_code': int(first[1]), 'resource': resource,
        'response_sha256': hashlib.sha256(response.encode()).hexdigest(),
        'wire_request_sha256': hashlib.sha256(request_arguments['content'].encode()).hexdigest(),
        'transport_metadata': payload['transport_metadata'],
        'raw_request_response_persisted': False, 'lab_solved': False,
        'verdict': 'observation_only',
    }

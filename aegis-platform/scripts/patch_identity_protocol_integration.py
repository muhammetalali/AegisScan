from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / 'aegis-platform/backend/enterprise/web_security_models.py'
ROUTER = ROOT / 'aegis-platform/backend/fastapi_app/routers/web_security.py'


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding='utf-8')
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f'expected integration anchor missing in {path}: {old!r}')
    path.write_text(text.replace(old, new, 1), encoding='utf-8')


def append_once(path: Path, marker: str, block: str) -> None:
    text = path.read_text(encoding='utf-8')
    if marker in text:
        return
    path.write_text(text.rstrip() + '\n\n' + block.strip() + '\n', encoding='utf-8')


def main() -> None:
    replace_once(
        MODEL,
        "        CROSS_PROTOCOL = 'cross_protocol', 'Cross-Protocol State'\n",
        "        CROSS_PROTOCOL = 'cross_protocol', 'Cross-Protocol State'\n"
        "        IDENTITY_PROTOCOL_SECURITY = 'identity_protocol_security', 'Identity Protocol Security'\n",
    )

    replace_once(
        ROUTER,
        "from fastapi_app.core.dependencies import get_current_user\n",
        "from fastapi_app.contracts.identity_protocol_security import IdentityProtocolBatchIn\n"
        "from fastapi_app.core.dependencies import get_current_user\n",
    )
    replace_once(
        ROUTER,
        "from fastapi_app.services.credential_execution import authorize_credential_refs_for_execution\n",
        "from fastapi_app.services.credential_execution import authorize_credential_refs_for_execution\n"
        "from fastapi_app.services.identity_protocol_security import run_identity_protocol_security\n",
    )
    replace_once(
        ROUTER,
        "            'cross_protocol_state_validation': True,\n",
        "            'cross_protocol_state_validation': True,\n"
        "            'identity_protocol_security': True,\n",
    )

    append_once(
        ROUTER,
        "async def evaluate_identity_protocol_security(",
        '''
@router.post('/projects/{project_id}/identity-protocols/evaluate')
async def evaluate_identity_protocol_security(
    project_id: str,
    payload: IdentityProtocolBatchIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    cases = [item.model_dump(mode='json') for item in payload.cases]
    governance = await _protocol_budget_governance(
        project,
        payload.budget_id,
        capability='identity_protocol_security',
        cases=cases,
    )
    credential_bindings = await _protocol_credential_governance(
        project,
        uid,
        capability_id='identity-protocol.security-validation',
        target_origin=payload.target_origin,
        cases=cases,
    )
    governance = {**governance, 'credential_bindings': credential_bindings}
    run, observations = await sync_to_async(run_identity_protocol_security)(
        project,
        uid,
        cases,
        governance,
    )
    return {
        'contract_version': CONTRACT_VERSION,
        'run_id': str(run.id),
        'kind': run.kind,
        'input_sha256': run.input_sha256,
        'summary': run.summary,
        'observations': [_protocol_observation_dict(item) for item in observations],
    }
''',
    )


if __name__ == '__main__':
    main()

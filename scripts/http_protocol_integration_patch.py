from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if new in text:
        return
    if old not in text:
        raise SystemExit(f'patch anchor missing: {path}: {old!r}')
    path.write_text(text.replace(old, new, 1))


models = ROOT / 'aegis-platform/backend/enterprise/web_security_models.py'
replace_once(
    models,
    "        IDENTITY_PROTOCOL_SECURITY = 'identity_protocol_security', 'Identity Protocol Security'\n",
    "        IDENTITY_PROTOCOL_SECURITY = 'identity_protocol_security', 'Identity Protocol Security'\n        HTTP_PROTOCOL_SECURITY = 'http_protocol_security', 'HTTP Protocol Security'\n",
)

credentials = ROOT / 'aegis-platform/backend/fastapi_app/services/credential_execution.py'
replace_once(
    credentials,
    "    'identity-protocol.security-validation',\n}",
    "    'identity-protocol.security-validation',\n    'http-protocol.security-validation',\n}",
)

router = ROOT / 'aegis-platform/backend/fastapi_app/routers/web_security.py'
replace_once(
    router,
    'from fastapi_app.contracts.identity_protocol_security import IdentityProtocolBatchIn\n',
    'from fastapi_app.contracts.identity_protocol_security import IdentityProtocolBatchIn\nfrom fastapi_app.contracts.http_protocol_security import HttpProtocolBatchIn\n',
)
replace_once(
    router,
    'from fastapi_app.services.identity_protocol_security import run_identity_protocol_security\n',
    'from fastapi_app.services.identity_protocol_security import run_identity_protocol_security\nfrom fastapi_app.services.http_protocol_security import run_http_protocol_security\n',
)
route = '''

@router.post('/projects/{project_id}/http-protocol/evaluate')
async def evaluate_http_protocol_security(
    project_id: str,
    payload: HttpProtocolBatchIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    cases = [item.model_dump(mode='json') for item in payload.cases]
    governance = await _protocol_budget_governance(
        project, payload.budget_id, capability='http_protocol_security', cases=cases,
    )
    credential_bindings = await _protocol_credential_governance(
        project, uid, capability_id='http-protocol.security-validation',
        target_origin=payload.target_origin, cases=cases,
    )
    governance = {**governance, 'credential_bindings': credential_bindings}
    run, observations = await sync_to_async(run_http_protocol_security)(project, uid, cases, governance)
    return {
        'contract_version': CONTRACT_VERSION,
        'run_id': str(run.id),
        'kind': run.kind,
        'input_sha256': run.input_sha256,
        'summary': run.summary,
        'observations': [_protocol_observation_dict(item) for item in observations],
    }
'''
text = router.read_text()
if "'/projects/{project_id}/http-protocol/evaluate'" not in text:
    router.write_text(text.rstrip() + route.rstrip() + '\n')

# Bootstrap files are intentionally self-removing so they never remain in the product tree.
(ROOT / '.github/workflows/http-protocol-bootstrap.yml').unlink(missing_ok=True)
Path(__file__).unlink(missing_ok=True)

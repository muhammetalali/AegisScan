from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_lab_scope_is_single_canonical_boundary():
    scope = (ROOT / 'aegis-platform/backend/fastapi_app/services/scope_authorization.py').read_text(encoding='utf-8')
    prod = (ROOT / 'aegis-platform/docker-compose.prod.yml').read_text(encoding='utf-8')
    egress = (ROOT / 'aegis-platform/docker/scanner-egress/entrypoint.sh').read_text(encoding='utf-8')
    secret_init = (ROOT / 'aegis-platform/scripts/production_secret_init.py').read_text(encoding='utf-8')

    assert "AEGIS_LAB_NETWORK_CIDRS" in scope
    assert "AEGIS_LAB_NETWORK_CIDRS" in prod
    assert "AEGIS_LAB_NETWORK_CIDRS" in egress
    assert '"AEGIS_LAB_NETWORK_CIDRS"' in secret_init
    assert 'for target in $LAB_NETWORKS' in egress


def test_manual_validation_authorization_friction_is_removed():
    api = (ROOT / 'aegis-platform/backend/fastapi_app/routers/validations.py').read_text(encoding='utf-8')
    remediation = (ROOT / 'aegis-platform/backend/fastapi_app/routers/remediation.py').read_text(encoding='utf-8')
    ui = (ROOT / 'aegis-platform/frontend/src/pages/validations/NewValidation.tsx').read_text(encoding='utf-8')
    assets_ui = (ROOT / 'aegis-platform/frontend/src/pages/assets/Assets.tsx').read_text(encoding='utf-8')
    finding_ui = (ROOT / 'aegis-platform/frontend/src/pages/vulnerabilities/VulnerabilityDetail.tsx').read_text(encoding='utf-8')
    findings_ui = (ROOT / 'aegis-platform/frontend/src/pages/vulnerabilities/Vulnerabilities.tsx').read_text(encoding='utf-8')

    assert 'authorized must be true for real security execution' not in api
    assert 'authorized must be true for offensive validation execution' not in api
    assert 'authorized must be true for real remediation validation' not in remediation
    assert "asset_config.get('authorized')" not in remediation
    assert 'authorization_decision=decision' in remediation
    assert 'I confirm this target is authorized for security validation.' not in ui
    assert 'Inherited from asset policy' in ui
    assert 'authorized:true' not in assets_ui
    assert 'authorized: true' not in finding_ui
    assert 'authorized:true' not in findings_ui

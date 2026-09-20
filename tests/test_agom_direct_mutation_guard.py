from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ci" / "agom_direct_mutation_guard.py"
SPEC = importlib.util.spec_from_file_location("agom_direct_mutation_guard", MODULE_PATH)
assert SPEC and SPEC.loader
guard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = guard
SPEC.loader.exec_module(guard)


def codes(source: str, path: str = "aegis-platform/backend/fastapi_app/routers/example.py") -> set[str]:
    return {item.code for item in guard.scan_source(source, path)}


def test_rejects_immutable_ledger_write_outside_owner():
    source = """
from django_project.assets.models import AssetAuthorization
AssetAuthorization.objects.create(asset_id='1', authorized=True)
"""
    assert "AGOM-LEDGER-WRITE" in codes(source)


def test_allows_immutable_ledger_write_in_canonical_owner():
    source = """
from django_project.assets.models import AssetAuthorization
AssetAuthorization.objects.create(asset_id='1', authorized=True)
"""
    path = "aegis-platform/backend/fastapi_app/services/asset_authorization_governance.py"
    assert guard.scan_source(source, path) == []


def test_rejects_terminal_finding_status_assignment_outside_owner():
    source = """
terminal = Vulnerability.Status.FIXED
finding.status = terminal
finding.save(update_fields=['status'])
"""
    assert "AGOM-DIRECT-STATUS" in codes(source)


def test_local_terminal_constant_without_domain_write_is_not_a_violation():
    source = "terminal = Vulnerability.Status.FIXED"
    assert "AGOM-DIRECT-STATUS" not in codes(source)


def test_rejects_generic_remediation_closed_invocation():
    source = "transition(validation.id, RemediationState.CLOSED, reason='bypass')"
    assert "AGOM-REMEDIATION-CLOSE" in codes(source)


def test_rejects_asset_authorization_projection_mutation():
    source = """
configuration = dict(asset.configuration or {})
configuration['authorized'] = True
asset.configuration = configuration
"""
    result = codes(source)
    assert "AGOM-ASSET-AUTH-PROJECTION" in result
    assert "AGOM-ASSET-CONFIG-REPLACE" in result


def test_current_repository_has_no_direct_mutation_bypass():
    violations = guard.scan_repo(ROOT)
    assert violations == [], "\n".join(item.render() for item in violations)



def test_rejects_campaign_completion_outside_campaign_governance_owner():
    source = """
campaign.status = AdversaryCampaign.Status.COMPLETED
campaign.save(update_fields=['status'])
"""
    assert "AGOM-DIRECT-STATUS" in codes(source)


def test_allows_campaign_completion_in_canonical_owner():
    source = """
campaign.status = AdversaryCampaign.Status.COMPLETED
campaign.save(update_fields=['status'])
"""
    path = "aegis-platform/backend/fastapi_app/services/campaign_objective_assurance.py"
    assert guard.scan_source(source, path) == []



def test_rejects_asset_hard_delete_outside_authoritative_owner():
    source = """
asset = get_asset()
asset.delete()
"""
    assert "AGOM-ASSET-HARD-DELETE" in codes(source)


def test_allows_asset_hard_delete_in_authoritative_owner():
    source = """
asset = get_asset()
asset.delete()
"""
    path = "aegis-platform/backend/fastapi_app/services/asset_authorization_governance.py"
    assert guard.scan_source(source, path) == []

import pytest
from django.db import close_old_connections
from fastapi.testclient import TestClient

from django_project.intelligence.models import IntelligenceEnrichment
from django_project.users.models import User
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.main import app

pytestmark = pytest.mark.django_db(transaction=True)


def test_live_cve_enrichment_persists_provenance():
    user = User.objects.create_user(email='intelligence-e2e@example.invalid', password='Strong-Test-Password-123!')
    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(user.id)}
    try:
        with TestClient(app) as client:
            response = client.get('/api/v1/intelligence/cve/CVE-2021-44228')
    finally:
        app.dependency_overrides.clear()
        close_old_connections()

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload['live'] is True
    assert payload['persisted'] is True
    assert payload['cve_id'] == 'CVE-2021-44228'
    assert payload['snapshot_sha256']
    assert payload['source_urls']['nvd'].startswith('https://services.nvd.nist.gov/')
    assert payload['source_urls']['epss'].startswith('https://api.first.org/')

    snapshot = IntelligenceEnrichment.objects.get(pk=payload['id'])
    assert snapshot.cve_id == payload['cve_id']
    assert snapshot.snapshot_sha256 == payload['snapshot_sha256']
    assert snapshot.observed_by_id == user.id
    assert 'nvd' in snapshot.sources
    assert 'epss' in snapshot.sources
    assert snapshot.source_urls == payload['source_urls']


def test_unauthenticated_live_intelligence_is_rejected():
    try:
        with TestClient(app) as client:
            response = client.get('/api/v1/intelligence/cve/CVE-2021-44228')
    finally:
        close_old_connections()
    assert response.status_code in {401, 403}

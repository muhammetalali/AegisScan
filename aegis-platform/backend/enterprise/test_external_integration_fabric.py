import json
from types import SimpleNamespace

import pytest

from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.integrations import send_integration
from enterprise.models import (
    ExternalIntegration,
    ExternalIntelligenceSnapshot,
    IntegrationSyncRun,
    Organization,
    PluginPackage,
    TenantProject,
)
from fastapi_app.services import external_fabric
from fastapi_app.services.external_fabric import (
    ExternalFabricError,
    activate_plugin_package,
    approve_plugin_package,
    auto_update_plugin_package,
    dynamic_plugin_capabilities,
    fetch_indicator_intelligence,
    register_plugin_package,
    resolve_plugin_dependencies,
    sync_external_integration,
)


def _tenant():
    user=User.objects.create_user(username='fabric-user',email='fabric@example.com',password='Passw0rd!fabric')
    project=Project.objects.create(name='Fabric Project',slug='fabric-project',owner=user)
    organization=Organization.objects.create(name='Fabric Org',slug='fabric-org',owner=user)
    TenantProject.objects.create(organization=organization,project=project)
    return user,project,organization


@pytest.mark.django_db
def test_plugin_dependency_resolution_dynamic_delegation_and_auto_update():
    foundation=register_plugin_package(
        name='foundation',version='1.2.0',source='https://plugins.example.com/foundation-1.2.0.json',
        digest='a'*64,manifest={'capabilities':[]},dependencies=[],
    )
    approve_plugin_package(str(foundation.id))
    activate_plugin_package(str(foundation.id))

    first=register_plugin_package(
        name='network-extension',version='1.0.0',source='https://plugins.example.com/network-extension-1.0.0.json',
        digest='b'*64,
        manifest={'capabilities':[{'id':'plugin.network.discovery','delegate':'network.nmap','description':'Governed Nmap delegation'}]},
        dependencies=[{'name':'foundation','specifier':'>=1,<2'}],
    )
    approve_plugin_package(str(first.id))
    activate_plugin_package(str(first.id))
    resolution=resolve_plugin_dependencies(first)
    assert resolution['dependencies']['foundation']=='1.2.0'
    assert dynamic_plugin_capabilities()[0]['delegate']=='network.nmap'

    latest=register_plugin_package(
        name='network-extension',version='1.1.0',source='https://plugins.example.com/network-extension-1.1.0.json',
        digest='c'*64,
        manifest={'capabilities':[{'id':'plugin.network.discovery','delegate':'network.nmap'}]},
        dependencies=[{'name':'foundation','specifier':'>=1.2,<2'}],
    )
    approve_plugin_package(str(latest.id))
    selected=auto_update_plugin_package('network-extension')
    assert selected.version=='1.1.0'
    assert PluginPackage.objects.get(pk=first.pk).enabled is False
    assert PluginPackage.objects.get(pk=latest.pk).enabled is True


@pytest.mark.django_db
def test_plugin_rejects_shadowing_and_unsatisfied_dependency():
    with pytest.raises(ExternalFabricError,match='cannot shadow'):
        register_plugin_package(
            name='shadow',version='1.0.0',source='https://plugins.example.com/shadow.json',
            digest='d'*64,manifest={'capabilities':[{'id':'network.nmap','delegate':'network.nmap'}]},dependencies=[],
        )

    package=register_plugin_package(
        name='needs-missing',version='1.0.0',source='https://plugins.example.com/missing.json',
        digest='e'*64,manifest={'capabilities':[]},
        dependencies=[{'name':'missing-base','specifier':'>=2'}],
    )
    approve_plugin_package(str(package.id))
    with pytest.raises(ExternalFabricError,match='Unsatisfied plugin dependency'):
        activate_plugin_package(str(package.id))


@pytest.mark.django_db
def test_shodan_indicator_intelligence_is_persisted_and_hashed(monkeypatch):
    user,_,_=_tenant()
    monkeypatch.setenv('SHODAN_API_KEY','test-shodan-key')
    monkeypatch.setattr(external_fabric,'_request_json',lambda *args,**kwargs:{'ip_str':'203.0.113.10','ports':[443]})
    snapshot=fetch_indicator_intelligence(provider='shodan',indicator='203.0.113.10',actor_id=str(user.id))
    assert snapshot.provider==ExternalIntelligenceSnapshot.Provider.SHODAN
    assert snapshot.data['ports']==[443]
    assert len(snapshot.snapshot_sha256)==64
    assert snapshot.observed_by_id==user.id


@pytest.mark.django_db
def test_censys_credentials_are_structured_and_greynoise_supported(monkeypatch):
    user,_,_=_tenant()
    monkeypatch.setenv('CENSYS_API_CREDENTIALS',json.dumps({'api_id':'id','api_secret':'secret'}))
    monkeypatch.setenv('GREYNOISE_API_KEY','grey-key')
    calls=[]
    def fake_request(method,url,**kwargs):
        calls.append((url,kwargs))
        return {'ok':True}
    monkeypatch.setattr(external_fabric,'_request_json',fake_request)
    censys=fetch_indicator_intelligence(provider='censys',indicator='198.51.100.5',actor_id=str(user.id))
    greynoise=fetch_indicator_intelligence(provider='greynoise',indicator='198.51.100.5',actor_id=str(user.id))
    assert censys.provider=='censys' and greynoise.provider=='greynoise'
    assert any(call[1].get('auth')==('id','secret') for call in calls)
    assert any(call[1].get('headers',{}).get('key')=='grey-key' for call in calls)


@pytest.mark.django_db
def test_repository_sync_is_durable_and_tenant_bound(monkeypatch):
    user,project,organization=_tenant()
    integration=ExternalIntegration.objects.create(
        organization=organization,kind=ExternalIntegration.Kind.GITHUB,name='GitHub',
        base_url='https://api.github.com',secret_ref='GITHUB_SYNC_TOKEN',created_by=user,
    )
    monkeypatch.setattr(
        external_fabric,'_github_repositories',
        lambda item:[
            {'id':'1','name':'org/repo-one','url':'https://github.com/org/repo-one'},
            {'id':'2','name':'org/repo-two','url':'https://github.com/org/repo-two'},
        ],
    )
    run=sync_external_integration(integration_id=str(integration.id),project=project,user_id=str(user.id))
    assert run.status=='completed'
    assert run.records_count==2
    assert run.summary['records'][0]['name']=='org/repo-one'


@pytest.mark.django_db
def test_sentinel_qradar_and_soar_delivery_contracts(monkeypatch):
    user,_,organization=_tenant()
    monkeypatch.setenv('FABRIC_TOKEN','token-value')
    calls=[]
    class Response:
        status_code=202
        def raise_for_status(self): return None
    def fake_post(url,**kwargs):
        calls.append((url,kwargs))
        return Response()
    monkeypatch.setattr('enterprise.integrations.requests.post',fake_post)

    sentinel=ExternalIntegration.objects.create(
        organization=organization,kind=ExternalIntegration.Kind.SENTINEL,name='Sentinel',
        base_url='https://sentinel.example.com',secret_ref='FABRIC_TOKEN',
        config={'ingest_path':'dataCollectionRules/dcr/streams/Custom-Aegis?api-version=2023-01-01'},created_by=user,
    )
    qradar=ExternalIntegration.objects.create(
        organization=organization,kind=ExternalIntegration.Kind.QRADAR,name='QRadar',
        base_url='https://qradar.example.com',secret_ref='FABRIC_TOKEN',
        config={'ingest_path':'api/custom/aegis-events'},created_by=user,
    )
    soar=ExternalIntegration.objects.create(
        organization=organization,kind=ExternalIntegration.Kind.SOAR_WEBHOOK,name='SOAR',
        base_url='https://soar.example.com/hooks/aegis',secret_ref='FABRIC_TOKEN',created_by=user,
    )
    assert send_integration(sentinel,{'type':'finding'})['http_status']==202
    assert send_integration(qradar,{'type':'finding'})['http_status']==202
    assert send_integration(soar,{'type':'finding'})['http_status']==202
    assert calls[0][1]['headers']['Authorization']=='Bearer token-value'
    assert calls[1][1]['headers']['SEC']=='token-value'
    assert calls[2][1]['headers']['Authorization']=='Bearer token-value'


@pytest.mark.django_db
def test_failed_repository_sync_persists_failure_evidence(monkeypatch):
    user,project,organization=_tenant()
    integration=ExternalIntegration.objects.create(
        organization=organization,kind=ExternalIntegration.Kind.GITHUB,name='GitHub failure',
        base_url='https://api.github.com',secret_ref='GITHUB_SYNC_TOKEN',created_by=user,
    )
    monkeypatch.setattr(
        external_fabric,'_github_repositories',
        lambda item: (_ for _ in ()).throw(ExternalFabricError('provider unavailable')),
    )
    with pytest.raises(ExternalFabricError,match='provider unavailable'):
        sync_external_integration(integration_id=str(integration.id),project=project,user_id=str(user.id))
    run=IntegrationSyncRun.objects.get(integration=integration,project=project)
    assert run.status==IntegrationSyncRun.Status.FAILED
    assert 'provider unavailable' in run.error_message
    assert run.completed_at is not None


@pytest.mark.django_db
def test_due_connector_dispatch_queues_project_bound_sync(monkeypatch):
    from enterprise import tasks
    user,project,organization=_tenant()
    integration=ExternalIntegration.objects.create(
        organization=organization,kind=ExternalIntegration.Kind.GHCR,name='GHCR',
        base_url='https://ghcr.io',secret_ref='GHCR_TOKEN',
        config={'auto_sync_minutes':5},created_by=user,
    )
    queued=[]
    monkeypatch.setattr(
        tasks.sync_external_integration_task,
        'delay',
        lambda integration_id,project_id,user_id: SimpleNamespace(
            id=(queued.append((integration_id,project_id,user_id)) or 'task-1')
        ),
    )
    result=tasks.dispatch_due_integration_syncs(limit=10)
    assert result['queued']==1
    assert queued==[(str(integration.id),str(project.id),str(user.id))]

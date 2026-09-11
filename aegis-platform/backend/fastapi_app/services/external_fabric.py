from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import httpx
from django.db import transaction
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from enterprise.models import (
    ExternalIntegration,
    ExternalIntelligenceSnapshot,
    IntegrationSyncRun,
    PluginPackage,
)


class ExternalFabricError(RuntimeError):
    pass


_HTTP_TIMEOUT=httpx.Timeout(15.0,connect=5.0)


def _secret(ref: str) -> str:
    if not ref:
        return ''
    value=os.getenv(ref)
    if not value:
        raise ExternalFabricError(f'Integration secret environment variable is not configured: {ref}')
    return value


def _canonical(payload: Any) -> bytes:
    return json.dumps(payload,sort_keys=True,separators=(',',':'),default=str).encode('utf-8')


def _request_json(
    method: str,
    url: str,
    *,
    headers: dict[str,str]|None=None,
    params: dict[str,Any]|None=None,
    auth: tuple[str,str]|None=None,
) -> dict[str,Any]:
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT,follow_redirects=False) as client:
            response=client.request(method,url,headers=headers,params=params,auth=auth)
            response.raise_for_status()
            payload=response.json()
    except (httpx.HTTPError,ValueError) as exc:
        raise ExternalFabricError(f'External provider request failed: {url}') from exc
    if not isinstance(payload,dict):
        raise ExternalFabricError(f'External provider returned non-object JSON: {url}')
    return payload


@transaction.atomic
def fetch_indicator_intelligence(*,provider:str,indicator:str,actor_id:str|None=None) -> ExternalIntelligenceSnapshot:
    try:
        address=str(ipaddress.ip_address(indicator.strip()))
    except ValueError as exc:
        raise ExternalFabricError('Shodan/Censys/GreyNoise indicator must be a valid IP address') from exc

    provider=provider.strip().lower()
    headers={'Accept':'application/json'}
    auth=None
    params=None
    if provider==ExternalIntelligenceSnapshot.Provider.SHODAN:
        token=_secret('SHODAN_API_KEY')
        url=f'https://api.shodan.io/shodan/host/{address}'
        params={'key':token}
    elif provider==ExternalIntelligenceSnapshot.Provider.CENSYS:
        raw=_secret('CENSYS_API_CREDENTIALS')
        try:
            credentials=json.loads(raw)
            auth=(str(credentials['api_id']),str(credentials['api_secret']))
        except (ValueError,KeyError,TypeError) as exc:
            raise ExternalFabricError('CENSYS_API_CREDENTIALS must be JSON containing api_id and api_secret') from exc
        url=f'https://search.censys.io/api/v2/hosts/{address}'
    elif provider==ExternalIntelligenceSnapshot.Provider.GREYNOISE:
        token=_secret('GREYNOISE_API_KEY')
        headers['key']=token
        url=f'https://api.greynoise.io/v3/community/{address}'
    else:
        raise ExternalFabricError(f'Unsupported external intelligence provider: {provider}')

    data=_request_json('GET',url,headers=headers,params=params,auth=auth)
    observed_at=datetime.now(timezone.utc)
    digest=hashlib.sha256(_canonical({'provider':provider,'indicator':address,'data':data,'source_url':url,'observed_at':observed_at.isoformat()})).hexdigest()
    return ExternalIntelligenceSnapshot.objects.create(
        provider=provider,indicator=address,data=data,source_url=url,snapshot_sha256=digest,
        observed_by_id=actor_id,observed_at=observed_at,
    )


def _normalize_dependencies(dependencies: list[dict[str,Any]]) -> list[dict[str,str]]:
    normalized=[]
    seen=set()
    for item in dependencies:
        if not isinstance(item,dict):
            raise ExternalFabricError('Plugin dependencies must be objects')
        name=str(item.get('name') or '').strip()
        specifier=str(item.get('specifier') or '').strip()
        if not name or name in seen:
            raise ExternalFabricError('Plugin dependency names must be non-empty and unique')
        try:
            SpecifierSet(specifier)
        except InvalidSpecifier as exc:
            raise ExternalFabricError(f'Invalid dependency specifier for {name}: {specifier}') from exc
        normalized.append({'name':name,'specifier':specifier})
        seen.add(name)
    return normalized


def _validate_plugin_manifest(manifest: dict[str,Any]) -> dict[str,Any]:
    if not isinstance(manifest,dict):
        raise ExternalFabricError('Plugin manifest must be an object')
    capabilities=manifest.get('capabilities') or []
    if not isinstance(capabilities,list) or len(capabilities)>128:
        raise ExternalFabricError('Plugin capabilities must be an array with at most 128 entries')
    normalized=[]
    ids=set()
    from fastapi_app.services.capability_registry import get_capability
    for item in capabilities:
        if not isinstance(item,dict):
            raise ExternalFabricError('Plugin capability entries must be objects')
        capability_id=str(item.get('id') or '').strip()
        delegate=str(item.get('delegate') or '').strip()
        if not capability_id or not delegate or capability_id in ids:
            raise ExternalFabricError('Plugin capability requires unique id and delegate')
        try:
            get_capability(delegate)
        except ValueError as exc:
            raise ExternalFabricError(f'Plugin capability delegates to unknown built-in capability: {delegate}') from exc
        try:
            get_capability(capability_id)
        except ValueError:
            pass
        else:
            raise ExternalFabricError(f'Plugin capability cannot shadow built-in capability: {capability_id}')
        normalized.append({
            'id':capability_id,
            'delegate':delegate,
            'description':str(item.get('description') or '')[:500],
        })
        ids.add(capability_id)
    result=dict(manifest)
    result['capabilities']=normalized
    return result


@transaction.atomic
def register_plugin_package(
    *,
    name:str,
    version:str,
    source:str,
    digest:str,
    manifest:dict[str,Any],
    dependencies:list[dict[str,Any]],
) -> PluginPackage:
    if not name.strip() or len(name)>160:
        raise ExternalFabricError('Plugin name is required and must be <= 160 characters')
    try:
        normalized_version=str(Version(version))
    except InvalidVersion as exc:
        raise ExternalFabricError(f'Invalid plugin semantic version: {version}') from exc
    if len(digest)!=64 or any(ch not in '0123456789abcdef' for ch in digest):
        raise ExternalFabricError('Plugin digest must be a lowercase SHA-256 hex digest')
    manifest=_validate_plugin_manifest(manifest)
    dependencies=_normalize_dependencies(dependencies)
    package,created=PluginPackage.objects.get_or_create(
        name=name.strip(),version=normalized_version,
        defaults={'source':source,'digest':digest,'manifest':manifest,'dependencies':dependencies},
    )
    if not created and (package.digest!=digest or package.source!=source or package.manifest!=manifest or package.dependencies!=dependencies):
        raise ExternalFabricError('Existing plugin version is immutable; publish a new semantic version')
    return package


def resolve_plugin_dependencies(package: PluginPackage, *, include_candidate: bool=True) -> dict[str,Any]:
    available={}
    for item in PluginPackage.objects.filter(approved=True).order_by('name','-installed_at'):
        try:
            version=Version(item.version)
        except InvalidVersion:
            continue
        available.setdefault(item.name,[]).append((version,item))

    graph={}
    visited=set()
    active=set()
    selected={}

    def visit(current: PluginPackage):
        key=f'{current.name}@{current.version}'
        if key in active:
            raise ExternalFabricError(f'Plugin dependency cycle detected at {key}')
        if key in visited:
            return
        active.add(key)
        graph[key]=[]
        for dep in _normalize_dependencies(current.dependencies or []):
            spec=SpecifierSet(dep['specifier'])
            candidates=[row for ver,row in available.get(dep['name'],[]) if ver in spec and row.enabled]
            if not candidates:
                raise ExternalFabricError(f'Unsatisfied plugin dependency: {dep["name"]}{dep["specifier"]}')
            chosen=max(candidates,key=lambda row:Version(row.version))
            graph[key].append(f'{chosen.name}@{chosen.version}')
            selected[chosen.name]=chosen.version
            visit(chosen)
        active.remove(key)
        visited.add(key)

    if include_candidate and package.approved:
        available.setdefault(package.name,[]).append((Version(package.version),package))
    visit(package)
    return {'root':f'{package.name}@{package.version}','dependencies':selected,'graph':graph}


@transaction.atomic
def activate_plugin_package(package_id:str) -> PluginPackage:
    package=PluginPackage.objects.select_for_update().get(pk=package_id)
    if not package.approved:
        raise ExternalFabricError('Plugin package must be approved before activation')
    resolve_plugin_dependencies(package)
    candidate_ids={str(item.get('id')) for item in (package.manifest.get('capabilities') or []) if isinstance(item,dict)}
    for other in PluginPackage.objects.filter(approved=True,enabled=True).exclude(name=package.name):
        other_ids={str(item.get('id')) for item in (other.manifest.get('capabilities') or []) if isinstance(item,dict)}
        collision=sorted(candidate_ids & other_ids)
        if collision:
            raise ExternalFabricError(f'Plugin capability collision with {other.name}: {collision}')
    PluginPackage.objects.filter(name=package.name,enabled=True).exclude(pk=package.pk).update(enabled=False)
    package.enabled=True
    package.save(update_fields=['enabled','updated_at'])
    return package


@transaction.atomic
def approve_plugin_package(package_id:str) -> PluginPackage:
    package=PluginPackage.objects.select_for_update().get(pk=package_id)
    _validate_plugin_manifest(package.manifest)
    _normalize_dependencies(package.dependencies or [])
    package.approved=True
    package.save(update_fields=['approved','updated_at'])
    return package


def dynamic_plugin_capabilities() -> list[dict[str,Any]]:
    rows=[]
    for package in PluginPackage.objects.filter(approved=True,enabled=True).order_by('name','version'):
        resolve_plugin_dependencies(package)
        for capability in package.manifest.get('capabilities') or []:
            rows.append({
                'id':capability['id'],'delegate':capability['delegate'],
                'description':capability.get('description') or '',
                'plugin':package.name,'plugin_version':package.version,
                'source':'approved-plugin-delegation',
            })
    return rows


def resolve_dynamic_capability(capability_id:str) -> dict[str,Any]|None:
    for item in dynamic_plugin_capabilities():
        if item['id']==capability_id:
            return item
    return None


def _auth_headers(integration:ExternalIntegration) -> dict[str,str]:
    secret=_secret(integration.secret_ref)
    headers={'Accept':'application/json'}
    if secret:
        headers['Authorization']=f'Bearer {secret}'
    return headers


def _sync_repository(integration:ExternalIntegration) -> list[dict[str,Any]]:
    base=integration.base_url.rstrip('/')+'/'
    headers=_auth_headers(integration)
    if integration.kind==ExternalIntegration.Kind.GITHUB:
        payload=_request_json('GET',urljoin(base,'user/repos'),headers=headers,params={'per_page':100,'affiliation':'owner,collaborator,organization_member'})
        # GitHub returns an array, so use a dedicated client path.
        raise ExternalFabricError('internal-array-dispatch')
    if integration.kind==ExternalIntegration.Kind.GITLAB:
        url=urljoin(base,'api/v4/projects')
        try:
            with httpx.Client(timeout=_HTTP_TIMEOUT,follow_redirects=False) as client:
                response=client.get(url,headers=headers,params={'membership':'true','per_page':100})
                response.raise_for_status(); payload=response.json()
        except (httpx.HTTPError,ValueError) as exc:
            raise ExternalFabricError(f'External provider request failed: {url}') from exc
        if not isinstance(payload,list): raise ExternalFabricError('GitLab project response must be an array')
        return [{'id':str(x.get('id')),'name':str(x.get('path_with_namespace') or x.get('name') or ''),'url':str(x.get('web_url') or '')} for x in payload if isinstance(x,dict)]
    if integration.kind==ExternalIntegration.Kind.BITBUCKET:
        workspace=str(integration.config.get('workspace') or '').strip()
        if not workspace: raise ExternalFabricError('Bitbucket integration requires config.workspace')
        url=urljoin(base,f'2.0/repositories/{workspace}')
        payload=_request_json('GET',url,headers=headers,params={'pagelen':100})
        values=payload.get('values') or []
        if not isinstance(values,list): raise ExternalFabricError('Bitbucket values must be an array')
        return [{'id':str(x.get('uuid') or ''),'name':str(x.get('full_name') or x.get('name') or ''),'url':str((x.get('links') or {}).get('html',{}).get('href') or '')} for x in values if isinstance(x,dict)]
    raise ExternalFabricError('Unsupported repository integration kind')


def _github_repositories(integration:ExternalIntegration) -> list[dict[str,Any]]:
    base=integration.base_url.rstrip('/')+'/'
    url=urljoin(base,'user/repos')
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT,follow_redirects=False) as client:
            response=client.get(url,headers=_auth_headers(integration),params={'per_page':100,'affiliation':'owner,collaborator,organization_member'})
            response.raise_for_status(); payload=response.json()
    except (httpx.HTTPError,ValueError) as exc:
        raise ExternalFabricError(f'External provider request failed: {url}') from exc
    if not isinstance(payload,list): raise ExternalFabricError('GitHub repository response must be an array')
    return [{'id':str(x.get('id')),'name':str(x.get('full_name') or x.get('name') or ''),'url':str(x.get('html_url') or '')} for x in payload if isinstance(x,dict)]


def _sync_registry(integration:ExternalIntegration) -> list[dict[str,Any]]:
    if integration.kind==ExternalIntegration.Kind.ECR:
        raw=_secret(integration.secret_ref)
        try:
            credentials=json.loads(raw)
        except ValueError as exc:
            raise ExternalFabricError('ECR secret must be JSON credentials') from exc
        import boto3
        client=boto3.client(
            'ecr',region_name=str(integration.config.get('region') or 'us-east-1'),
            aws_access_key_id=credentials.get('access_key_id'),
            aws_secret_access_key=credentials.get('secret_access_key'),
            aws_session_token=credentials.get('session_token'),
        )
        response=client.describe_repositories(maxResults=100)
        return [{'id':str(x.get('repositoryArn') or ''),'name':str(x.get('repositoryName') or ''),'url':str(x.get('repositoryUri') or '')} for x in response.get('repositories',[])]

    base=integration.base_url.rstrip('/')+'/'
    headers=_auth_headers(integration)
    if integration.kind==ExternalIntegration.Kind.HARBOR:
        url=urljoin(base,'api/v2.0/projects')
        try:
            with httpx.Client(timeout=_HTTP_TIMEOUT,follow_redirects=False) as client:
                response=client.get(url,headers=headers,params={'page_size':100})
                response.raise_for_status(); payload=response.json()
        except (httpx.HTTPError,ValueError) as exc:
            raise ExternalFabricError(f'External provider request failed: {url}') from exc
        if not isinstance(payload,list): raise ExternalFabricError('Harbor project response must be an array')
        return [{'id':str(x.get('project_id') or ''),'name':str(x.get('name') or ''),'url':integration.base_url} for x in payload if isinstance(x,dict)]

    path=str(integration.config.get('catalog_path') or '/v2/_catalog')
    url=urljoin(base,path.lstrip('/'))
    payload=_request_json('GET',url,headers=headers)
    repositories=payload.get('repositories') or []
    if not isinstance(repositories,list): raise ExternalFabricError('Registry catalog repositories must be an array')
    return [{'id':str(name),'name':str(name),'url':integration.base_url} for name in repositories[:1000]]


@transaction.atomic
def sync_external_integration(*,integration_id:str,project,user_id:str) -> IntegrationSyncRun:
    integration=ExternalIntegration.objects.select_related('organization').get(pk=integration_id)
    if integration.organization_id!=project.tenant_link.organization_id:
        raise ExternalFabricError('Integration and project must belong to the same organization')
    run=IntegrationSyncRun.objects.create(
        organization=integration.organization,project=project,integration=integration,
        sync_type='repository' if integration.kind in {ExternalIntegration.Kind.GITHUB,ExternalIntegration.Kind.GITLAB,ExternalIntegration.Kind.BITBUCKET} else 'registry',
        status=IntegrationSyncRun.Status.RUNNING,requested_by_id=user_id,started_at=datetime.now(timezone.utc),
    )
    try:
        if integration.kind==ExternalIntegration.Kind.GITHUB:
            records=_github_repositories(integration)
        elif integration.kind in {ExternalIntegration.Kind.GITLAB,ExternalIntegration.Kind.BITBUCKET}:
            records=_sync_repository(integration)
        elif integration.kind in {ExternalIntegration.Kind.ECR,ExternalIntegration.Kind.GCR,ExternalIntegration.Kind.ACR,ExternalIntegration.Kind.HARBOR,ExternalIntegration.Kind.GHCR}:
            records=_sync_registry(integration)
        else:
            raise ExternalFabricError('Integration kind is not a repository or registry connector')
        run.records_count=len(records)
        run.summary={'records':records[:1000],'truncated':len(records)>1000}
        run.status=IntegrationSyncRun.Status.COMPLETED
        run.completed_at=datetime.now(timezone.utc)
        run.save(update_fields=['records_count','summary','status','completed_at'])
        return run
    except Exception as exc:
        run.status=IntegrationSyncRun.Status.FAILED
        run.error_message=str(exc)
        run.completed_at=datetime.now(timezone.utc)
        run.save(update_fields=['status','error_message','completed_at'])
        raise

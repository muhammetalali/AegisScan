from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

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


def _request_array(
    url: str,
    *,
    headers: dict[str,str]|None=None,
    params: dict[str,Any]|None=None,
) -> list[dict[str,Any]]:
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT,follow_redirects=False) as client:
            response=client.get(url,headers=headers,params=params)
            response.raise_for_status()
            payload=response.json()
    except (httpx.HTTPError,ValueError) as exc:
        raise ExternalFabricError(f'External provider request failed: {url}') from exc
    if not isinstance(payload,list):
        raise ExternalFabricError(f'External provider returned non-array JSON: {url}')
    return [item for item in payload if isinstance(item,dict)]


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
    observed_by_field=ExternalIntelligenceSnapshot._meta.get_field('observed_by')
    normalized_actor_id=(
        None
        if actor_id in {None,''}
        else observed_by_field.target_field.to_python(actor_id)
    )
    with transaction.atomic():
        return ExternalIntelligenceSnapshot.objects.create(
            provider=provider,indicator=address,data=data,source_url=url,snapshot_sha256=digest,
            observed_by_id=normalized_actor_id,observed_at=observed_at,
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
    parsed_source=urlsplit(source)
    if parsed_source.scheme!='https' or not parsed_source.hostname or parsed_source.username or parsed_source.password:
        raise ExternalFabricError('Plugin source must be a credential-free HTTPS URL')
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


@transaction.atomic
def auto_update_plugin_package(name:str) -> PluginPackage:
    candidates=[]
    for package in PluginPackage.objects.select_for_update().filter(name=name,approved=True):
        try:
            candidates.append((Version(package.version),package))
        except InvalidVersion:
            continue
    if not candidates:
        raise ExternalFabricError(f'No approved plugin package is available for {name}')
    failures=[]
    for _,package in sorted(candidates,key=lambda item:item[0],reverse=True):
        try:
            resolve_plugin_dependencies(package)
        except ExternalFabricError as exc:
            failures.append(f'{package.version}:{exc}')
            continue
        return activate_plugin_package(str(package.id))
    raise ExternalFabricError('No dependency-compatible approved version is available: '+'; '.join(failures))


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


def _limited(value:Any,default:int,maximum:int)->int:
    try:
        number=int(value)
    except (TypeError,ValueError):
        number=default
    return max(1,min(number,maximum))


def _github_repositories(integration:ExternalIntegration) -> list[dict[str,Any]]:
    base=integration.base_url.rstrip('/')+'/'
    headers=_auth_headers(integration)
    repos=_request_array(
        urljoin(base,'user/repos'),headers=headers,
        params={'per_page':100,'affiliation':'owner,collaborator,organization_member','sort':'updated'},
    )
    max_repositories=_limited(integration.config.get('max_repositories'),25,100)
    activity_limit=_limited(integration.config.get('activity_limit'),20,100)
    records=[]
    for repo in repos[:max_repositories]:
        full_name=str(repo.get('full_name') or repo.get('name') or '').strip()
        if not full_name:
            continue
        encoded='/'.join(quote(part,safe='') for part in full_name.split('/'))
        item={
            'id':str(repo.get('id') or ''),
            'name':full_name,
            'url':str(repo.get('html_url') or ''),
            'default_branch':str(repo.get('default_branch') or ''),
            'private':bool(repo.get('private')),
            'commits':[],
            'pull_requests':[],
            'webhooks':[],
            'activity_errors':[],
        }
        endpoints={
            'commits':(f'repos/{encoded}/commits',{'per_page':activity_limit}),
            'pull_requests':(f'repos/{encoded}/pulls',{'state':'all','per_page':activity_limit}),
            'webhooks':(f'repos/{encoded}/hooks',{'per_page':activity_limit}),
        }
        for key,(path,params) in endpoints.items():
            try:
                rows=_request_array(urljoin(base,path),headers=headers,params=params)
                if key=='commits':
                    item[key]=[{
                        'id':str(row.get('sha') or ''),
                        'url':str(row.get('html_url') or ''),
                        'message':str(((row.get('commit') or {}).get('message') or ''))[:500],
                    } for row in rows]
                elif key=='pull_requests':
                    item[key]=[{
                        'id':str(row.get('id') or row.get('number') or ''),
                        'number':row.get('number'),
                        'state':str(row.get('state') or ''),
                        'url':str(row.get('html_url') or ''),
                    } for row in rows]
                else:
                    item[key]=[{
                        'id':str(row.get('id') or ''),
                        'active':bool(row.get('active')),
                        'events':row.get('events') if isinstance(row.get('events'),list) else [],
                    } for row in rows]
            except ExternalFabricError as exc:
                item['activity_errors'].append(f'{key}:{exc}')
        records.append(item)
    return records


def _gitlab_repositories(integration:ExternalIntegration) -> list[dict[str,Any]]:
    base=integration.base_url.rstrip('/')+'/'
    headers=_auth_headers(integration)
    repos=_request_array(urljoin(base,'api/v4/projects'),headers=headers,params={'membership':'true','per_page':100,'order_by':'updated_at'})
    max_repositories=_limited(integration.config.get('max_repositories'),25,100)
    activity_limit=_limited(integration.config.get('activity_limit'),20,100)
    records=[]
    for repo in repos[:max_repositories]:
        project_id=str(repo.get('id') or '')
        if not project_id:
            continue
        item={
            'id':project_id,'name':str(repo.get('path_with_namespace') or repo.get('name') or ''),
            'url':str(repo.get('web_url') or ''),'default_branch':str(repo.get('default_branch') or ''),
            'private':str(repo.get('visibility') or '')!='public','commits':[],'pull_requests':[],'webhooks':[],'activity_errors':[],
        }
        endpoints={
            'commits':(f'api/v4/projects/{quote(project_id,safe="")}/repository/commits',{'per_page':activity_limit}),
            'pull_requests':(f'api/v4/projects/{quote(project_id,safe="")}/merge_requests',{'scope':'all','per_page':activity_limit}),
            'webhooks':(f'api/v4/projects/{quote(project_id,safe="")}/hooks',{'per_page':activity_limit}),
        }
        for key,(path,params) in endpoints.items():
            try:
                rows=_request_array(urljoin(base,path),headers=headers,params=params)
                if key=='commits':
                    item[key]=[{'id':str(row.get('id') or ''),'url':str(row.get('web_url') or ''),'message':str(row.get('message') or row.get('title') or '')[:500]} for row in rows]
                elif key=='pull_requests':
                    item[key]=[{'id':str(row.get('id') or row.get('iid') or ''),'number':row.get('iid'),'state':str(row.get('state') or ''),'url':str(row.get('web_url') or '')} for row in rows]
                else:
                    item[key]=[{'id':str(row.get('id') or ''),'url':str(row.get('url') or ''),'enabled':bool(row.get('enable_ssl_verification',True))} for row in rows]
            except ExternalFabricError as exc:
                item['activity_errors'].append(f'{key}:{exc}')
        records.append(item)
    return records


def _bitbucket_repositories(integration:ExternalIntegration) -> list[dict[str,Any]]:
    base=integration.base_url.rstrip('/')+'/'
    headers=_auth_headers(integration)
    workspace=str(integration.config.get('workspace') or '').strip()
    if not workspace:
        raise ExternalFabricError('Bitbucket integration requires config.workspace')
    payload=_request_json('GET',urljoin(base,f'2.0/repositories/{quote(workspace,safe="")}'),headers=headers,params={'pagelen':100,'sort':'-updated_on'})
    repos=payload.get('values') or []
    if not isinstance(repos,list):
        raise ExternalFabricError('Bitbucket values must be an array')
    max_repositories=_limited(integration.config.get('max_repositories'),25,100)
    activity_limit=_limited(integration.config.get('activity_limit'),20,100)
    records=[]
    for repo in [row for row in repos if isinstance(row,dict)][:max_repositories]:
        full_name=str(repo.get('full_name') or repo.get('name') or '').strip()
        if not full_name:
            continue
        encoded=quote(full_name,safe='')
        item={
            'id':str(repo.get('uuid') or ''),'name':full_name,
            'url':str((repo.get('links') or {}).get('html',{}).get('href') or ''),
            'default_branch':str((repo.get('mainbranch') or {}).get('name') or ''),
            'private':bool(repo.get('is_private')),'commits':[],'pull_requests':[],'webhooks':[],'activity_errors':[],
        }
        endpoints={
            'commits':f'2.0/repositories/{encoded}/commits',
            'pull_requests':f'2.0/repositories/{encoded}/pullrequests',
            'webhooks':f'2.0/repositories/{encoded}/hooks',
        }
        for key,path in endpoints.items():
            try:
                response=_request_json('GET',urljoin(base,path),headers=headers,params={'pagelen':activity_limit})
                rows=response.get('values') or []
                if not isinstance(rows,list): raise ExternalFabricError(f'Bitbucket {key} values must be an array')
                rows=[row for row in rows if isinstance(row,dict)]
                if key=='commits':
                    item[key]=[{'id':str(row.get('hash') or ''),'url':str((row.get('links') or {}).get('html',{}).get('href') or ''),'message':str(row.get('message') or '')[:500]} for row in rows]
                elif key=='pull_requests':
                    item[key]=[{'id':str(row.get('id') or ''),'number':row.get('id'),'state':str(row.get('state') or ''),'url':str((row.get('links') or {}).get('html',{}).get('href') or '')} for row in rows]
                else:
                    item[key]=[{'id':str(row.get('uuid') or ''),'active':bool(row.get('active')),'events':list((row.get('events') or {}).keys()) if isinstance(row.get('events'),dict) else []} for row in rows]
            except ExternalFabricError as exc:
                item['activity_errors'].append(f'{key}:{exc}')
        records.append(item)
    return records


def _sync_repository(integration:ExternalIntegration) -> list[dict[str,Any]]:
    if integration.kind==ExternalIntegration.Kind.GITHUB:
        return _github_repositories(integration)
    if integration.kind==ExternalIntegration.Kind.GITLAB:
        return _gitlab_repositories(integration)
    if integration.kind==ExternalIntegration.Kind.BITBUCKET:
        return _bitbucket_repositories(integration)
    raise ExternalFabricError('Unsupported repository integration kind')


def _sync_registry(integration:ExternalIntegration) -> list[dict[str,Any]]:
    image_limit=_limited(integration.config.get('image_limit'),50,200)
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
        response=client.describe_repositories(maxResults=min(100,image_limit))
        records=[]
        for repo in response.get('repositories',[]):
            name=str(repo.get('repositoryName') or '')
            if not name: continue
            images=client.describe_images(repositoryName=name,maxResults=min(100,image_limit)).get('imageDetails',[])
            records.append({
                'id':str(repo.get('repositoryArn') or ''),'name':name,'url':str(repo.get('repositoryUri') or ''),
                'images':[{
                    'digest':str(image.get('imageDigest') or ''),
                    'tags':image.get('imageTags') if isinstance(image.get('imageTags'),list) else [],
                    'pushed_at':str(image.get('imagePushedAt') or ''),
                    'size_bytes':int(image.get('imageSizeInBytes') or 0),
                } for image in images[:image_limit] if isinstance(image,dict)],
            })
        return records

    base=integration.base_url.rstrip('/')+'/'
    headers=_auth_headers(integration)
    if integration.kind==ExternalIntegration.Kind.HARBOR:
        projects=_request_array(urljoin(base,'api/v2.0/projects'),headers=headers,params={'page_size':100})
        records=[]
        for project in projects[:_limited(integration.config.get('max_projects'),20,100)]:
            project_name=str(project.get('name') or '')
            if not project_name: continue
            repo_url=urljoin(base,f'api/v2.0/projects/{quote(project_name,safe="")}/repositories')
            repositories=_request_array(repo_url,headers=headers,params={'page_size':100})
            for repo in repositories:
                name=str(repo.get('name') or '')
                if not name: continue
                artifact_url=urljoin(base,f'api/v2.0/projects/{quote(project_name,safe="")}/repositories/{quote(name,safe="")}/artifacts')
                try:
                    artifacts=_request_array(artifact_url,headers=headers,params={'page_size':image_limit,'with_tag':'true'})
                except ExternalFabricError:
                    artifacts=[]
                records.append({
                    'id':str(repo.get('id') or ''),'name':name,'url':integration.base_url,
                    'images':[{
                        'digest':str(artifact.get('digest') or ''),
                        'tags':[str(tag.get('name')) for tag in (artifact.get('tags') or []) if isinstance(tag,dict) and tag.get('name')],
                        'size_bytes':int(artifact.get('size') or 0),
                        'pushed_at':str(artifact.get('push_time') or ''),
                    } for artifact in artifacts[:image_limit]],
                })
        return records

    catalog_path=str(integration.config.get('catalog_path') or '/v2/_catalog')
    payload=_request_json('GET',urljoin(base,catalog_path.lstrip('/')),headers=headers)
    repositories=payload.get('repositories') or []
    if not isinstance(repositories,list):
        raise ExternalFabricError('Registry catalog repositories must be an array')
    records=[]
    for name_value in repositories[:_limited(integration.config.get('max_repositories'),100,500)]:
        name=str(name_value)
        tags=[]
        try:
            tag_payload=_request_json('GET',urljoin(base,f'v2/{quote(name,safe="/")}/tags/list'),headers=headers)
            raw_tags=tag_payload.get('tags') or []
            if isinstance(raw_tags,list): tags=[str(tag) for tag in raw_tags[:image_limit]]
        except ExternalFabricError:
            pass
        records.append({'id':name,'name':name,'url':integration.base_url,'images':[{'tag':tag} for tag in tags]})
    return records


def sync_external_integration(*,integration_id:str,project,user_id:str) -> IntegrationSyncRun:
    integration=ExternalIntegration.objects.select_related('organization').get(pk=integration_id)
    if integration.organization_id!=project.tenant_link.organization_id:
        raise ExternalFabricError('Integration and project must belong to the same organization')
    with transaction.atomic():
        run=IntegrationSyncRun.objects.create(
            organization=integration.organization,project=project,integration=integration,
            sync_type='repository' if integration.kind in {ExternalIntegration.Kind.GITHUB,ExternalIntegration.Kind.GITLAB,ExternalIntegration.Kind.BITBUCKET} else 'registry',
            status=IntegrationSyncRun.Status.RUNNING,requested_by_id=user_id,started_at=datetime.now(timezone.utc),
        )
    try:
        if integration.kind in {ExternalIntegration.Kind.GITHUB,ExternalIntegration.Kind.GITLAB,ExternalIntegration.Kind.BITBUCKET}:
            records=_sync_repository(integration)
        elif integration.kind in {ExternalIntegration.Kind.ECR,ExternalIntegration.Kind.GCR,ExternalIntegration.Kind.ACR,ExternalIntegration.Kind.HARBOR,ExternalIntegration.Kind.GHCR}:
            records=_sync_registry(integration)
        else:
            raise ExternalFabricError('Integration kind is not a repository or registry connector')
        with transaction.atomic():
            run=IntegrationSyncRun.objects.select_for_update().get(pk=run.pk)
            run.records_count=len(records)
            run.summary={'records':records[:1000],'truncated':len(records)>1000}
            run.status=IntegrationSyncRun.Status.COMPLETED
            run.completed_at=datetime.now(timezone.utc)
            run.save(update_fields=['records_count','summary','status','completed_at'])
        return run
    except Exception as exc:
        with transaction.atomic():
            failed=IntegrationSyncRun.objects.select_for_update().get(pk=run.pk)
            failed.status=IntegrationSyncRun.Status.FAILED
            failed.error_message=str(exc)[:4000]
            failed.completed_at=datetime.now(timezone.utc)
            failed.save(update_fields=['status','error_message','completed_at'])
        raise

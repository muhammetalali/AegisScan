from __future__ import annotations

import os
import time
from typing import Any

import requests
from django.utils import timezone

from .models import ExternalIntegration, SBOMArtifact, SBOMComponent
from .services import fetch_intel


def _secret(ref: str) -> str:
    value = os.getenv(ref)
    if not value:
        raise RuntimeError(f'Integration secret environment variable is not configured: {ref}')
    return value


def send_integration(integration: ExternalIntegration, event: dict[str, Any]) -> dict[str, Any]:
    if not integration.enabled:
        return {'status': 'disabled'}
    url = integration.base_url.rstrip('/')
    headers={'Content-Type':'application/json'}
    secret = _secret(integration.secret_ref) if integration.secret_ref else ''
    if integration.kind == ExternalIntegration.Kind.SPLUNK:
        url = url if url.endswith('/services/collector/event') else url + '/services/collector/event'
        headers['Authorization'] = f'Splunk {secret}'
        body={'event':event,'time':time.time(),'sourcetype':integration.config.get('sourcetype','aegisscan')}
    elif integration.kind == ExternalIntegration.Kind.ELASTIC:
        index=integration.config.get('index','aegisscan-events')
        url=url + f'/{index}/_doc'
        if secret: headers['Authorization']=f'ApiKey {secret}'
        body=event
    elif integration.kind == ExternalIntegration.Kind.SLACK:
        body={'text': integration.config.get('text_prefix','AegisScan') + ': ' + event.get('type','event'), 'attachments':[{'text': event}]}
        if secret: headers['Authorization']=f'Bearer {secret}'
    elif integration.kind == ExternalIntegration.Kind.TEAMS:
        body={'@type':'MessageCard','@context':'https://schema.org/extensions','summary':event.get('type','AegisScan event'),'themeColor':'0078D4','sections':[{'facts':[{'name':k,'value':str(v)} for k,v in event.items()]}]}
    else:
        body=event
        if secret: headers['Authorization']=f'Bearer {secret}'
    response=requests.post(url,json=body,headers=headers,timeout=20)
    response.raise_for_status()
    return {'status':'sent','http_status':response.status_code}


def ingest_sbom(project, organization, source: str, source_ref: str, document: dict[str,Any], user_id: str):
    fmt='cyclonedx' if 'components' in document and ('bomFormat' in document or 'specVersion' in document) else 'spdx' if 'packages' in document or 'spdxVersion' in document else 'unknown'
    if fmt=='unknown': raise ValueError('Unsupported SBOM format; expected CycloneDX or SPDX JSON')
    import json, hashlib
    raw=json.dumps(document,sort_keys=True,separators=(',',':')).encode()
    artifact=SBOMArtifact.objects.create(organization=organization,project=project,source=source,source_ref=source_ref,format=fmt,sha256=hashlib.sha256(raw).hexdigest(),component_count=0,document=document,created_by_id=user_id)
    rows=document.get('components',[]) if fmt=='cyclonedx' else document.get('packages',[])
    for row in rows:
        if not isinstance(row,dict): continue
        name=str(row.get('name') or '').strip()
        version=str(row.get('version') or row.get('versionInfo') or '').strip()
        if not name: continue
        ecosystem=str(row.get('type') or row.get('supplier') or '').strip()
        purl=str(row.get('purl') or row.get('externalRefs', [{}])[0].get('referenceLocator') if isinstance(row.get('externalRefs'),list) and row.get('externalRefs') else '').strip()
        licenses=row.get('licenses',[]) if isinstance(row.get('licenses'),list) else []
        hashes=row.get('hashes',[]) if isinstance(row.get('hashes'),list) else []
        comp=SBOMComponent.objects.create(artifact=artifact,name=name,version=version,ecosystem=ecosystem,purl=purl,licenses=licenses if licenses else [],hashes=hashes)
        try:
            payload=fetch_intel('osv',f'{name}@{version}',package={'name':name,'ecosystem':ecosystem or 'PyPI'})
            ids=[str(v.get('id')) for v in payload.get('vulns',[]) if isinstance(v,dict) and v.get('id')] if isinstance(payload,dict) else []
            comp.vulnerabilities=ids; comp.save(update_fields=['vulnerabilities'])
        except Exception:
            # SBOM ingestion is durable even when enrichment is temporarily unavailable.
            comp.vulnerabilities=[]
    artifact.component_count=artifact.components.count(); artifact.save(update_fields=['component_count'])
    return artifact

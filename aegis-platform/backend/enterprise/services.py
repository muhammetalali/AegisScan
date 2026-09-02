from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from datetime import timedelta
from typing import Any

import requests
from django.db import transaction
from django.utils import timezone
from django_celery_beat.models import IntervalSchedule, PeriodicTask

from django_project.assets.models import Asset, AssetRelationship
from django_project.compliance.models import ComplianceAssessment
from django_project.evidence.models import Evidence
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from .models import (
    AttackPath, ComplianceMapping, DigitalTwin, ExecutiveSnapshot,
    FindingIntelligence, Organization, OrganizationMembership, ReportSchedule,
    ThreatIntelAudit, ThreatIntelCache, TwinNode, TwinRelationship,
)


PROVIDERS = {
    'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    'osv': 'https://api.osv.dev/v1/query',
    'kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'epss': 'https://api.first.org/data/v1/epss',
}


def ensure_project_tenant(project, user_id: str) -> Organization:
    link = getattr(project, 'tenant_link', None)
    if link:
        if not OrganizationMembership.objects.filter(organization=link.organization, user_id=user_id, is_active=True).exists():
            raise PermissionError('User is not a member of the project tenant')
        return link.organization
    owner = project.owner
    org, _ = Organization.objects.get_or_create(slug=f'user-{owner.id}', defaults={'name': f"{owner.get_full_name() or owner.email} Organization", 'owner': owner})
    OrganizationMembership.objects.get_or_create(organization=org, user=owner, defaults={'role': OrganizationMembership.Role.OWNER})
    from .models import TenantProject
    TenantProject.objects.get_or_create(project=project, defaults={'organization': org})
    if org.owner_id != owner.id:
        raise PermissionError('Project tenant ownership mismatch')
    if not OrganizationMembership.objects.filter(organization=org, user_id=user_id, is_active=True).exists():
        if str(owner.id) == str(user_id):
            OrganizationMembership.objects.get_or_create(organization=org, user_id=user_id, defaults={'role': OrganizationMembership.Role.OWNER})
        else:
            raise PermissionError('User is not a member of the project tenant')
    return org


def build_twin(twin_id: str) -> DigitalTwin:
    twin = DigitalTwin.objects.select_related('project').get(pk=twin_id)
    project = twin.project
    twin.nodes.all().delete()
    twin.relationships.all().delete()
    asset_nodes = {}
    for asset in Asset.objects.filter(project=project, is_active=True):
        node = TwinNode.objects.create(twin=twin, kind=TwinNode.Kind.ASSET, external_id=str(asset.id), name=asset.name, properties={'type': asset.type, 'criticality': asset.criticality, 'configuration': asset.configuration})
        asset_nodes[asset.id] = node
        for service in (asset.configuration or {}).get('services', []):
            svc = TwinNode.objects.create(twin=twin, kind=TwinNode.Kind.SERVICE, external_id=f'{asset.id}:service:{service}', name=str(service), properties={'asset_id': str(asset.id)})
            TwinRelationship.objects.create(twin=twin, source=node, target=svc, relationship_type='hosts')
    for rel in AssetRelationship.objects.filter(project=project).select_related('source','target'):
        if rel.source_id in asset_nodes and rel.target_id in asset_nodes:
            TwinRelationship.objects.create(twin=twin, source=asset_nodes[rel.source_id], target=asset_nodes[rel.target_id], relationship_type=rel.relationship_type, properties=rel.metadata)
    for finding in Vulnerability.objects.filter(project=project, status__in=[Vulnerability.Status.OPEN,Vulnerability.Status.CONFIRMED,Vulnerability.Status.IN_PROGRESS]).select_related('asset'):
        if finding.asset_id in asset_nodes:
            fn=TwinNode.objects.create(twin=twin, kind=TwinNode.Kind.VULNERABILITY, external_id=str(finding.id), name=finding.title, properties={'severity':finding.severity,'risk_score':finding.risk_score,'source_engine':finding.source_engine})
            TwinRelationship.objects.create(twin=twin, source=asset_nodes[finding.asset_id], target=fn, relationship_type='affected_by')
    twin.snapshot={'node_count': twin.nodes.count(), 'relationship_count': twin.relationships.count(), 'project_id': str(project.id)}
    twin.status=DigitalTwin.Status.READY; twin.built_at=timezone.now(); twin.version += 1; twin.save(update_fields=['snapshot','status','built_at','version','updated_at'])
    return twin


def predict_scenario(scenario):
    twin=scenario.twin
    baseline=sum(float(n.properties.get('risk_score',0)) for n in twin.nodes.filter(kind=TwinNode.Kind.VULNERABILITY))
    affected={str(x) for x in (scenario.affected_nodes or [])}
    multiplier=float((scenario.parameters or {}).get('risk_multiplier', 1.0))
    reduction=float((scenario.parameters or {}).get('risk_reduction', 0.0))
    impacted=sum(float(n.properties.get('risk_score',0)) for n in twin.nodes.filter(id__in=affected, kind=TwinNode.Kind.VULNERABILITY))
    predicted=max(0.0, baseline - impacted + impacted*multiplier - reduction)
    scenario.baseline_risk=baseline; scenario.predicted_risk=predicted; scenario.risk_delta=predicted-baseline
    scenario.evidence={'baseline_source':'digital_twin_nodes','affected_risk':impacted}
    scenario.recommendation='Apply the modeled change only when the predicted risk delta is non-positive.' if scenario.risk_delta > 0 else 'Modeled change does not increase observed risk.'
    scenario.status='completed'; scenario.completed_at=timezone.now(); scenario.save(update_fields=['baseline_risk','predicted_risk','risk_delta','evidence','recommendation','status','completed_at'])
    return scenario


def generate_attack_paths(project, organization, max_depth=8):
    adjacency=defaultdict(list)
    for rel in AssetRelationship.objects.filter(project=project).values('source_id','target_id','relationship_type'):
        adjacency[str(rel['source_id'])].append((str(rel['target_id']),rel['relationship_type']))
    findings=list(Vulnerability.objects.filter(project=project, asset__isnull=False, status__in=[Vulnerability.Status.OPEN,Vulnerability.Status.CONFIRMED,Vulnerability.Status.IN_PROGRESS]).values('id','asset_id','risk_score','title'))
    results=[]
    for item in findings:
        start=str(item['asset_id'])
        queue=deque([(start,[{'node':start,'type':'asset'}])]); seen={start}
        while queue:
            node,path=queue.popleft()
            if len(path)>=max_depth: continue
            for target,rel_type in adjacency.get(node,[]):
                if target in seen: continue
                seen.add(target); new_path=path+[{'node':target,'type':rel_type}]
                if target != start and any(v['asset_id'] and str(v['asset_id'])==target for v in findings):
                    results.append((path,new_path)); continue
                queue.append((target,new_path))
    created=[]
    for path,tail in results[:500]:
        created.append(AttackPath.objects.create(organization=organization, project=project, source_node=path[0], target_node=tail[-1], steps=tail, risk_score=sum(float(item.get('risk_score',0)) for item in findings if str(item['asset_id']) in {x['node'] for x in tail})))
    return created


def map_compliance(project):
    assessments=ComplianceAssessment.objects.filter(project=project).select_related('framework','control')
    findings=Vulnerability.objects.filter(project=project)
    created=0
    for assessment in assessments:
        control_text=f"{assessment.control.control_id} {assessment.control.title} {assessment.control.category}".lower()
        for finding in findings:
            hay=' '.join([finding.title,finding.description,finding.category,finding.owasp_category,finding.cwe_id,' '.join(finding.tags or [])]).lower()
            score=0.0
            reason=''
            if assessment.control.control_id.lower() in hay: score=0.95; reason='Control identifier matched finding metadata.'
            elif finding.cwe_id and finding.cwe_id.lower() in control_text: score=0.9; reason='CWE mapped to control metadata.'
            elif any(token and token in hay for token in control_text.split() if len(token)>4): score=0.65; reason='Control/finding semantic keyword rule matched.'
            if score >= 0.65:
                _, was_created=ComplianceMapping.objects.update_or_create(assessment=assessment,vulnerability=finding,defaults={'mapping_reason':reason,'confidence':score,'source':'deterministic_rule'})
                created += int(was_created)
    return created


def executive_snapshot(project, organization):
    qs=Vulnerability.objects.filter(project=project)
    active=qs.exclude(status__in=[Vulnerability.Status.FIXED,Vulnerability.Status.FALSE_POSITIVE,Vulnerability.Status.ACCEPTED_RISK,Vulnerability.Status.WONT_FIX,Vulnerability.Status.DUPLICATE])
    critical=active.filter(severity=Vulnerability.Severity.CRITICAL).count(); high=active.filter(severity=Vulnerability.Severity.HIGH).count()
    risk=sum(float(x.risk_score) for x in active)
    validated=qs.filter(validation_status='validated').count(); fixed=qs.filter(status=Vulnerability.Status.FIXED).count()
    coverage=round(Scan.objects.filter(project=project,status=Scan.Status.COMPLETED).values('asset_id').distinct().count()/project.assets.count()*100,2) if project.assets.count() else 0.0
    assessed=ComplianceAssessment.objects.filter(project=project).exclude(status=ComplianceAssessment.Status.NOT_ASSESSED); compliant=assessed.filter(status=ComplianceAssessment.Status.COMPLIANT).count(); partial=assessed.filter(status=ComplianceAssessment.Status.PARTIAL).count(); compliance=round((compliant+partial*0.5)/assessed.count()*100,2) if assessed.exists() else 0.0
    score=max(0.0,min(100.0,100.0-risk)); previous=ExecutiveSnapshot.objects.filter(project=project).order_by('-captured_at').first(); delta=round(score-(previous.score if previous else score),2)
    snapshot=ExecutiveSnapshot.objects.create(organization=organization,project=project,score=round(score,2),risk=round(risk,2),critical_findings=critical,high_findings=high,open_findings=active.count(),validated_findings=validated,fixed_findings=fixed,compliance_score=compliance,coverage_score=coverage,trend='improving' if delta>0 else 'declining' if delta<0 else 'stable',deltas={'score':delta,'risk':round(risk-(previous.risk if previous else risk),2)})
    return snapshot


def schedule_task(schedule: ReportSchedule):
    minutes={'daily':1440,'weekly':10080,'monthly':43200}.get(schedule.frequency)
    if schedule.frequency=='cron':
        raise ValueError('Use django-celery-beat CrontabSchedule for cron schedules')
    interval,_=IntervalSchedule.objects.get_or_create(every=minutes, period=IntervalSchedule.MINUTES)
    PeriodicTask.objects.update_or_create(name=f'aegis-report:{schedule.id}',defaults={'interval':interval,'task':'fastapi_app.tasks.enterprise_tasks.execute_report_schedule','kwargs':json.dumps({'schedule_id':str(schedule.id)}),'enabled':schedule.enabled,'start_time':schedule.next_run})


def _http_json(provider, method, url, **kwargs):
    started=timezone.now(); response=None; error=''
    try:
        response=requests.request(method,url,timeout=20,**kwargs)
        response.raise_for_status(); payload=response.json()
        digest=hashlib.sha256(response.content).hexdigest()
        return payload,response.status_code,digest,int((timezone.now()-started).total_seconds()*1000),''
    except Exception as exc:
        error=str(exc); return {},getattr(response,'status_code',None),'',int((timezone.now()-started).total_seconds()*1000),error


def fetch_intel(provider: str, key: str, cve: str|None=None, package: dict|None=None):
    now=timezone.now(); cached=ThreatIntelCache.objects.filter(provider=provider,key=key,expires_at__gt=now).first()
    if cached: return cached.payload
    headers={}; params={}; body=None
    if provider=='nvd': params={'cveId':cve} if cve else {'resultsPerPage':1}
    elif provider=='epss': params={'cve':cve}
    elif provider=='osv': body={'package':package} if package else {'package':{'name':key,'ecosystem':'PyPI'}}
    elif provider=='kev': pass
    if provider=='osv': payload,status,digest,duration,error=_http_json(provider,'POST',PROVIDERS[provider],json=body,headers=headers)
    else: payload,status,digest,duration,error=_http_json(provider,'GET',PROVIDERS[provider],params=params,headers=headers)
    ThreatIntelAudit.objects.create(provider=provider,operation='fetch',key=key,response_status=status,duration_ms=duration,error_message=error)
    if error: raise RuntimeError(f'{provider} provider request failed: {error}')
    cache, _=ThreatIntelCache.objects.update_or_create(provider=provider,key=key,defaults={'payload':payload,'fetched_at':now,'expires_at':now+timedelta(hours=6),'http_status':status,'sha256':digest})
    return cache.payload


def fuse_finding(finding: Vulnerability):
    intelligence, _=FindingIntelligence.objects.get_or_create(vulnerability=finding)
    cves=list(finding.cve_ids or [])
    intelligence.nvd=fetch_intel('nvd',cves[0],cve=cves[0]) if cves else {}
    intelligence.osv=fetch_intel('osv',cves[0],package=None) if cves else {}
    intelligence.epss=fetch_intel('epss',cves[0],cve=cves[0]) if cves else {}
    kev=fetch_intel('kev','global')
    vulnerabilities=kev.get('vulnerabilities',[]) if isinstance(kev,dict) else []
    intelligence.cisa_kev=next((x for x in vulnerabilities if cves and x.get('cveID') in cves),{})
    epss_data=intelligence.epss.get('data',[]) if isinstance(intelligence.epss,dict) else []
    epss_score=float(epss_data[0].get('epss',0)) if epss_data else 0.0
    kev_hit=bool(intelligence.cisa_kev); nvd_hit=bool(intelligence.nvd.get('vulnerabilities')) if isinstance(intelligence.nvd,dict) else False; osv_hit=bool(intelligence.osv.get('vulns')) if isinstance(intelligence.osv,dict) else False
    signals=sum([nvd_hit,osv_hit,kev_hit,epss_score>0]); intelligence.confidence=round(min(100.0,25.0*signals+25.0*(epss_score>0.5)),2)
    intelligence.conflict=bool(kev_hit and epss_score < 0.01)
    intelligence.explanation=f'NVD={nvd_hit}; OSV={osv_hit}; CISA KEV={kev_hit}; EPSS={epss_score:.4f}.'
    intelligence.recommendation='Prioritize immediate remediation.' if kev_hit or epss_score>=0.5 else 'Review and remediate according to project risk policy.'
    intelligence.save(); return intelligence

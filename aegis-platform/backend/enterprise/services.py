from __future__ import annotations

import hashlib
import json
import os
import time
from collections import defaultdict, deque
from datetime import timedelta

import requests
from django.core.cache import cache
from django.utils import timezone
from django_celery_beat.models import IntervalSchedule, PeriodicTask

from django_project.assets.models import Asset, AssetRelationship
from django_project.compliance.models import ComplianceAssessment
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from .models import AttackPath, ComplianceMapping, DigitalTwin, ExecutiveSnapshot, FindingIntelligence, Organization, OrganizationMembership, ReportSchedule, ThreatIntelAudit, ThreatIntelCache, TwinNode, TwinRelationship

PROVIDERS={'nvd':'https://services.nvd.nist.gov/rest/json/cves/2.0','osv':'https://api.osv.dev/v1/query','osv_vuln':'https://api.osv.dev/v1/vulns','kev':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json','epss':'https://api.first.org/data/v1/epss'}


def ensure_project_tenant(project,user_id:str)->Organization:
    link=getattr(project,'tenant_link',None)
    if link:
        if not OrganizationMembership.objects.filter(organization=link.organization,user_id=user_id,is_active=True).exists(): raise PermissionError('User is not a member of the project tenant')
        return link.organization
    owner=project.owner
    org,_=Organization.objects.get_or_create(slug=f'user-{owner.id}',defaults={'name':f"{owner.get_full_name() or owner.email} Organization",'owner':owner})
    OrganizationMembership.objects.get_or_create(organization=org,user=owner,defaults={'role':OrganizationMembership.Role.OWNER})
    from .models import TenantProject
    TenantProject.objects.get_or_create(project=project,defaults={'organization':org})
    if org.owner_id!=owner.id: raise PermissionError('Project tenant ownership mismatch')
    if not OrganizationMembership.objects.filter(organization=org,user_id=user_id,is_active=True).exists():
        if str(owner.id)==str(user_id): OrganizationMembership.objects.get_or_create(organization=org,user_id=user_id,defaults={'role':OrganizationMembership.Role.OWNER})
        else: raise PermissionError('User is not a member of the project tenant')
    return org


def build_twin(twin_id:str)->DigitalTwin:
    twin=DigitalTwin.objects.select_related('project').get(pk=twin_id); project=twin.project
    twin.nodes.all().delete(); twin.relationships.all().delete(); asset_nodes={}
    for asset in Asset.objects.filter(project=project,is_active=True):
        node=TwinNode.objects.create(twin=twin,kind=TwinNode.Kind.ASSET,external_id=str(asset.id),name=asset.name,properties={'type':asset.type,'criticality':asset.criticality,'configuration':asset.configuration}); asset_nodes[asset.id]=node
        for service in (asset.configuration or {}).get('services',[]):
            svc=TwinNode.objects.create(twin=twin,kind=TwinNode.Kind.SERVICE,external_id=f'{asset.id}:service:{service}',name=str(service),properties={'asset_id':str(asset.id)}); TwinRelationship.objects.create(twin=twin,source=node,target=svc,relationship_type='hosts')
    for rel in AssetRelationship.objects.filter(project=project).select_related('source','target'):
        if rel.source_id in asset_nodes and rel.target_id in asset_nodes: TwinRelationship.objects.create(twin=twin,source=asset_nodes[rel.source_id],target=asset_nodes[rel.target_id],relationship_type=rel.relationship_type,properties=rel.metadata)
    for finding in Vulnerability.objects.filter(project=project,status__in=[Vulnerability.Status.OPEN,Vulnerability.Status.CONFIRMED,Vulnerability.Status.IN_PROGRESS]).select_related('asset'):
        if finding.asset_id in asset_nodes:
            fn=TwinNode.objects.create(twin=twin,kind=TwinNode.Kind.VULNERABILITY,external_id=str(finding.id),name=finding.title,properties={'severity':finding.severity,'risk_score':finding.risk_score,'source_engine':finding.source_engine}); TwinRelationship.objects.create(twin=twin,source=asset_nodes[finding.asset_id],target=fn,relationship_type='affected_by')
    twin.snapshot={'node_count':twin.nodes.count(),'relationship_count':twin.relationships.count(),'project_id':str(project.id)}; twin.status=DigitalTwin.Status.READY; twin.built_at=timezone.now(); twin.version+=1; twin.save(update_fields=['snapshot','status','built_at','version','updated_at']); return twin


def predict_scenario(scenario):
    twin=scenario.twin; baseline=sum(float(n.properties.get('risk_score',0)) for n in twin.nodes.filter(kind=TwinNode.Kind.VULNERABILITY)); affected={str(x) for x in (scenario.affected_nodes or [])}; multiplier=float((scenario.parameters or {}).get('risk_multiplier',1.0)); reduction=float((scenario.parameters or {}).get('risk_reduction',0.0)); impacted=sum(float(n.properties.get('risk_score',0)) for n in twin.nodes.filter(id__in=affected,kind=TwinNode.Kind.VULNERABILITY)); predicted=max(0.0,baseline-impacted+impacted*multiplier-reduction)
    scenario.baseline_risk=baseline; scenario.predicted_risk=predicted; scenario.risk_delta=predicted-baseline; scenario.evidence={'baseline_source':'digital_twin_nodes','affected_risk':impacted}; scenario.recommendation='Apply the modeled change only when the predicted risk delta is non-positive.' if scenario.risk_delta>0 else 'Modeled change does not increase observed risk.'; scenario.status='completed'; scenario.completed_at=timezone.now(); scenario.save(update_fields=['baseline_risk','predicted_risk','risk_delta','evidence','recommendation','status','completed_at']); return scenario


def generate_attack_paths(project,organization,max_depth=8):
    adjacency=defaultdict(list)
    for rel in AssetRelationship.objects.filter(project=project).values('source_id','target_id','relationship_type'): adjacency[str(rel['source_id'])].append((str(rel['target_id']),rel['relationship_type']))
    findings=list(Vulnerability.objects.filter(project=project,asset__isnull=False,status__in=[Vulnerability.Status.OPEN,Vulnerability.Status.CONFIRMED,Vulnerability.Status.IN_PROGRESS]).values('id','asset_id','risk_score','title')); results=[]
    for item in findings:
        start=str(item['asset_id']); queue=deque([(start,[{'node':start,'type':'asset'}])]); seen={start}
        while queue:
            node,path=queue.popleft()
            if len(path)>=max_depth: continue
            for target,rel_type in adjacency.get(node,[]):
                if target in seen: continue
                seen.add(target); new_path=path+[{'node':target,'type':rel_type}]
                if any(str(v['asset_id'])==target for v in findings): results.append((path,new_path)); continue
                queue.append((target,new_path))
    created=[]
    for path,tail in results[:500]: created.append(AttackPath.objects.create(organization=organization,project=project,source_node=path[0],target_node=tail[-1],steps=tail,risk_score=sum(float(item.get('risk_score',0)) for item in findings if str(item['asset_id']) in {x['node'] for x in tail})))
    return created


def map_compliance(project):
    assessments=ComplianceAssessment.objects.filter(project=project).select_related('framework','control'); findings=Vulnerability.objects.filter(project=project); created=0
    for assessment in assessments:
        control_text=f"{assessment.control.control_id} {assessment.control.title} {assessment.control.category}".lower()
        for finding in findings:
            hay=' '.join([finding.title,finding.description,finding.category,finding.owasp_category,finding.cwe_id,' '.join(finding.tags or [])]).lower(); score=0.0; reason=''
            if assessment.control.control_id.lower() in hay: score=0.95; reason='Control identifier matched finding metadata.'
            elif finding.cwe_id and finding.cwe_id.lower() in control_text: score=0.9; reason='CWE mapped to control metadata.'
            elif any(token and token in hay for token in control_text.split() if len(token)>4): score=0.65; reason='Control/finding deterministic keyword rule matched.'
            if score>=0.65:
                _,was_created=ComplianceMapping.objects.update_or_create(assessment=assessment,vulnerability=finding,defaults={'mapping_reason':reason,'confidence':score,'source':'deterministic_rule'}); created+=int(was_created)
    return created


def executive_snapshot(project,organization):
    qs=Vulnerability.objects.filter(project=project); active=qs.exclude(status__in=[Vulnerability.Status.FIXED,Vulnerability.Status.FALSE_POSITIVE,Vulnerability.Status.ACCEPTED_RISK,Vulnerability.Status.WONT_FIX,Vulnerability.Status.DUPLICATE]); critical=active.filter(severity=Vulnerability.Severity.CRITICAL).count(); high=active.filter(severity=Vulnerability.Severity.HIGH).count(); risk=sum(float(x.risk_score) for x in active); validated=qs.filter(validation_status='validated').count(); fixed=qs.filter(status=Vulnerability.Status.FIXED).count(); total_assets=project.assets.count(); scanned=Scan.objects.filter(project=project,status=Scan.Status.COMPLETED).values('asset_id').distinct().count(); coverage=round(scanned/total_assets*100,2) if total_assets else 0.0; assessed=ComplianceAssessment.objects.filter(project=project).exclude(status=ComplianceAssessment.Status.NOT_ASSESSED); compliant=assessed.filter(status=ComplianceAssessment.Status.COMPLIANT).count(); partial=assessed.filter(status=ComplianceAssessment.Status.PARTIAL).count(); compliance=round((compliant+partial*0.5)/assessed.count()*100,2) if assessed.exists() else 0.0; score=max(0.0,min(100.0,100.0-risk)); previous=ExecutiveSnapshot.objects.filter(project=project).order_by('-captured_at').first(); delta=round(score-(previous.score if previous else score),2); return ExecutiveSnapshot.objects.create(organization=organization,project=project,score=round(score,2),risk=round(risk,2),critical_findings=critical,high_findings=high,open_findings=active.count(),validated_findings=validated,fixed_findings=fixed,compliance_score=compliance,coverage_score=coverage,trend='improving' if delta>0 else 'declining' if delta<0 else 'stable',deltas={'score':delta,'risk':round(risk-(previous.risk if previous else risk),2)},source_scan=Scan.objects.filter(project=project,status=Scan.Status.COMPLETED).order_by('-completed_at').first())


def schedule_task(schedule:ReportSchedule):
    if schedule.frequency=='cron': raise ValueError('Cron report schedules require an explicit CrontabSchedule configuration')
    minutes={'daily':1440,'weekly':10080,'monthly':43200}.get(schedule.frequency)
    if not minutes: raise ValueError(f'Unsupported report schedule frequency: {schedule.frequency}')
    interval,_=IntervalSchedule.objects.get_or_create(every=minutes,period=IntervalSchedule.MINUTES)
    PeriodicTask.objects.update_or_create(name=f'aegis-report:{schedule.id}',defaults={'interval':interval,'task':'enterprise.execute_report_schedule','kwargs':json.dumps({'schedule_id':str(schedule.id)}),'enabled':schedule.enabled,'start_time':schedule.next_run})


def _http_json(provider,method,url,**kwargs):
    started=time.monotonic(); response=None
    try:
        response=requests.request(method,url,timeout=20,**kwargs); response.raise_for_status(); payload=response.json(); digest=hashlib.sha256(response.content).hexdigest(); return payload,response.status_code,digest,int((time.monotonic()-started)*1000),''
    except Exception as exc: return {},getattr(response,'status_code',None),'',int((time.monotonic()-started)*1000),str(exc)


def fetch_intel(provider:str,key:str,cve:str|None=None,package:dict|None=None):
    now=timezone.now(); cached=ThreatIntelCache.objects.filter(provider=provider,key=key,expires_at__gt=now).first()
    if cached:return cached.payload
    throttle={'nvd':6,'epss':1,'kev':60,'osv':0}.get(provider,1)
    if throttle and not cache.add(f'aegis:intel:throttle:{provider}',1,timeout=throttle): raise RuntimeError(f'{provider} provider is rate-limited; retry after the configured throttle window')
    headers={}; params={}; body=None; method='GET'; url=PROVIDERS[provider]
    if provider=='nvd':
        params={'cveId':cve} if cve else {'resultsPerPage':1}
        if os.getenv('NVD_API_KEY'): headers['apiKey']=os.environ['NVD_API_KEY']
    elif provider=='epss': params={'cve':cve}
    elif provider=='osv':
        if cve: url=f"{PROVIDERS['osv_vuln']}/{cve}"
        else: method='POST'; body={'package':package} if package else {'package':{'name':key,'ecosystem':'PyPI'}}
    payload,status,digest,duration,error=_http_json(provider,method,url,params=params,json=body,headers=headers) if method=='POST' else _http_json(provider,method,url,params=params,headers=headers)
    ThreatIntelAudit.objects.create(provider=provider,operation='fetch',key=key,response_status=status,duration_ms=duration,error_message=error)
    if error: raise RuntimeError(f'{provider} provider request failed: {error}')
    cache_obj,_=ThreatIntelCache.objects.update_or_create(provider=provider,key=key,defaults={'payload':payload,'fetched_at':now,'expires_at':now+timedelta(minutes=15 if provider in {'kev','epss'} else 360),'http_status':status,'sha256':digest}); return cache_obj.payload


def fuse_finding(finding:Vulnerability):
    intel,_=FindingIntelligence.objects.get_or_create(vulnerability=finding); cves=list(finding.cve_ids or []); primary=cves[0] if cves else None
    intel.nvd=fetch_intel('nvd',primary,cve=primary) if primary else {}; intel.osv=fetch_intel('osv',primary,cve=primary) if primary else {}; intel.epss=fetch_intel('epss',primary,cve=primary) if primary else {}; kev=fetch_intel('kev','global'); rows=kev.get('vulnerabilities',[]) if isinstance(kev,dict) else []; intel.cisa_kev=next((x for x in rows if primary and x.get('cveID')==primary),{})
    epss_rows=intel.epss.get('data',[]) if isinstance(intel.epss,dict) else []; epss_score=float(epss_rows[0].get('epss',0)) if epss_rows else 0.0; nvd_hit=bool(intel.nvd); osv_hit=bool(intel.osv); kev_hit=bool(intel.cisa_kev); signals=sum([nvd_hit,osv_hit,kev_hit,epss_score>0]); intel.confidence=round(min(100.0,25.0*signals+25.0*(epss_score>0.5)),2); intel.conflict=bool(kev_hit and epss_score<0.01); intel.explanation=f'NVD={nvd_hit}; OSV={osv_hit}; CISA KEV={kev_hit}; EPSS={epss_score:.4f}.'; intel.recommendation='Prioritize immediate remediation.' if kev_hit or epss_score>=0.5 else 'Review and remediate according to project risk policy.'; intel.save(); return intel

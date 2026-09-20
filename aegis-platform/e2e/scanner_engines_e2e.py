#!/usr/bin/env python3
"""Authorized black-box E2E for all four scanner engines."""
from __future__ import annotations
import os,sys,time,uuid
from typing import Any
import requests
BASE=os.getenv('AEGIS_BASE_URL','http://localhost'); API_ROOT=os.getenv('AEGIS_FASTAPI_URL',BASE); API=f'{API_ROOT}/api/v1'; DJANGO=os.getenv('AEGIS_DJANGO_URL',f'{BASE}/api/v1'); TARGET=os.getenv('AEGIS_E2E_TARGET','aegis-scan-target'); MASSCAN_TARGET=os.getenv('AEGIS_MASSCAN_TARGET','10.251.0.10'); TIMEOUT=int(os.getenv('AEGIS_E2E_TIMEOUT','600')); VERIFY=os.getenv('AEGIS_VERIFY_TLS','true').lower() not in {'0','false','no'}; EMAIL=os.environ['AEGIS_E2E_EMAIL']; PASSWORD=os.environ['AEGIS_E2E_PASSWORD']; GOV_ORG_ID=os.environ['AEGIS_E2E_GOV_ORG_ID']; APPROVER_MEMBERSHIP_ID=os.environ['AEGIS_E2E_APPROVER_MEMBERSHIP_ID']; APPROVER_EMAIL=os.environ['AEGIS_E2E_APPROVER_EMAIL']; APPROVER_PASSWORD=os.environ['AEGIS_E2E_APPROVER_PASSWORD']
def req(s:requests.Session,method:str,url:str,expected:set[int],**kwargs)->dict[str,Any]|list[Any]:
 r=s.request(method,url,timeout=30,verify=VERIFY,**kwargs); print(f'E2E_HTTP stage="{method} {url}" status={r.status_code}',flush=True)
 if r.status_code not in expected: raise RuntimeError(f'{method} {url} failed HTTP {r.status_code}: {r.text[:1000]}')
 if not r.text:return {}
 try:return r.json()
 except ValueError as exc:raise RuntimeError(f'Non-JSON response from {url}: {r.text[:1000]}') from exc
def collection(data:dict[str,Any]|list[Any],label:str)->list[dict[str,Any]]:
 if isinstance(data,list): return data
 if isinstance(data,dict) and isinstance(data.get('results'),list): return data['results']
 raise RuntimeError(f'{label} response contract invalid: expected list or paginated results, got {type(data).__name__}: {data!r}')
def csrf(s):
 data=req(s,'GET',f'{DJANGO}/auth/csrf/',{200}); token=data.get('csrfToken') if isinstance(data,dict) else None; token=token or s.cookies.get('csrftoken')
 if not token:raise RuntimeError('CSRF token missing')
 return token
def asset(s,project_id,name,asset_type,configuration,tags):
 data=req(s,'POST',f'{API}/assets/',{201},json={'project_id':project_id,'name':name,'type':asset_type,'environment':'development','criticality':'medium','configuration':configuration,'tags':tags}); aid=data.get('id') if isinstance(data,dict) else None
 if not aid: raise RuntimeError(f'Asset creation did not return id: {data!r}')
 return str(aid)
def authorize(s,approver,project_id,asset_id,marker):
 request_id=str(uuid.uuid4())
 proposal=req(s,'POST',f'{API}/assets/{asset_id}/authorization',{202},json={'authorized':True,'reason':f'CI controlled real scanner target ({marker})'},headers={'X-Request-ID':request_id})
 governed=proposal.get('governed_action') if isinstance(proposal,dict) else None
 if not isinstance(governed,dict) or governed.get('action_id')!='asset.authorization.approve': raise RuntimeError(f'{marker} authorization proposal contract invalid: {proposal!r}')
 executed=req(approver,'POST',f'{API}/assurance/governance/actions/execute',{200},json={'action_id':'asset.authorization.approve','project_id':project_id,'entity_type':'asset','entity_id':asset_id,'expected_version':governed['expected_version'],'idempotency_key':f'scanner-e2e-authorization-execute-{marker}-{request_id}','request_id':governed['request_id'],'parameters':governed['parameters']})
 result=executed.get('result') if isinstance(executed,dict) else None
 decision_id=str(result.get('authorization_decision_id') or '') if isinstance(result,dict) else ''
 if not decision_id: raise RuntimeError(f'{marker} governed authorization execution did not return a durable decision: {executed!r}')
 if str(executed.get('request_id') or '')!=str(governed['request_id']): raise RuntimeError(f'{marker} governed authorization lost request lineage: {executed!r}')
 history=collection(req(s,'GET',f'{API}/assets/{asset_id}/authorization',{200}),f'{asset_id} authorization history')
 current=next((item for item in history if str(item.get('id') or '')==decision_id),None)
 if not current or current.get('authorized') is not True or current.get('currently_valid') is not True: raise RuntimeError(f'{marker} authoritative authorization decision missing or invalid for {asset_id}: {history!r}')
 return decision_id
def main()->int:
 s=requests.Session(); token=csrf(s); headers={'X-CSRFToken':token,'Referer':f'{BASE}/'}; req(s,'POST',f'{DJANGO}/auth/login/',{200},json={'email':EMAIL,'password':PASSWORD},headers=headers); token=csrf(s); headers['X-CSRFToken']=token
 project=req(s,'POST',f'{DJANGO}/projects/',{201},json={'name':f'Scanner Engine E2E {uuid.uuid4().hex[:10]}','description':'Authorized scanner engine black-box E2E','environment':'development'},headers=headers); pid=str(project['id'])
 binding=req(s,'POST',f'{API}/enterprise/projects/{pid}/tenant',{200},params={'organization_id':GOV_ORG_ID})
 if str(binding.get('organization_id') or '')!=GOV_ORG_ID: raise RuntimeError(f'Project tenant binding did not persist: {binding!r}')
 grant=req(s,'POST',f'{API}/assurance/governance/responsibilities/grants',{200},json={'organization_id':GOV_ORG_ID,'membership_id':APPROVER_MEMBERSHIP_ID,'responsibility':'authorization_approver','scope_kind':'project','project_id':pid,'reason':'Independent scanner E2E asset authorization approval duty.','idempotency_key':f'scanner-e2e-authorization-responsibility-{pid}'})
 if str(grant.get('membership_id') or '')!=APPROVER_MEMBERSHIP_ID or grant.get('responsibility')!='authorization_approver': raise RuntimeError(f'Authorization responsibility grant did not persist: {grant!r}')
 approver=requests.Session(); approver.verify=VERIFY; approver_csrf=csrf(approver); approver_headers={'X-CSRFToken':approver_csrf,'Referer':f'{BASE}/'}; req(approver,'POST',f'{DJANGO}/auth/login/',{200},json={'email':APPROVER_EMAIL,'password':APPROVER_PASSWORD},headers=approver_headers)
 nmap_asset=asset(s,pid,'Nmap target','ip_address',{'host':TARGET},['e2e','nmap']); nmap_auth=authorize(s,approver,pid,nmap_asset,'nmap')
 masscan_asset=asset(s,pid,'Masscan target','network_range',{'cidr':MASSCAN_TARGET},['e2e','masscan']); masscan_auth=authorize(s,approver,pid,masscan_asset,'masscan')
 nuclei_asset=asset(s,pid,'Nuclei target','website',{'url':f'http://{TARGET}'},['e2e','nuclei']); nuclei_auth=authorize(s,approver,pid,nuclei_asset,'nuclei')
 semgrep_asset=asset(s,pid,'Backend Source','source_code',{'path':'/app/e2e'},['e2e','semgrep']); semgrep_auth=authorize(s,approver,pid,semgrep_asset,'semgrep')
 specs=[('nmap','ip',{'host':TARGET},nmap_asset,'quick',nmap_auth),('masscan','network',{'host':MASSCAN_TARGET,'ports':'80','rate':1000},masscan_asset,'quick',masscan_auth),('nuclei','url',{'url':f'http://{TARGET}'},nuclei_asset,'standard',nuclei_auth),('semgrep','code',{'path':'/app/e2e'},semgrep_asset,'standard',semgrep_auth)]; scans=[]
 for engine,scan_type,config,asset_id,depth,authorization_id in specs:
  created=req(s,'POST',f'{API}/scans/',{201},json={'project_id':pid,'name':f'E2E {engine}','scan_type':scan_type,'asset_id':asset_id,'engines':[engine],'depth':depth,'config':config})
  if str(created.get('authorization_decision_id') or '') != authorization_id: raise RuntimeError(f'{engine} scan creation lost authorization binding: expected={authorization_id} response={created!r}')
  scans.append((engine,created['id'],authorization_id))
 results={}
 for engine,sid,authorization_id in scans:
  print(f'ENGINE_START engine={engine} scan_id={sid}',flush=True); deadline=time.monotonic()+TIMEOUT; state={}
  while time.monotonic()<deadline:
   state=req(s,'GET',f'{API}/scans/{sid}',{200}); print(f'ENGINE_STATE engine={engine} status={state.get("status")} progress={state.get("progress")}',flush=True)
   if state.get('status') in {'completed','failed','cancelled','partial'}:break
   time.sleep(2)
  executions=collection(req(s,'GET',f'{API}/scans/{sid}/engine-executions',{200}),f'{engine} execution'); matching=[item for item in executions if item.get('engine')==engine]; diagnostic={'scan':state,'executions':executions}; print(f'ENGINE_DIAGNOSTIC engine={engine} diagnostic={diagnostic}',flush=True)
  if state.get('status')!='completed':raise RuntimeError(f'{engine} scan {sid} ended in {state.get("status")}: {diagnostic}')
  if not matching or any(item.get('status')!='completed' for item in matching):raise RuntimeError(f'{engine} execution contract invalid: {diagnostic}')
  evidence=collection(req(s,'GET',f'{API}/evidence/',{200},params={'scan_id':sid,'limit':500}),f'{engine} evidence'); scanner=[x for x in evidence if x.get('source')==engine]
  if not scanner:raise RuntimeError(f'{engine} produced no persisted evidence: {diagnostic}; evidence={evidence}')
  for item in scanner:
   if len(item.get('sha256',''))!=64 or item.get('scan_id')!=sid:raise RuntimeError(f'{engine} evidence provenance invalid: {item}')
  result_data=matching[0].get('result_data') or {}
  if str(result_data.get('authorization_decision_id') or '') != authorization_id: raise RuntimeError(f'{engine} execution authorization provenance mismatch: expected={authorization_id} execution={matching[0]}')
  results[engine]={'scan_id':sid,'findings_count':state.get('findings_count',0),'evidence_count':len(scanner),'authorization_decision_id':result_data.get('authorization_decision_id')}
 print('SCANNER_ENGINES_REAL_E2E=PASS');print(f'project_id={pid}');print(results);return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as exc:print(f'SCANNER_ENGINES_REAL_E2E=FAIL: {exc}',file=sys.stderr);raise

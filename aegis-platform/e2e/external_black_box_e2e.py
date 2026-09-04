#!/usr/bin/env python3
"""Real HTTP-only AegisScan E2E harness."""
from __future__ import annotations
import os,sys,time,uuid
from typing import Any
import requests
BASE_URL=os.getenv('AEGIS_BASE_URL','http://localhost'); DJANGO_URL=os.getenv('AEGIS_DJANGO_URL',f'{BASE_URL}/api/v1'); API_URL=os.getenv('AEGIS_FASTAPI_URL',BASE_URL); API_V1=f'{API_URL}/api/v1'; TARGET=os.getenv('AEGIS_E2E_TARGET','aegis-scan-target'); TIMEOUT=int(os.getenv('AEGIS_E2E_TIMEOUT','180')); VERIFY_TLS=os.getenv('AEGIS_VERIFY_TLS','true').lower() not in {'0','false','no'}; E2E_EMAIL=os.getenv('AEGIS_E2E_EMAIL'); E2E_PASSWORD=os.getenv('AEGIS_E2E_PASSWORD')
def require(response:requests.Response,expected:set[int],label:str)->dict[str,Any]|list[Any]:
 if response.status_code not in expected: raise RuntimeError(f'{label} failed: HTTP {response.status_code}: {response.text[:1000]}')
 if not response.text:return {}
 try:return response.json()
 except ValueError as exc:raise RuntimeError(f'{label} returned non-JSON response: {response.text[:1000]}') from exc
def http(session:requests.Session,method:str,url:str,label:str,expected:set[int],**kwargs)->dict[str,Any]|list[Any]:
 response=session.request(method,url,**kwargs); print(f'E2E_HTTP stage="{label}" method={method} status={response.status_code} url={url}',flush=True); return require(response,expected,label)
def csrf(session:requests.Session)->str:
 data=http(session,'GET',f'{DJANGO_URL}/auth/csrf/','CSRF bootstrap',{200},timeout=15,verify=VERIFY_TLS); token=data.get('csrfToken') if isinstance(data,dict) else None; token=token or session.cookies.get('csrftoken')
 if not token:raise RuntimeError('CSRF token was not issued')
 return token
def collection(data:dict[str,Any]|list[Any],label:str)->list[dict[str,Any]]:
 if isinstance(data,list): return data
 if isinstance(data,dict) and isinstance(data.get('results'),list): return data['results']
 raise RuntimeError(f'{label} response contract invalid: expected list or paginated results, got {type(data).__name__}')
def main()->int:
 session=requests.Session(); session.verify=VERIFY_TLS; http(session,'GET',f'{API_URL}/ready','FastAPI readiness',{200},timeout=15); http(session,'GET',f'{API_URL}/health','FastAPI health',{200},timeout=15)
 csrf_token=csrf(session); unique=uuid.uuid4().hex[:12]; email=E2E_EMAIL or f'e2e-{unique}@aegisscan.local'; password=E2E_PASSWORD or f'Aegis-E2E-{unique}-StrongPass!9'; headers={'X-CSRFToken':csrf_token,'Referer':f'{BASE_URL}/'}
 if not (E2E_EMAIL and E2E_PASSWORD): http(session,'POST',f'{DJANGO_URL}/auth/register/','User registration',{201},json={'email':email,'first_name':'E2E','last_name':'Harness','password':password,'password_confirm':password},headers=headers,timeout=20)
 csrf_token=csrf(session); headers['X-CSRFToken']=csrf_token; http(session,'POST',f'{DJANGO_URL}/auth/login/','Login',{200},json={'email':email,'password':password},headers=headers,timeout=20)
 project=http(session,'POST',f'{DJANGO_URL}/projects/','Project creation',{201},json={'name':f'External E2E {unique}','description':'Real HTTP black-box validation project','environment':'development'},headers=headers,timeout=20); project_id=project['id']
 asset=http(session,'POST',f'{API_V1}/assets/','Nmap asset creation',{201},json={'project_id':project_id,'name':f'External Nmap target {unique}','type':'ip_address','description':'Real E2E target','environment':'development','criticality':'medium','configuration':{'host':TARGET},'tags':['e2e','nmap']},timeout=20); asset_id=asset.get('id') if isinstance(asset,dict) else None
 if not asset_id:raise RuntimeError(f'Asset creation did not return id: {asset!r}')
 authorization=http(session,'POST',f'{API_V1}/assets/{asset_id}/authorization','Authoritative Nmap authorization',{200},json={'authorized':True,'reason':'CI controlled real scanner target'},timeout=20)
 if not isinstance(authorization,dict) or (authorization.get('configuration') or {}).get('authorized') is not True:raise RuntimeError(f'Authorization grant did not persist: {authorization!r}')
 scan=http(session,'POST',f'{API_V1}/scans/','Real Nmap scan creation',{201},json={'project_id':project_id,'name':f'External real Nmap {unique}','scan_type':'ip','asset_id':asset_id,'engines':['nmap'],'depth':'quick','config':{'host':TARGET}},timeout=20); scan_id=scan.get('id') if isinstance(scan,dict) else None
 if not scan_id:raise RuntimeError('Scan creation did not return id')
 deadline=time.monotonic()+TIMEOUT; last={}
 while time.monotonic()<deadline:
  last=http(session,'GET',f'{API_V1}/scans/{scan_id}','Scan polling',{200},timeout=20)
  if isinstance(last,dict) and last.get('status') in {'completed','failed','cancelled','partial'}:break
  time.sleep(2)
 else:raise RuntimeError(f'Nmap scan timed out after {TIMEOUT}s; last state={last}')
 if not isinstance(last,dict) or last.get('status')!='completed':raise RuntimeError(f'Nmap scan did not complete successfully: {last}')
 if int(last.get('findings_count',0))<1:raise RuntimeError(f'Expected at least one real Nmap finding, got {last}')
 findings_data=http(session,'GET',f'{API_V1}/vulnerabilities/','Finding retrieval',{200},params={'project_id':project_id,'scan_id':scan_id,'limit':200},timeout=20); findings=collection(findings_data,'Finding retrieval')
 if not findings:raise RuntimeError('Scan completed but no finding was returned for the scan')
 finding=findings[0]; finding_id=finding.get('id')
 if finding.get('scan_id')!=scan_id:raise RuntimeError(f'Finding provenance mismatch: finding.scan_id={finding.get("scan_id")} scan={scan_id}')
 evidence_data=http(session,'GET',f'{API_V1}/vulnerabilities/{finding_id}/evidences','Evidence retrieval',{200},timeout=20); evidence=collection(evidence_data,'Evidence retrieval')
 scanner_evidence=[item for item in evidence if item.get('source')=='nmap']
 if not scanner_evidence:raise RuntimeError(f'No Nmap evidence found: {evidence_data}')
 for item in scanner_evidence:
  if item.get('finding_id')!=finding_id or len(item.get('sha256',''))!=64 or item.get('evidence_type')!='scanner_output':raise RuntimeError(f'Evidence provenance invalid: {item}')
 executions=collection(http(session,'GET',f'{API_V1}/scans/{scan_id}/engine-executions','Nmap execution retrieval',{200},timeout=20),'Nmap executions'); matching=[x for x in executions if x.get('engine')=='nmap']
 if not matching or matching[0].get('status')!='completed':raise RuntimeError(f'Nmap execution contract invalid: {executions}')
 auth_id=matching[0].get('result_data',{}).get('authorization_decision_id');
 if not auth_id:raise RuntimeError(f'Nmap execution lost authorization provenance: {matching[0]}')
 print('EXTERNAL_REAL_E2E=PASS'); print(f'project_id={project_id}'); print(f'asset_id={asset_id}'); print(f'scan_id={scan_id}'); print(f'finding_id={finding_id}'); print(f'evidence_count={len(scanner_evidence)}'); print(f'authorization_decision_id={auth_id}'); print(f'target={TARGET}'); return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as exc:print(f'EXTERNAL_REAL_E2E=FAIL: {exc}',file=sys.stderr,flush=True);raise

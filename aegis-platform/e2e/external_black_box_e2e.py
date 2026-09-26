#!/usr/bin/env python3
"""Real HTTP-only AegisScan E2E harness."""
from __future__ import annotations
import json,os,sys,time,uuid
from pathlib import Path
from typing import Any
import requests
BASE_URL=os.getenv('AEGIS_BASE_URL','http://localhost'); DJANGO_URL=os.getenv('AEGIS_DJANGO_URL',f'{BASE_URL}/api/v1'); API_URL=os.getenv('AEGIS_FASTAPI_URL',BASE_URL); API_V1=f'{API_URL}/api/v1'; TARGET=os.getenv('AEGIS_E2E_TARGET','aegis-scan-target'); TIMEOUT=int(os.getenv('AEGIS_E2E_TIMEOUT','180')); VERIFY_TLS=os.getenv('AEGIS_VERIFY_TLS','true').lower() not in {'0','false','no'}; E2E_EMAIL=os.getenv('AEGIS_E2E_EMAIL'); E2E_PASSWORD=os.getenv('AEGIS_E2E_PASSWORD'); E2E_APPROVER_EMAIL=os.getenv('AEGIS_E2E_APPROVER_EMAIL'); E2E_APPROVER_PASSWORD=os.getenv('AEGIS_E2E_APPROVER_PASSWORD'); E2E_GOV_ORG_ID=os.getenv('AEGIS_E2E_GOV_ORG_ID'); E2E_APPROVER_MEMBERSHIP_ID=os.getenv('AEGIS_E2E_APPROVER_MEMBERSHIP_ID'); STATE_PATH=os.getenv('AEGIS_E2E_STATE_PATH','').strip(); EPHEMERAL_FIXTURE=os.getenv('AEGIS_E2E_EPHEMERAL_FIXTURE','').lower() in {'1','true','yes','on'}; CLEANUP_ONLY=os.getenv('AEGIS_E2E_CLEANUP_ONLY','').lower() in {'1','true','yes','on'}; CAPACITY_MODE=os.getenv('AEGIS_E2E_CAPACITY_MODE','').lower() in {'1','true','yes','on'}
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
def prove_detection_response(session:requests.Session,email:str,password:str)->str:
 attack=requests.Session(); attack.verify=VERIFY_TLS; attack_token=csrf(attack); attack_headers={'X-CSRFToken':attack_token,'Referer':f'{BASE_URL}/'}
 for number in range(5):
  http(attack,'POST',f'{DJANGO_URL}/auth/login/',f'Rejected login {number+1}',{401},json={'email':email,'password':f'{password}-rejected'},headers=attack_headers,timeout=20)
 events=http(session,'GET',f'{API_V1}/security-events','Security detection retrieval',{200},params={'status':'new','severity':'high','limit':50},timeout=20)
 if not isinstance(events,dict) or not isinstance(events.get('items'),list):raise RuntimeError(f'Security event collection contract invalid: {events!r}')
 matching=[item for item in events['items'] if item.get('event_type')=='brute_force' and item.get('target_user_email')==email]
 if len(matching)!=1:raise RuntimeError(f'Expected one tenant-scoped identity detection, got {matching!r}')
 event=matching[0]; event_id=event.get('id')
 deadline=time.monotonic()+60; delivered=None
 while time.monotonic()<deadline:
  notifications=http(session,'GET',f'{API_V1}/enterprise/notifications','Detection notification retrieval',{200},params={'limit':200},timeout=20)
  rows=notifications if isinstance(notifications,list) else []
  delivered=next((item for item in rows if (item.get('payload') or {}).get('security_event_id')==event_id),None)
  if delivered and delivered.get('status')=='sent':break
  time.sleep(1)
 if not delivered or delivered.get('status')!='sent':raise RuntimeError(f'Detection notification was not durably delivered: {delivered!r}')
 if (delivered.get('payload') or {}).get('action_url')!='/security-events':raise RuntimeError(f'Notification response link is invalid: {delivered!r}')
 investigating=http(session,'POST',f'{API_V1}/security-events/{event_id}/transition','Start security investigation',{200},json={'status':'investigating'},timeout=20)
 if investigating.get('status')!='investigating':raise RuntimeError(f'Investigation transition did not persist: {investigating!r}')
 notes='External E2E contained the simulated authentication source and verified the target account.'
 resolved=http(session,'POST',f'{API_V1}/security-events/{event_id}/transition','Resolve security event',{200},json={'status':'resolved','resolution_notes':notes},timeout=20)
 if resolved.get('status')!='resolved' or resolved.get('resolution_notes')!=notes or not resolved.get('resolved_at'):raise RuntimeError(f'Resolution evidence did not persist: {resolved!r}')
 http(session,'POST',f'{API_V1}/security-events/{event_id}/transition','Reject terminal event reopen',{409},json={'status':'investigating'},timeout=20)
 final=http(session,'GET',f'{API_V1}/security-events/{event_id}','Resolved security event retrieval',{200},timeout=20)
 if final.get('status')!='resolved':raise RuntimeError(f'Terminal security event state was not durable: {final!r}')
 print(f'security_event_id={event_id}'); print(f'notification_id={delivered.get("id")}'); return str(event_id)
def _deactivate_ephemeral_account(email:str,password:str,label:str)->None:
 session=requests.Session(); session.verify=VERIFY_TLS; token=csrf(session); headers={'X-CSRFToken':token,'Referer':f'{BASE_URL}/'}
 http(session,'POST',f'{DJANGO_URL}/auth/login/',f'{label} login for cleanup',{200},json={'email':email,'password':password},headers=headers,timeout=20)
 token=csrf(session); headers['X-CSRFToken']=token
 http(session,'POST',f'{DJANGO_URL}/auth/deactivate-self/',f'{label} self-deactivation',{200},json={'password':password},headers=headers,timeout=20)

def main()->int:
 if CLEANUP_ONLY:
  if not all([E2E_EMAIL,E2E_PASSWORD,E2E_APPROVER_EMAIL,E2E_APPROVER_PASSWORD]):
   print('EXTERNAL_E2E_CLEANUP=SKIPPED_NO_FIXTURE'); return 0
  _deactivate_ephemeral_account(E2E_APPROVER_EMAIL,E2E_APPROVER_PASSWORD,'Governance approver')
  _deactivate_ephemeral_account(E2E_EMAIL,E2E_PASSWORD,'E2E actor')
  print('EXTERNAL_E2E_CLEANUP=PASS'); return 0
 if CAPACITY_MODE and not all([E2E_EMAIL,E2E_PASSWORD,E2E_APPROVER_EMAIL,E2E_APPROVER_PASSWORD]):
  raise RuntimeError('Capacity mode requires pre-provisioned actor and approver credentials')
 session=requests.Session(); session.verify=VERIFY_TLS; http(session,'GET',f'{API_URL}/ready','FastAPI readiness',{200},timeout=15); http(session,'GET',f'{API_URL}/health','FastAPI health',{200},timeout=15)
 csrf_token=csrf(session); unique=uuid.uuid4().hex[:12]; email=E2E_EMAIL or f'e2e-{unique}@aegisscan.local'; password=E2E_PASSWORD or f'Aegis-E2E-{unique}-StrongPass!9'; approver_email=E2E_APPROVER_EMAIL or f'e2e-approver-{unique}@aegisscan.local'; approver_password=E2E_APPROVER_PASSWORD or f'Aegis-E2E-Approver-{unique}-StrongPass!7'; headers={'X-CSRFToken':csrf_token,'Referer':f'{BASE_URL}/'}
 if not (E2E_EMAIL and E2E_PASSWORD): http(session,'POST',f'{DJANGO_URL}/auth/register/','User registration',{201},json={'email':email,'first_name':'E2E','last_name':'Harness','password':password,'password_confirm':password},headers=headers,timeout=20)
 approver_bootstrap=requests.Session(); approver_bootstrap.verify=VERIFY_TLS; approver_bootstrap_token=csrf(approver_bootstrap); approver_bootstrap_headers={'X-CSRFToken':approver_bootstrap_token,'Referer':f'{BASE_URL}/'}
 if not (E2E_APPROVER_EMAIL and E2E_APPROVER_PASSWORD): http(approver_bootstrap,'POST',f'{DJANGO_URL}/auth/register/','Governance approver registration',{201},json={'email':approver_email,'first_name':'E2E','last_name':'Approver','password':approver_password,'password_confirm':approver_password},headers=approver_bootstrap_headers,timeout=20)
 csrf_token=csrf(session); headers['X-CSRFToken']=csrf_token; http(session,'POST',f'{DJANGO_URL}/auth/login/','Login',{200},json={'email':email,'password':password},headers=headers,timeout=20)
 project=http(session,'POST',f'{DJANGO_URL}/projects/','Project creation',{201},json={'name':f'External E2E {unique}','description':'Real HTTP black-box validation project','environment':'development'},headers=headers,timeout=20); project_id=project['id']
 created_organization=http(session,'POST',f'{API_V1}/enterprise/organizations','Tenant creation',{201},json={'name':f'External E2E API Tenant {unique}','slug':f'external-e2e-api-{unique}'},timeout=20)
 if not isinstance(created_organization,dict) or not created_organization.get('id'):raise RuntimeError(f'Tenant creation did not return id: {created_organization!r}')
 organization_id=E2E_GOV_ORG_ID or str(created_organization['id'])
 approver_membership_id=E2E_APPROVER_MEMBERSHIP_ID
 if not approver_membership_id:
  membership=http(session,'POST',f'{API_V1}/enterprise/organizations/{organization_id}/members','Governance approver organization membership',{201},json={'email':approver_email,'role':'admin'},timeout=20)
  approver_membership_id=membership.get('id') if isinstance(membership,dict) else None
  if not approver_membership_id:raise RuntimeError(f'Governance approver membership did not return id: {membership!r}')
 binding=http(session,'POST',f'{API_V1}/enterprise/projects/{project_id}/tenant','Project tenant binding',{200},params={'organization_id':organization_id},timeout=20)
 if binding.get('organization_id')!=organization_id:raise RuntimeError(f'Project tenant binding did not persist: {binding!r}')
 grant=http(session,'POST',f'{API_V1}/assurance/governance/responsibilities/grants','Governed authorization responsibility grant',{200},json={'organization_id':organization_id,'membership_id':approver_membership_id,'responsibility':'authorization_approver','scope_kind':'project','project_id':project_id,'reason':'Independent CI asset authorization approval duty.','idempotency_key':f'e2e-authorization-responsibility-{unique}'},timeout=20)
 if grant.get('membership_id')!=approver_membership_id or grant.get('responsibility')!='authorization_approver':raise RuntimeError(f'Authorization responsibility grant did not persist: {grant!r}')
 asset=http(session,'POST',f'{API_V1}/assets/','Nmap asset creation',{201},json={'project_id':project_id,'name':f'External Nmap target {unique}','type':'ip_address','description':'Real E2E target','environment':'development','criticality':'medium','configuration':{'host':TARGET},'tags':['e2e','nmap']},timeout=20); asset_id=asset.get('id') if isinstance(asset,dict) else None
 if not asset_id:raise RuntimeError(f'Asset creation did not return id: {asset!r}')
 proposal=http(session,'POST',f'{API_V1}/assets/{asset_id}/authorization','Submit governed Nmap authorization',{202},json={'authorized':True,'reason':'CI controlled real scanner target'},timeout=20)
 governed_request=proposal.get('governed_action') if isinstance(proposal,dict) else None
 if not isinstance(governed_request,dict) or governed_request.get('action_id')!='asset.authorization.approve':raise RuntimeError(f'Authorization proposal contract invalid: {proposal!r}')
 approver=requests.Session(); approver.verify=VERIFY_TLS; approver_token=csrf(approver); approver_headers={'X-CSRFToken':approver_token,'Referer':f'{BASE_URL}/'}
 http(approver,'POST',f'{DJANGO_URL}/auth/login/','Governance approver login',{200},json={'email':approver_email,'password':approver_password},headers=approver_headers,timeout=20)
 authorization_execution=http(approver,'POST',f'{API_V1}/assurance/governance/actions/execute','Execute governed Nmap authorization',{200},json={'action_id':'asset.authorization.approve','project_id':project_id,'entity_type':'asset','entity_id':asset_id,'expected_version':governed_request['expected_version'],'idempotency_key':f'e2e-authorization-execute-{unique}','request_id':governed_request['request_id'],'parameters':governed_request['parameters']},timeout=20)
 authorization_result=authorization_execution.get('result') if isinstance(authorization_execution,dict) else None
 authorization_decision_id=authorization_result.get('authorization_decision_id') if isinstance(authorization_result,dict) else None
 if not authorization_decision_id:raise RuntimeError(f'Governed authorization execution did not return a durable decision: {authorization_execution!r}')
 if authorization_execution.get('request_id')!=governed_request['request_id']:raise RuntimeError(f'Governed authorization lost request lineage: {authorization_execution!r}')
 if CAPACITY_MODE:
  print('CAPACITY_IDENTITY_DETECTION=SKIPPED_BOUNDED_MODE')
 else:
  prove_detection_response(session,email,password)
 idempotency_key=f'e2e-governed-{unique}'; correlation_id=f'e2e-corr-{unique}'
 execution=http(session,'POST',f'{API_V1}/capabilities/network.nmap/execute','Governed Nmap capability execution',{202},json={'project_id':project_id,'asset_id':asset_id,'depth':'quick','options':{},'credential_refs':[],'idempotency_key':idempotency_key,'correlation_id':correlation_id},timeout=20)
 if not isinstance(execution,dict):raise RuntimeError(f'Governed execution response invalid: {execution!r}')
 contract=execution.get('execution_contract') if isinstance(execution.get('execution_contract'),dict) else {}
 scan=execution.get('scan') if isinstance(execution.get('scan'),dict) else {}
 scan_id=scan.get('id')
 if not scan_id:raise RuntimeError(f'Governed execution did not return canonical Scan id: {execution!r}')
 if contract.get('contract_version')!='1.0' or contract.get('policy_version')!='capability-execution.v4':raise RuntimeError(f'Governed execution contract version invalid: {contract!r}')
 if contract.get('capability_id')!='network.nmap' or contract.get('requested_capability_id')!='network.nmap':raise RuntimeError(f'Governed execution capability identity invalid: {contract!r}')
 if contract.get('project_ref')!=f'project:{project_id}' or contract.get('asset_ref')!=f'asset:{asset_id}':raise RuntimeError(f'Governed execution scope identity invalid: {contract!r}')
 if contract.get('idempotency_key')!=idempotency_key or not contract.get('runner_profile'):raise RuntimeError(f'Governed execution transport/runtime identity invalid: {contract!r}')
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
 if str(auth_id)!=str(authorization_decision_id):raise RuntimeError(f'Nmap execution authorization lineage mismatch: expected={authorization_decision_id} actual={auth_id}')
 if STATE_PATH:
  state={'project_id':project_id,'asset_id':asset_id,'capability_id':'network.nmap','depth':'quick','idempotency_key':idempotency_key,'correlation_id':correlation_id,'scan_id':scan_id,'execution_contract':contract,'execution_contract_fingerprint':execution.get('execution_contract_fingerprint'),'policy_version':execution.get('policy_version')}
  state_path=Path(STATE_PATH); state_path.parent.mkdir(parents=True,exist_ok=True); state_path.write_text(json.dumps(state,sort_keys=True,indent=2),encoding='utf-8')
 print('EXTERNAL_REAL_E2E=PASS'); print(f'project_id={project_id}'); print(f'asset_id={asset_id}'); print(f'scan_id={scan_id}'); print(f'finding_id={finding_id}'); print(f'evidence_count={len(scanner_evidence)}'); print(f'authorization_decision_id={auth_id}'); print(f'target={TARGET}'); print(f'governed_contract_fingerprint={execution.get("execution_contract_fingerprint")}'); return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as exc:print(f'EXTERNAL_REAL_E2E=FAIL: {exc}',file=sys.stderr,flush=True);raise

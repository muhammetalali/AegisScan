#!/usr/bin/env python3
"""Authorized black-box E2E for all four scanner engines."""
from __future__ import annotations
import os, sys, time, uuid
from typing import Any
import requests

BASE=os.getenv('AEGIS_BASE_URL','http://localhost'); API=os.getenv('AEGIS_FASTAPI_URL',BASE); DJANGO=os.getenv('AEGIS_DJANGO_URL',f'{BASE}/api/v1'); TARGET=os.getenv('AEGIS_E2E_TARGET','aegis-scan-target'); TIMEOUT=int(os.getenv('AEGIS_E2E_TIMEOUT','600')); VERIFY=os.getenv('AEGIS_VERIFY_TLS','true').lower() not in {'0','false','no'}; EMAIL=os.environ['AEGIS_E2E_EMAIL']; PASSWORD=os.environ['AEGIS_E2E_PASSWORD']

def req(s:requests.Session, method:str, url:str, expected:set[int], **kwargs)->dict[str,Any]:
    r=s.request(method,url,timeout=30,verify=VERIFY,**kwargs)
    if r.status_code not in expected: raise RuntimeError(f'{method} {url} failed HTTP {r.status_code}: {r.text[:1000]}')
    if not r.text:return {}
    try:return r.json()
    except ValueError as exc:raise RuntimeError(f'Non-JSON response from {url}') from exc

def csrf(s):
    data=req(s,'GET',f'{DJANGO}/auth/csrf/',{200}); token=data.get('csrfToken') or s.cookies.get('csrftoken')
    if not token:raise RuntimeError('CSRF token missing')
    return token

def main()->int:
    s=requests.Session(); s.verify=VERIFY; token=csrf(s); headers={'X-CSRFToken':token,'Referer':f'{BASE}/'}
    req(s,'POST',f'{DJANGO}/auth/login/',{200},json={'email':EMAIL,'password':PASSWORD},headers=headers)
    project=req(s,'POST',f'{DJANGO}/projects/',{201},json={'name':f'Scanner Engine E2E {uuid.uuid4().hex[:10]}','description':'Authorized scanner engine black-box E2E','environment':'development'}); pid=str(project['id'])
    assets={}
    assets['semgrep']=req(s,'POST',f'{API}/assets/',{201},json={'project_id':pid,'name':'Backend Source','type':'source_code','environment':'development','criticality':'medium','configuration':{'path':'/app/e2e','authorized':True},'tags':['e2e','semgrep']})
    specs=[
      ('nmap','network',{'target':TARGET},None),
      ('masscan','network',{'target':TARGET,'ports':'80','rate':1000},None),
      ('nuclei','url',{'target':f'http://{TARGET}'},None),
      ('semgrep','code',{'path':'/app/e2e'},str(assets['semgrep']['id'])),
    ]
    scans=[]
    for engine,scan_type,config,asset_id in specs:
        body={'project_id':pid,'name':f'E2E {engine}','scan_type':scan_type,'engines':[engine],'depth':'quick' if engine in {'nmap','masscan'} else 'standard','config':config,'authorized':True}
        if asset_id: body['asset_id']=asset_id
        scans.append((engine,req(s,'POST',f'{API}/scans/',{201},json=body)['id']))
    results={}
    for engine,sid in scans:
        deadline=time.monotonic()+TIMEOUT; state={}
        while time.monotonic()<deadline:
            state=req(s,'GET',f'{API}/scans/{sid}',{200})
            if state.get('status') in {'completed','failed','cancelled','partial'}:break
            time.sleep(2)
        if state.get('status')!='completed': raise RuntimeError(f'{engine} scan {sid} ended in {state.get("status")}: {state}')
        executions=req(s,'GET',f'{API}/scans/{sid}/engine-executions',{200})
        if not executions or executions[0].get('status')!='completed' or executions[0].get('engine')!=engine: raise RuntimeError(f'{engine} execution contract invalid: {executions}')
        evidence=req(s,'GET',f'{API}/evidence/',{200},params={'scan_id':sid,'limit':500})
        scanner=[x for x in evidence if x.get('source')==engine]
        if not scanner: raise RuntimeError(f'{engine} produced no persisted evidence: {evidence}')
        for item in scanner:
            if len(item.get('sha256',''))!=64 or item.get('scan_id')!=sid: raise RuntimeError(f'{engine} evidence provenance invalid: {item}')
        results[engine]={'scan_id':sid,'findings_count':state.get('findings_count',0),'evidence_count':len(scanner)}
    print('SCANNER_ENGINES_REAL_E2E=PASS'); print(f'project_id={pid}'); print(results); return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as exc: print(f'SCANNER_ENGINES_REAL_E2E=FAIL: {exc}',file=sys.stderr); raise

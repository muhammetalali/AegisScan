from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import asyncio
import random

router = APIRouter()

_store: dict[str, dict] = {}
_tasks: dict[str, asyncio.Task] = {}

# ---- Contracts ----

# State machine: QUEUED -> INITIALIZING -> RUNNING -> COMPLETED / FAILED / CANCELLED
# Phases map to engine groups for UI
PHASES = ["queued","initializing","recon","discovery","enumeration","analysis","validation","reporting","completed"]
# engine -> phase mapping
ENGINE_PHASE = {
    "recon": "recon",
    "evidence_collection": "recon",
    "vuln_intelligence": "discovery",
    "validation": "discovery",
    "control_validation": "enumeration",
    "coverage_gap": "enumeration",
    "attack_path": "analysis",
    "evidence_graph": "analysis",
    "knowledge": "analysis",
    "posture": "analysis",
    "policy_compliance": "validation",
    "twin_engine": "validation",
    "scenarios": "validation",
    "dashboard": "reporting",
    "reporting": "reporting",
}

# Grouped for Command Center UI (5 groups as per spec)
GROUPS = [
    {"id": "recon", "label": "Recon", "engines": ["recon","evidence_collection"], "desc": "DNS • Subdomain • Port • Service Discovery"},
    {"id": "discovery", "label": "Discovery", "engines": ["vuln_intelligence","validation"], "desc": "HTTP • Technology • Endpoint • Directory"},
    {"id": "enumeration", "label": "Enumeration", "engines": ["control_validation","coverage_gap"], "desc": "Headers • TLS • Config • Vulnerability"},
    {"id": "analysis", "label": "Analysis", "engines": ["attack_path","evidence_graph","knowledge","posture"], "desc": "Security Checks • Risk Analysis"},
    {"id": "reporting", "label": "Reporting", "engines": ["policy_compliance","twin_engine","scenarios","dashboard","reporting"], "desc": "Findings • Report Generator"},
]

ALL_ENGINES = ["recon","evidence_collection","vuln_intelligence","validation","control_validation","coverage_gap","attack_path","evidence_graph","knowledge","posture","policy_compliance","twin_engine","scenarios","dashboard","reporting"]

class ValidationCreate(BaseModel):
    target_type: str = Field(description="url | ip | code | api")
    target_value: str
    profile: str = Field(default="full")
    engines: List[str] = Field(default_factory=list)
    scope: Optional[str] = None
    authorized: bool = Field(description="Must be true - audit requirement")
    include_subdomains: bool = False
    duration_minutes: int = 60
    rate_limit: int = 5
    extra: dict = Field(default_factory=dict)

class ValidationOut(BaseModel):
    id: str
    target_type: str
    target_value: str
    profile: str
    engines: List[str]
    scope: Optional[str]
    status: str
    progress: int
    current_phase: str
    created_at: str
    audit_note: str

ALLOWED_TYPES = {"url", "ip", "code", "api"}
ALLOWED_PROFILES = {"quick", "full", "custom"}

# ---- Helpers ----

def _now_iso():
    return datetime.utcnow().isoformat()

def _make_live_event(etype: str, message: str, meta: dict | None = None):
    return {"ts": _now_iso(), "type": etype, "message": message, "meta": meta or {}}

def _engine_state(status: str = "pending", progress: int = 0, findings: int = 0, duration: str = "—"):
    return {"status": status, "progress": progress, "findings": findings, "duration": duration}

# Background simulator - advances validation through engines

async def _simulate_validation(vid: str):
    """Simulates enterprise flow: QUEUED -> INITIALIZING -> phases -> COMPLETED. Broadcasts via websocket_manager if available."""
    # lazy import to avoid circular
    try:
        from ..main import websocket_manager  # type: ignore
    except Exception:
        websocket_manager = None

    async def broadcast(msg: dict):
        if websocket_manager:
            try:
                await websocket_manager.broadcast(f"validation_{vid}", msg)
                await websocket_manager.broadcast(f"scan_{vid}", msg)
            except Exception:
                pass

    v = _store.get(vid)
    if not v:
        return

    # validation.started
    v["status"] = "running"
    v["current_phase"] = "initializing"
    v["progress"] = 2
    v["live_events"].append(_make_live_event("validation.started", f"Validation {vid} started", {"target": v["target_value"]}))
    await broadcast({"type": "validation.started", "validation_id": vid, "progress": v["progress"], "current_phase": v["current_phase"]})
    await asyncio.sleep(0.8)

    v["current_phase"] = "recon"
    v["live_events"].append(_make_live_event("phase.started", "Phase RECON started"))
    await broadcast({"type": "phase.started", "phase": "recon"})
    await asyncio.sleep(0.5)

    # iterate engines in order of ALL_ENGINES filtered by selected engines, but keep phase order
    selected = [e for e in ALL_ENGINES if e in v["engines"]]
    total = len(selected) or 1
    for idx, eng in enumerate(selected):
        # check cancelled
        if v.get("status") == "cancelled":
            v["live_events"].append(_make_live_event("validation.failed", "Validation cancelled by user", {"engine": eng}))
            await broadcast({"type": "validation.failed", "reason": "cancelled"})
            return
        phase = ENGINE_PHASE.get(eng, "analysis")
        if v["current_phase"] != phase:
            # phase transition
            prev = v["current_phase"]
            v["current_phase"] = phase
            v["live_events"].append(_make_live_event("phase.completed", f"Phase {prev} completed"))
            v["live_events"].append(_make_live_event("phase.started", f"Phase {phase.upper()} started"))
            await broadcast({"type": "phase.completed", "phase": prev})
            await broadcast({"type": "phase.started", "phase": phase})

        # engine.started
        v["engines_state"][eng]["status"] = "running"
        v["live_events"].append(_make_live_event("engine.started", f"Engine {eng} started", {"engine": eng}))
        await broadcast({"type": "engine.started", "engine": eng, "phase": phase})

        # simulate progress 0->100 in steps
        for p in [25, 55, 78, 100]:
            await asyncio.sleep(random.uniform(0.4, 0.9))
            v["engines_state"][eng]["progress"] = p
            v["progress"] = int(((idx + p/100) / total) * 100)
            # random findings
            if random.random() > 0.6:
                v["engines_state"][eng]["findings"] += random.randint(1, 3)
                msg = random.choice(["Finding correlated", "Evidence collected", "Asset analyzed", "Control validation completed", "Port 443/tcp detected", "HTTP headers analyzed"])
                v["live_events"].append(_make_live_event("finding.created", msg, {"engine": eng}))
                await broadcast({"type": "finding.created", "engine": eng, "message": msg})
            await broadcast({"type": "engine.progress", "engine": eng, "progress": p, "overall": v["progress"]})
            # keep only last 80 events
            if len(v["live_events"]) > 80:
                v["live_events"] = v["live_events"][-80:]

        v["engines_state"][eng]["status"] = "completed"
        v["engines_state"][eng]["progress"] = 100
        v["live_events"].append(_make_live_event("engine.completed", f"Engine {eng} completed", {"engine": eng, "findings": v["engines_state"][eng]["findings"]}))
        await broadcast({"type": "engine.completed", "engine": eng})

    v["status"] = "completed"
    v["current_phase"] = "completed"
    v["progress"] = 100
    v["completed_at"] = _now_iso()
    _generate_results(vid)
    v["live_events"].append(_make_live_event("validation.completed", "Validation completed successfully"))
    await broadcast({"type": "validation.completed", "validation_id": vid, "progress": 100})

# ---- Routes ----

@router.post("/validations", response_model=ValidationOut, status_code=201)
async def create_validation(body: ValidationCreate):
    if body.target_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail=f"target_type must be one of {ALLOWED_TYPES}")
    if body.profile not in ALLOWED_PROFILES:
        raise HTTPException(status_code=400, detail=f"profile must be one of {ALLOWED_PROFILES}")
    if not body.authorized:
        raise HTTPException(status_code=400, detail="authorized must be true - scope authorization required (Audit Log)")
    if not body.target_value or not body.target_value.strip():
        raise HTTPException(status_code=400, detail="target_value is required")
    if not body.engines:
        raise HTTPException(status_code=400, detail="engines must contain at least one engine")

    vid = f"val-{uuid.uuid4().hex[:8]}"
    now = _now_iso()
    engines_state = {e: _engine_state("pending" if e in body.engines else "skipped") for e in ALL_ENGINES}
    # mark selected as queued
    for e in body.engines:
        if e in engines_state:
            engines_state[e]["status"] = "queued"

    item = {
        "id": vid,
        "target_type": body.target_type,
        "target_value": body.target_value,
        "profile": body.profile,
        "engines": body.engines,
        "scope": body.scope or body.target_value,
        "status": "queued",
        "progress": 0,
        "current_phase": "queued",
        "created_at": now,
        "completed_at": None,
        "audit_note": f"Scope={body.scope or body.target_value} authorized={body.authorized} rate={body.rate_limit} duration={body.duration_minutes}m",
        "extra": body.extra,
        "include_subdomains": body.include_subdomains,
        "engines_state": engines_state,
        "live_events": [
            _make_live_event("validation.queued", f"Validation {vid} queued", {"scope": body.scope or body.target_value}),
            _make_live_event("scope.authorized", f"Scope authorized: {body.scope or body.target_value}", {"authorized": True}),
        ],
        "groups": GROUPS,
    }
    _store[vid] = item
    try:
        from .audit import add_audit_entry
        add_audit_entry(user="system", action="validation.create", target=item["scope"] or item["target_value"], project="—", result="success")
    except Exception:
        pass

    # queue enterprise flow: Validate -> Scope Check (done) -> Create Job (done) -> Queue -> start simulator
    # start background progression after short delay
    task = asyncio.create_task(_simulate_validation(vid))
    _tasks[vid] = task

    return ValidationOut(**{k: item[k] for k in ValidationOut.model_fields.keys()})

@router.get("/validations", response_model=List[ValidationOut])
async def list_validations(limit: int = 20):
    vals = sorted(_store.values(), key=lambda x: x["created_at"], reverse=True)[:limit]
    return [ValidationOut(**{k: v[k] for k in ValidationOut.model_fields.keys()}) for v in vals]

@router.get("/validations/{vid}", response_model=ValidationOut)
async def get_validation(vid: str):
    if vid not in _store:
        raise HTTPException(status_code=404, detail="Validation not found")
    v = _store[vid]
    return ValidationOut(**{k: v[k] for k in ValidationOut.model_fields.keys()})

@router.get("/validations/{vid}/progress")
async def get_validation_progress(vid: str):
    if vid not in _store:
        raise HTTPException(status_code=404, detail="Validation not found")
    v = _store[vid]
    # build grouped view for Command Center
    groups_view = []
    for g in GROUPS:
        engines = []
        for eid in g["engines"]:
            st = v["engines_state"].get(eid, _engine_state("skipped"))
            engines.append({"id": eid, "label": eid, **st})
        # group status derived
        statuses = [e["status"] for e in engines]
        if all(s in ("completed","skipped") for s in statuses):
            gstatus = "completed"
        elif any(s == "running" for s in statuses):
            gstatus = "running"
        elif any(s == "queued" for s in statuses):
            gstatus = "queued"
        else:
            gstatus = "pending"
        groups_view.append({"id": g["id"], "label": g["label"], "desc": g["desc"], "status": gstatus, "engines": engines})

    # flat engines list with phase
    flat = []
    for eid in ALL_ENGINES:
        st = v["engines_state"].get(eid, _engine_state("skipped"))
        flat.append({"id": eid, "phase": ENGINE_PHASE.get(eid, "analysis"), **st})

    return {
        "id": vid,
        "target_type": v["target_type"],
        "target_value": v["target_value"],
        "scope": v["scope"],
        "status": v["status"],
        "progress": v["progress"],
        "current_phase": v["current_phase"],
        "created_at": v["created_at"],
        "completed_at": v.get("completed_at"),
        "groups": groups_view,
        "engines": flat,
        "phases": PHASES,
        "live_events": list(reversed(v["live_events"][-40:])),  # newest first for UI
        "audit_note": v["audit_note"],
    }

@router.post("/validations/{vid}/cancel")
async def cancel_validation(vid: str):
    if vid not in _store:
        raise HTTPException(status_code=404, detail="Validation not found")
    v = _store[vid]
    if v["status"] in ("completed","failed","cancelled"):
        return {"status": v["status"], "message": "Already finished"}
    v["status"] = "cancelled"
    v["live_events"].append(_make_live_event("validation.failed", "Validation cancelled by user"))
    t = _tasks.get(vid)
    if t and not t.done():
        t.cancel()
    return {"status": "cancelled"}

@router.post("/validations/{vid}/pause")
async def pause_validation(vid: str):
    if vid not in _store:
        raise HTTPException(status_code=404, detail="Validation not found")
    v = _store[vid]
    v["status"] = "paused"
    v["live_events"].append(_make_live_event("validation.paused", "Validation paused"))
    return {"status": "paused"}

@router.post("/validations/{vid}/resume")
async def resume_validation(vid: str):
    if vid not in _store:
        raise HTTPException(status_code=404, detail="Validation not found")
    v = _store[vid]
    if v["status"] != "paused":
        raise HTTPException(status_code=400, detail="Not paused")
    v["status"] = "running"
    v["live_events"].append(_make_live_event("validation.resumed", "Validation resumed"))
    # restart simulator from current point
    if vid not in _tasks or _tasks[vid].done():
        _tasks[vid] = asyncio.create_task(_simulate_validation(vid))
    return {"status": "running"}


# ===================== Stage 7: Results layer (Simulation/Demo) =====================

# Synthetic generator - deterministic per vid, clearly marked as simulation
def _seed_for(vid: str) -> int:
    return sum(ord(c) for c in vid) % 100000

def _generate_results(vid: str):
    v = _store.get(vid)
    if not v or v.get("results"):
        return
    seed = _seed_for(vid)
    rnd = random.Random(seed)
    target = v["target_value"]
    host = target.replace("https://","").replace("http://","").split("/")[0].split(":")[0] or "example.local"

    # Assets & Services
    assets = [
        {"id": f"ast-{vid[:4]}-1", "name": host, "type": "host", "ip": f"192.168.{seed%255}.10", "services": [
            {"port": 443, "service": "https", "state": "open", "evidence_id": f"ev-{vid[:4]}-s1"},
            {"port": 80, "service": "http", "state": "open", "evidence_id": f"ev-{vid[:4]}-s2"},
        ]},
        {"id": f"ast-{vid[:4]}-2", "name": f"api.{host}", "type": "api", "ip": f"192.168.{seed%255}.11", "services": [
            {"port": 443, "service": "https", "state": "open", "evidence_id": f"ev-{vid[:4]}-s3"},
        ]},
    ]

    severities = ["critical","high","high","medium","medium","medium","low","low","informational"]
    categories = ["Injection","TLS","Headers","Auth","Exposure","Config","XSS","SSRF","IDOR"]
    findings = []
    evidences = []
    for i in range(9):
        fid = f"f-{vid[:4]}-{i+1:02d}"
        sev = severities[i % len(severities)]
        conf = rnd.randint(72, 97)
        asset = assets[i % len(assets)]["name"]
        title = rnd.choice(["Missing HSTS Header","TLS 1.0 Enabled","Exposed .env","IDOR on /api/users","Reflected XSS","SSRF via webhook","Weak Password Policy","Open Directory Listing","CORS Misconfig"])
        evid = [
            {"id": f"ev-{vid[:4]}-{fid}-1", "type": "request", "engine": "validation", "finding_id": fid, "data": {"method": "GET", "url": f"https://{host}/", "headers": {"User-Agent": "AegisScan/1.0"}}},
            {"id": f"ev-{vid[:4]}-{fid}-2", "type": "response", "engine": "evidence_collection", "finding_id": fid, "data": {"status": 200, "headers": {"Server": "nginx/1.24", "Strict-Transport-Security": "missing" if "HSTS" in title else "max-age=31536000"}, "body_snippet": "<html>…</html>"}},
            {"id": f"ev-{vid[:4]}-{fid}-3", "type": "raw", "engine": "evidence_graph", "finding_id": fid, "data": {"note": "Engine output correlated", "confidence": conf}},
        ]
        evidences.extend(evid)
        findings.append({
            "id": fid,
            "severity": sev,
            "confidence": conf,
            "status": rnd.choice(["open","open","reviewed"]),
            "category": categories[i % len(categories)],
            "asset": asset,
            "title": title,
            "description": f"Detected {title} on {asset}. Requires validation with evidence.",
            "impact": "Confidentiality / Integrity impact if exploited.",
            "evidence_ids": [e["id"] for e in evid],
            "cwe": f"CWE-{rnd.randint(79, 918)}",
            "cvss": round(rnd.uniform(3.1, 9.8), 1),
        })

    # Add infra evidences
    evidences.extend([
        {"id": f"ev-{vid[:4]}-s1", "type": "ports", "engine": "recon", "finding_id": None, "data": {"host": host, "ports": [80,443]}},
        {"id": f"ev-{vid[:4]}-s2", "type": "headers", "engine": "control_validation", "finding_id": None, "data": {"headers": {"X-Frame-Options": "missing"}}},
        {"id": f"ev-{vid[:4]}-s3", "type": "dns", "engine": "recon", "finding_id": None, "data": {"records": [{"type": "A", "value": assets[0]["ip"]}]}},
    ])

    # Graph: Target -> Assets -> Services -> Findings -> Evidence -> Control
    nodes = [
        {"id": "target", "type": "target", "label": host, "meta": {"target": target}},
    ]
    for a in assets:
        nodes.append({"id": a["id"], "type": "asset", "label": a["name"]})
        for s in a["services"]:
            sid = f"svc-{a['id']}-{s['port']}"
            nodes.append({"id": sid, "type": "service", "label": f"{s['service']}:{s['port']}"})
    for f in findings:
        nodes.append({"id": f["id"], "type": "finding", "label": f["title"][:24], "meta": {"severity": f["severity"]}})
    for e in evidences[:12]:
        nodes.append({"id": e["id"], "type": "evidence", "label": e["type"]})
    # controls as nodes
    nodes.append({"id": "ctrl-1", "type": "control", "label": "Remediation: HSTS + TLS 1.2+"})

    edges = []
    for a in assets:
        edges.append({"from": "target", "to": a["id"], "label": "discovered"})
        for s in a["services"]:
            sid = f"svc-{a['id']}-{s['port']}"
            edges.append({"from": a["id"], "to": sid, "label": "exposes"})
    for f in findings:
        # link finding to first service of first asset
        edges.append({"from": f"svc-{assets[0]['id']}-443", "to": f["id"], "label": "generated"})
        for eid in f["evidence_ids"]:
            edges.append({"from": f["id"], "to": eid, "label": "supported"})
        edges.append({"from": f["id"], "to": "ctrl-1", "label": "mapped to"})

    attack_paths = [
        {"id": "ap-1", "entry": host, "discovery": "Directory /api exposed", "weakness": findings[0]["title"], "impact": "Data exposure / takeover", "chain": ["target", assets[0]["id"], findings[0]["id"], "ctrl-1"], "risk": "high"},
        {"id": "ap-2", "entry": f"api.{host}", "discovery": "IDOR pattern", "weakness": findings[3]["title"], "impact": "Horizontal privilege escalation", "chain": ["target", assets[1]["id"], findings[3]["id"], "ctrl-1"], "risk": "critical"},
    ]

    controls = [
        {"id": "ctrl-1", "title": "Enforce HSTS & Disable TLS 1.0/1.1", "remediation": "Add Strict-Transport-Security, disable TLS1.0/1.1, enable 1.2+", "priority": "P1", "verification": "Re-scan TLS + headers", "finding_ids": [findings[0]["id"], findings[1]["id"]]},
        {"id": "ctrl-2", "title": "Fix IDOR - Object-level authz", "remediation": "Enforce authorization check on /api/users/{id}", "priority": "P1", "verification": "Authenticated tests", "finding_ids": [findings[3]["id"]]},
        {"id": "ctrl-3", "title": "Sanitize input - XSS", "remediation": "Encode output, CSP, input validation", "priority": "P2", "verification": "Payload tests", "finding_ids": [findings[4]["id"]]},
    ]

    compliance = [
        {"framework": "OWASP Top10", "control": "A01 Broken Access Control", "status": "fail", "evidence_ids": [f["evidence_ids"][0] for f in findings[:2]]},
        {"framework": "CIS", "control": "4.1 TLS Configuration", "status": "partial", "evidence_ids": [f"ev-{vid[:4]}-s1"]},
        {"framework": "NIST", "control": "SC-8 Transmission Confidentiality", "status": "fail", "evidence_ids": [f["evidence_ids"][1] for f in findings[:1]]},
    ]

    # Overview metrics
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    risk_score = max(12, 96 - counts["critical"]*18 - counts["high"]*9 - counts["medium"]*4)

    v["results"] = {
        "simulation": True,
        "notice": "Simulation / Demo Data — not real security findings. Will be replaced by ScanOrchestrator + Celery + Engines.",
        "overview": {
            "risk_score": risk_score,
            "findings_count": len(findings),
            "assets_count": len(assets),
            "evidence_count": len(evidences),
            "engines_executed": len(v["engines"]),
            "severity_counts": counts,
            "validation_summary": f"Profile {v['profile']} with {len(v['engines'])} engines on {host}",
        },
        "assets": assets,
        "findings": findings,
        "evidences": evidences,
        "graph": {"nodes": nodes, "edges": edges},
        "attack_paths": attack_paths,
        "controls": controls,
        "compliance": compliance,
    }

def _ensure_results(vid: str):
    v = _store.get(vid)
    if not v:
        raise HTTPException(status_code=404, detail="Validation not found")
    if not v.get("results"):
        # allow viewing even before completed for demo, but mark simulation
        _generate_results(vid)
    return v["results"]

@router.get("/validations/{vid}/results")
async def get_results(vid: str):
    return _ensure_results(vid)

@router.get("/validations/{vid}/findings")
async def get_findings(vid: str, severity: Optional[str] = None, q: Optional[str] = None):
    r = _ensure_results(vid)
    findings = r["findings"]
    if severity:
        findings = [f for f in findings if f["severity"] == severity]
    if q:
        ql = q.lower()
        findings = [f for f in findings if ql in f["title"].lower() or ql in f["asset"].lower() or ql in f["category"].lower()]
    return {"simulation": r["simulation"], "notice": r["notice"], "items": findings, "total": len(findings)}

@router.get("/validations/{vid}/evidence")
async def get_evidence(vid: str, finding_id: Optional[str] = None, type: Optional[str] = None):
    r = _ensure_results(vid)
    ev = r["evidences"]
    if finding_id:
        ev = [e for e in ev if e.get("finding_id") == finding_id]
    if type:
        ev = [e for e in ev if e["type"] == type]
    return {"simulation": r["simulation"], "notice": r["notice"], "items": ev, "total": len(ev)}

@router.get("/validations/{vid}/graph")
async def get_graph(vid: str):
    r = _ensure_results(vid)
    return {"simulation": r["simulation"], "notice": r["notice"], "graph": r["graph"]}

@router.get("/validations/{vid}/attack-paths")
async def get_attack_paths(vid: str):
    r = _ensure_results(vid)
    return {"simulation": r["simulation"], "notice": r["notice"], "items": r["attack_paths"]}

@router.get("/validations/{vid}/controls")
async def get_controls(vid: str):
    r = _ensure_results(vid)
    return {"simulation": r["simulation"], "notice": r["notice"], "items": r["controls"]}

@router.get("/validations/{vid}/compliance")
async def get_compliance(vid: str):
    r = _ensure_results(vid)
    return {"simulation": r["simulation"], "notice": r["notice"], "items": r["compliance"]}

@router.get("/findings/{fid}")
async def get_finding(fid: str):
    for v in _store.values():
        if v.get("results"):
            for f in v["results"]["findings"]:
                if f["id"] == fid:
                    # enrich with evidences
                    ev = [e for e in v["results"]["evidences"] if e.get("finding_id") == fid]
                    return {"finding": f, "evidence": ev, "simulation": True}
    raise HTTPException(status_code=404, detail="Finding not found")

@router.get("/evidence/{eid}")
async def get_evidence_by_id(eid: str):
    for v in _store.values():
        if v.get("results"):
            for e in v["results"]["evidences"]:
                if e["id"] == eid:
                    return {"evidence": e, "simulation": True}
    raise HTTPException(status_code=404, detail="Evidence not found")


@router.get("/findings")
async def list_all_findings(severity: str | None = None, status: str | None = None, q: str | None = None, limit: int = 50):
    all_findings = []
    for v in _store.values():
        if v.get("results"):
            for f in v["results"]["findings"]:
                all_findings.append({**f, "validation_id": v["id"], "validation_target": v["target_value"]})
    if severity:
        all_findings = [f for f in all_findings if f["severity"]==severity]
    if status:
        all_findings = [f for f in all_findings if f["status"]==status]
    if q:
        ql=q.lower()
        all_findings = [f for f in all_findings if ql in f["title"].lower() or ql in f["asset"].lower() or ql in f["category"].lower()]
    return {"items": all_findings[:limit], "total": len(all_findings), "simulation": True}

# ===== Reports + Diff =====

@router.get("/validations/{vid}/reports")
async def get_report(vid: str, type: str = "executive", format: str = "json"):
    r = _ensure_results(vid)
    ov = r["overview"]
    # Executive / Technical / Evidence / Compliance / Risk
    base = {
        "validation_id": vid,
        "type": type,
        "format": format,
        "simulation": r["simulation"],
        "notice": r["notice"],
        "generated_at": _now_iso(),
        "summary": ov,
    }
    if type == "executive":
        base["content"] = {"executive_summary": f"Risk Score {ov['risk_score']}/100 with {ov['findings_count']} findings", "key_risks": [f["title"] for f in r["findings"] if f["severity"] in ("critical","high")][:3]}
    elif type == "technical":
        base["content"] = {"findings": r["findings"], "assets": r["assets"]}
    elif type == "evidence":
        base["content"] = {"evidences": r["evidences"][:20]}
    elif type == "compliance":
        base["content"] = {"compliance": r["compliance"]}
    elif type == "risk":
        base["content"] = {"severity_counts": ov["severity_counts"], "controls": r["controls"]}
    else:
        base["content"] = {"overview": ov}

    if format == "markdown":
        md = f"# {type.title()} Report — {vid}\n\n**Risk Score:** {ov['risk_score']}/100\n\n**Findings:** {ov['findings_count']}\n\n{base['content']}"
        return {"markdown": md, **base}
    if format == "html":
        html = f"<h1>{type.title()} Report {vid}</h1><p>Risk {ov['risk_score']}/100</p><pre>{str(base['content'])[:800]}</pre>"
        return {"html": html, **base}
    if format == "csv":
        csv = "severity,title,asset,confidence\n" + "\n".join([f"{f['severity']},{f['title']},{f['asset']},{f['confidence']}" for f in r["findings"]])
        return {"csv": csv, **base}
    return base

@router.get("/reports/compare")
async def compare_reports(from_id: str, to_id: str):
    r1 = _ensure_results(from_id)
    r2 = _ensure_results(to_id)
    def sev(r): return r["overview"]["severity_counts"]
    s1, s2 = sev(r1), sev(r2)
    diff = {k: s2.get(k,0)-s1.get(k,0) for k in set(list(s1.keys())+list(s2.keys()))}
    return {
        "from": {"id": from_id, "risk_score": r1["overview"]["risk_score"], "severity": s1},
        "to": {"id": to_id, "risk_score": r2["overview"]["risk_score"], "severity": s2},
        "diff": diff,
        "risk_delta": r2["overview"]["risk_score"] - r1["overview"]["risk_score"],
        "remediation_verification": "Remediation Verification — decrease in critical/high indicates progress" if diff.get("critical",0) < 0 else "No improvement",
        "simulation": True,
    }


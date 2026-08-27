from fastapi import APIRouter, Query
from typing import List, Optional
from datetime import datetime, timedelta
import random

router = APIRouter()

ROLES = [
    {"id":"admin","name":"Admin","description":"Full platform access","permissions":["*"]},
    {"id":"manager","name":"Manager","description":"Manage projects, scans, reports","permissions":["projects:*","scans:*","reports:*"]},
    {"id":"analyst","name":"Analyst","description":"Analyze findings & evidence","permissions":["findings:read","evidence:read","graph:read"]},
    {"id":"viewer","name":"Viewer","description":"Read-only dashboard","permissions":["dashboard:read"]},
    {"id":"auditor","name":"Auditor","description":"Audit logs & compliance","permissions":["audit:read","compliance:read"]},
    {"id":"engineer","name":"Engineer","description":"Manage engines & posture","permissions":["engines:*","posture:*","twin:*"]},
    {"id":"guest","name":"Guest","description":"Limited demo access","permissions":["dashboard:read","validations:read"]},
]

USERS_MOCK = [
    {"id":"u-001","email":"admin@aegisscan.local","name":"Admin User","role":"admin","team":"Platform","status":"active","last_login": (datetime.utcnow()-timedelta(hours=1)).isoformat()},
    {"id":"u-002","email":"analyst@aegisscan.local","name":"Sara Analyst","role":"analyst","team":"Security","status":"active","last_login": (datetime.utcnow()-timedelta(days=1)).isoformat()},
    {"id":"u-003","email":"viewer@aegisscan.local","name":"Guest Viewer","role":"viewer","team":"External","status":"active","last_login": (datetime.utcnow()-timedelta(days=3)).isoformat()},
]

# in-memory audit log, seeded
_audit_log: List[dict] = []

def _seed_audit():
    if _audit_log:
        return
    actions = ["validation.create","validation.start","validation.completed","finding.reviewed","evidence.export","login.success","login.failed","report.export"]
    for i in range(24):
        _audit_log.append({
            "id": f"audit-{i+1:04d}",
            "user": random.choice(["admin@aegisscan.local","analyst@aegisscan.local","system"]),
            "action": random.choice(actions),
            "project": random.choice(["—","Website A","API B","Project C"]),
            "target": random.choice(["example.local","api.example.local","192.168.1.10"]),
            "timestamp": (datetime.utcnow()-timedelta(minutes=i*37)).isoformat(),
            "result": random.choice(["success","success","success","failed"]),
            "ip": f"10.0.{random.randint(1,5)}.{random.randint(2,254)}",
            "request_id": f"req-{random.randint(100000,999999)}",
        })

_seed_audit()

def add_audit_entry(user: str, action: str, target: str, project: str = "—", result: str = "success", ip: str = "127.0.0.1"):
    _audit_log.insert(0, {
        "id": f"audit-{len(_audit_log)+1:05d}",
        "user": user,
        "action": action,
        "project": project,
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "result": result,
        "ip": ip,
        "request_id": f"req-{random.randint(100000,999999)}",
    })
    if len(_audit_log) > 200:
        _audit_log.pop()

@router.get("/audit/logs")
async def list_audit_logs(limit: int = Query(20, le=100), action: Optional[str] = None, user: Optional[str] = None):
    items = _audit_log
    if action:
        items = [x for x in items if x["action"]==action]
    if user:
        items = [x for x in items if x["user"]==user]
    return {"items": items[:limit], "total": len(items)}

@router.get("/audit/roles")
async def list_roles():
    return {"items": ROLES, "total": len(ROLES)}

@router.get("/audit/users")
async def list_users():
    return {"items": USERS_MOCK, "total": len(USERS_MOCK)}

@router.get("/audit/teams")
async def list_teams():
    return {"items": [
        {"id":"team-platform","name":"Platform","members":5},
        {"id":"team-security","name":"Security","members":8},
        {"id":"team-external","name":"External","members":3},
    ]}

@router.get("/audit/api-keys")
async def list_api_keys():
    return {"items": [
        {"id":"key-001","name":"CI/CD Runner","prefix":"aegis_live_...4f2a","created_at": (datetime.utcnow()-timedelta(days=12)).isoformat(), "last_used": (datetime.utcnow()-timedelta(hours=2)).isoformat()},
        {"id":"key-002","name":"External Integration","prefix":"aegis_live_...9c11","created_at": (datetime.utcnow()-timedelta(days=30)).isoformat(), "last_used": None},
    ]}

@router.get("/audit/sessions")
async def list_sessions():
    return {"items": [
        {"id":"sess-001","user":"admin@aegisscan.local","ip":"10.0.1.15","user_agent":"Mozilla/5.0","created_at": (datetime.utcnow()-timedelta(hours=1)).isoformat(), "expires_at": (datetime.utcnow()+timedelta(hours=23)).isoformat()},
    ]}

@router.get("/audit/login-attempts")
async def list_login_attempts(limit: int = 20):
    return {"items": [
        {"id": f"attempt-{i}", "user": "analyst@aegisscan.local", "ip": f"10.0.1.{10+i}", "success": i%4!=0, "timestamp": (datetime.utcnow()-timedelta(minutes=i*15)).isoformat()}
        for i in range(limit)
    ]}

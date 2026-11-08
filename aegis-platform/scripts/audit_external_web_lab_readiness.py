#!/usr/bin/env python3
"""Host-only, read-only AegisScan external Web Lab preflight.

Does not authenticate as an app user, record provider approvals, dispatch scans,
send traffic to external targets, or assert that an arbitrary lab is solved.
Only the canonical production Django service is queried for authoritative state.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

CONTRACT = "aegis.external-web-lab-readiness.v1"
HOSTNAME = re.compile(r"^[a-z0-9.-]{1,253}$")
DJANGO_QUERY = r"""
import django
import json
import sys
from urllib.parse import urlsplit
django.setup()
from django_project.projects.models import Project
from django_project.assets.models import Asset
from django_project.system.credential_models import CredentialSecret
from enterprise.models import TenantProject
from fastapi_app.services.authorization_guard import asset_target, current_asset_authorization
from fastapi_app.services.web_labs_preparation import _provider_metadata
pid, desired = sys.argv[1:3]
project = Project.objects.filter(pk=pid).first()
def normalized_url(value):
    try:
        p = urlsplit(value)
        return (p.scheme.lower(), (p.netloc or "").lower(), p.path.rstrip("/") or "/")
    except ValueError:
        return None
assets = []
if project:
    for a in Asset.objects.filter(project_id=pid, is_active=True, type__in=["website", "api_endpoint"]).iterator(chunk_size=100):
        configured = asset_target(a)
        if normalized_url(configured) != normalized_url(desired):
            continue
        grant, reason = current_asset_authorization(a)
        enabled = (a.configuration or {}).get("authorized") is True
        assets.append({
            "asset_id": str(a.pk), "type": a.type,
            "authorized": bool(grant and enabled),
            "authorization_ref": str(grant.pk) if grant and enabled else None,
            "authorization_state": "current" if grant and enabled else "blocked",
        })
tenant_rows = list(TenantProject.objects.filter(
    project_id=pid, organization__is_active=True).values_list("organization_id", flat=True)) if project else []
provider, operations = _provider_metadata(pid) if len(tenant_rows) == 1 else (
    {"state": "tenant_missing_or_ambiguous", "decision_ref": None}, [])
identity_metadata_count = 0
if project:
    for item in CredentialSecret.objects.filter(
        project_id=pid, status=CredentialSecret.Status.ACTIVE
    ).values_list("scope", flat=True):
        if not isinstance(item, dict):
            continue
        if normalized_url(str(item.get("browser_origin", ""))) == normalized_url(desired):
            identity_metadata_count += 1
print(json.dumps({
    "project_active": bool(project and project.status == Project.Status.ACTIVE),
    "tenant_bindings": len(tenant_rows),
    "assets": sorted(assets, key=lambda item: item["asset_id"]),
    "provider": provider,
    "approved_operations": operations,
    "matching_active_credential_metadata": identity_metadata_count,
}, separators=(",", ":")))
"""

MCP_PROBE = r"""
import httpx
import json
endpoint = "/app/media/.burp-mcp-bridge/mcp.sock"
with httpx.Client(transport=httpx.HTTPTransport(uds=endpoint),
                  timeout=httpx.Timeout(5.0, connect=3.0)) as c:
    with c.stream("GET", "http://localhost/",
                  headers={"Accept": "text/event-stream"}) as response:
        print(json.dumps({
            "http_status": response.status_code,
            "content_type": response.headers.get("content-type", ""),
        }))
"""


def normalize_target(raw: str) -> str:
    if len(raw) > 500 or any(c.isspace() or ord(c) < 32 for c in raw):
        raise ValueError("Target URL contains unsupported characters")
    try:
        url = urlsplit(raw)
        host = url.hostname or ""
        port = url.port
    except ValueError as exc:
        raise ValueError("Invalid target URL") from exc
    if (url.scheme != "https" or not HOSTNAME.fullmatch(host) or
            host.startswith(".") or host.endswith(".") or ".." in host or
            url.username or url.password or url.query or url.fragment or
            not raw.startswith("https://")):
        raise ValueError("A credential-free, HTTPS-only external URL is required")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid HTTPS port")
    if url.path not in {"", "/"}:
        raise ValueError("Register the application origin as an exact root-scope asset")
    authority = host.lower() + (f":{port}" if port and port != 443 else "")
    return urlunsplit(("https", authority, "/", "", ""))


def run_json(command: list[str], *, timeout: int) -> dict:
    completed = subprocess.run(
        command, text=True, capture_output=True, check=False, timeout=timeout
    )
    if completed.returncode:
        raise RuntimeError("Authoritative read-only inspection failed")
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("Authoritative inspection returned no structured result")
    result = json.loads(lines[-1])
    if not isinstance(result, dict):
        raise RuntimeError("Authoritative inspection did not return a JSON object")
    return result


def collect(project_id: str, target: str, *, check_mcp: bool, asset_id: str | None = None) -> dict:
    project = str(UUID(project_id))
    normalized = normalize_target(target)
    selected_id = str(UUID(asset_id)) if asset_id else None
    state = run_json(
        ["docker", "exec", "aegis-django", "python", "-c", DJANGO_QUERY, project, normalized],
        timeout=22,
    )
    mcp = {"state": "not_checked"}
    if check_mcp:
        try:
            response = run_json(
                ["docker", "exec", "aegis-fastapi", "python", "-c", MCP_PROBE], timeout=12
            )
            good = (response.get("http_status") == 200 and
                    response.get("content_type", "").startswith("text/event-stream"))
            mcp = {"state": "reachable" if good else "unexpected_response"}
        except (RuntimeError, ValueError, subprocess.TimeoutExpired):
            mcp = {"state": "unavailable"}
    assets = state.get("assets", [])
    selected = [row for row in assets if row.get("asset_id") == selected_id] if selected_id else assets
    blockers: list[str] = []
    if not state.get("project_active"):
        blockers.append("project_not_active_or_missing")
    if state.get("tenant_bindings") != 1:
        blockers.append("enterprise_tenant_not_unique")
    if len(selected) != 1:
        blockers.append("exact_target_asset_missing_or_ambiguous")
    elif not selected[0].get("authorized"):
        blockers.append("latest_asset_authorization_not_valid")
    if state.get("provider", {}).get("state") != "metadata_ready":
        blockers.append("burp_enterprise_provider_not_admissible")
    if "burp.http_request" not in state.get("approved_operations", []):
        blockers.append("burp_http_operation_not_governed")
    if mcp["state"] != "reachable":
        blockers.append("live_burp_mcp_transport_not_verified")
    # Current canonical recipe only supports a sealed local BAC fixture.
    # A generic remote HTTP/OTP workflow must not masquerade as that recipe.
    blockers.append("generic_external_auth_otp_recipe_not_implemented")
    return {
        "contract_version": CONTRACT,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {"project_id": project, "asset_id": selected_id, "target": normalized, "external_probe_sent": False},
        "authoritative_state": state,
        "burp_transport": mcp,
        "existing_recipe": "bac-orders-v1 (local pinned fixture only)",
        "governed_execution_ready": False,
        "blockers": blockers,
        "claim": "PREFLIGHT_ONLY_NOT_A_LAB_ATTEMPT",
    }


def save_new(path: Path, record: dict) -> None:
    """Create once with least privilege; do not replace or follow a symlink."""
    data = (json.dumps(record, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--asset-id", help="Explicitly select one of multiple approved exact-target assets")
    parser.add_argument("--skip-local-mcp-check", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = collect(
            args.project_id, args.target, check_mcp=not args.skip_local_mcp_check,
            asset_id=args.asset_id,
        )
        if args.output:
            save_new(args.output, result)
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2 if result["blockers"] else 0
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"READINESS_CHECK_FAILED: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

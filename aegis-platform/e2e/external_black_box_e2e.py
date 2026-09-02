#!/usr/bin/env python3
"""Real HTTP-only AegisScan E2E harness.

The harness intentionally uses only public HTTP APIs after an optional CI-only
operator account has been provisioned outside the HTTP test boundary. This is
necessary because public registration intentionally creates Viewer users, while
project creation is restricted to users with the ``project.create`` capability.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from typing import Any

import requests


BASE_URL = os.getenv("AEGIS_BASE_URL", "http://localhost")
DJANGO_URL = os.getenv("AEGIS_DJANGO_URL", f"{BASE_URL}/api/v1")
FASTAPI_URL = os.getenv("AEGIS_FASTAPI_URL", f"{BASE_URL}")
TARGET = os.getenv("AEGIS_E2E_TARGET", "aegis-scan-target")
TIMEOUT = int(os.getenv("AEGIS_E2E_TIMEOUT", "180"))
VERIFY_TLS = os.getenv("AEGIS_VERIFY_TLS", "true").lower() not in {"0", "false", "no"}
E2E_EMAIL = os.getenv("AEGIS_E2E_EMAIL")
E2E_PASSWORD = os.getenv("AEGIS_E2E_PASSWORD")


def require(response: requests.Response, expected: set[int], label: str) -> dict[str, Any]:
    if response.status_code not in expected:
        raise RuntimeError(f"{label} failed: HTTP {response.status_code}: {response.text[:1000]}")
    if not response.text:
        return {}
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(f"{label} returned non-JSON response: {response.text[:1000]}") from exc


def csrf(session: requests.Session) -> str:
    response = session.get(f"{DJANGO_URL}/auth/csrf/", timeout=15, verify=VERIFY_TLS)
    data = require(response, {200}, "CSRF bootstrap")
    token = data.get("csrfToken") or session.cookies.get("csrftoken")
    if not token:
        raise RuntimeError("CSRF token was not issued")
    return token


def main() -> int:
    session = requests.Session()
    session.verify = VERIFY_TLS

    ready = session.get(f"{FASTAPI_URL}/ready", timeout=15)
    require(ready, {200}, "FastAPI readiness")
    health = session.get(f"{FASTAPI_URL}/health", timeout=15)
    require(health, {200}, "FastAPI health")

    csrf_token = csrf(session)
    unique = uuid.uuid4().hex[:12]

    # Production registration intentionally creates Viewers. The real
    # authorized workflow therefore logs in with a CI-only pre-provisioned
    # operator when AEGIS_E2E_EMAIL/PASSWORD are supplied. Without those
    # variables, retain the original public-registration coverage for local
    # smoke runs, which should expect project creation to be forbidden.
    email = E2E_EMAIL or f"e2e-{unique}@aegisscan.local"
    password = E2E_PASSWORD or f"Aegis-E2E-{unique}-StrongPass!9"
    headers = {"X-CSRFToken": csrf_token, "Referer": f"{BASE_URL}/"}

    if not (E2E_EMAIL and E2E_PASSWORD):
        registration = session.post(
            f"{DJANGO_URL}/auth/register/",
            json={
                "email": email,
                "first_name": "E2E",
                "last_name": "Harness",
                "password": password,
                "password_confirm": password,
            },
            headers=headers,
            timeout=20,
        )
        require(registration, {201}, "User registration")

    csrf_token = csrf(session)
    headers["X-CSRFToken"] = csrf_token
    login = session.post(
        f"{DJANGO_URL}/auth/login/",
        json={"email": email, "password": password},
        headers=headers,
        timeout=20,
    )
    require(login, {200}, "Login")

    project = session.post(
        f"{DJANGO_URL}/projects/",
        json={
            "name": f"External E2E {unique}",
            "description": "Real HTTP black-box validation project",
            "environment": "development",
        },
        timeout=20,
    )
    project_data = require(project, {201}, "Project creation")
    project_id = project_data.get("id")
    if not project_id:
        keys = sorted(project_data.keys()) if isinstance(project_data, dict) else []
        raise RuntimeError(
            "Project creation response contract invalid: expected top-level 'id' "
            f"(HTTP 201, keys={keys}, body={project_data!r})"
        )

    scan = session.post(
        f"{FASTAPI_URL}/scans/",
        json={
            "project_id": project_id,
            "name": f"External real Nmap {unique}",
            "scan_type": "network",
            "engines": ["nmap"],
            "depth": "quick",
            "config": {"target": TARGET},
            "authorized": True,
        },
        timeout=20,
    )
    scan_data = require(scan, {201}, "Real Nmap scan creation")
    scan_id = scan_data.get("id")
    if not scan_id:
        raise RuntimeError("Scan creation did not return id")

    deadline = time.monotonic() + TIMEOUT
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        status = session.get(f"{FASTAPI_URL}/scans/{scan_id}", timeout=20)
        last = require(status, {200}, "Scan polling")
        if last.get("status") in {"completed", "failed", "cancelled"}:
            break
        time.sleep(2)
    else:
        raise RuntimeError(f"Nmap scan timed out after {TIMEOUT}s; last state={last}")

    if last.get("status") != "completed":
        raise RuntimeError(f"Nmap scan did not complete successfully: {last}")
    if int(last.get("findings_count", 0)) < 1:
        raise RuntimeError(f"Expected at least one real Nmap finding, got {last}")

    findings = session.get(
        f"{FASTAPI_URL}/vulnerabilities/",
        params={"project_id": project_id, "scan_id": scan_id, "limit": 200},
        timeout=20,
    )
    findings_data = require(findings, {200}, "Finding retrieval")
    if not findings_data:
        raise RuntimeError("Scan completed but no finding was returned for the scan")

    finding = findings_data[0]
    finding_id = finding.get("id")
    if finding.get("scan_id") != scan_id:
        raise RuntimeError(f"Finding provenance mismatch: finding.scan_id={finding.get('scan_id')} scan={scan_id}")

    evidence = session.get(f"{FASTAPI_URL}/vulnerabilities/{finding_id}/evidences", timeout=20)
    evidence_data = require(evidence, {200}, "Evidence retrieval")
    if not evidence_data:
        raise RuntimeError("Finding exists but no evidence was returned")

    scanner_evidence = [item for item in evidence_data if item.get("source") == "nmap"]
    if not scanner_evidence:
        raise RuntimeError(f"No Nmap evidence found: {evidence_data}")
    for item in scanner_evidence:
        if item.get("finding_id") != finding_id:
            raise RuntimeError(f"Evidence/finding provenance mismatch: {item}")
        sha = item.get("sha256", "")
        if len(sha) != 64:
            raise RuntimeError(f"Evidence SHA-256 is invalid: {item}")
        if item.get("evidence_type") != "scanner_output":
            raise RuntimeError(f"Unexpected evidence type: {item}")

    print("EXTERNAL_REAL_E2E=PASS")
    print(f"project_id={project_id}")
    print(f"scan_id={scan_id}")
    print(f"finding_id={finding_id}")
    print(f"evidence_count={len(scanner_evidence)}")
    print(f"target={TARGET}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"EXTERNAL_REAL_E2E=FAIL: {exc}", file=sys.stderr)
        raise

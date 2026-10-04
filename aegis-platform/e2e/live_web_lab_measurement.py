"""Isolated Web Labs P6 live measurement harness.

This creates synthetic governance/auth context in the dedicated P6
PostgreSQL/Redis namespace, then deliberately stops. The trusted host lifecycle
authority must provision and inspect the target before scheduling is allowed.
No production database, broker, provider approval, or user principal is used.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4


def p6_environment_allowed(database, broker, env) -> bool:
    return (
        database.hostname == "aegis-burp-p3-postgres"
        and database.path == "/burp_p6"
        and broker.hostname == "aegis-burp-p3-redis"
        and broker.path == "/2"
        and env.get("AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF") == "1"
        and env.get("AEGIS_ISOLATED_BURP_LAB_VERIFICATION_PROOF") != "1"
    )


def _load_state(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise SystemExit("P6 state must be an object.")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["prepare", "schedule", "collect", "collect-disconnect"]
    )
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--inspection", type=Path)
    parser.add_argument("--variant", choices=["vulnerable", "patched"])
    args = parser.parse_args()

    database = urlsplit(os.environ.get("DATABASE_URL", ""))
    broker = urlsplit(os.environ.get("CELERY_BROKER_URL", ""))
    if not p6_environment_allowed(database, broker, os.environ):
        raise SystemExit(
            "This harness requires the dedicated isolated P6 database and broker."
        )

    source_commit = os.environ.get("AEGIS_PROOF_SOURCE_COMMIT", "")
    if len(source_commit) != 40 or any(c not in "0123456789abcdef" for c in source_commit):
        raise SystemExit("AEGIS_PROOF_SOURCE_COMMIT must be an exact lowercase Git SHA.")

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
    import django
    django.setup()

    from django.db import connections
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from django_project.assets.models import Asset, AssetAuthorization
    from django_project.evidence.models import Evidence
    from django_project.projects.models import Project
    from django_project.scans.models import Scan, ScanLog
    from django_project.system.credential_models import CredentialSecret
    from django_project.system.credential_vault import encrypt_secret, credential_fingerprint
    from django_project.users.models import User
    from django_project.vulnerabilities.models import Vulnerability
    from enterprise.burp_mcp_models import BurpMCPInvocation, BurpMCPInvocationClaim, BurpMCPSession
    from enterprise.models import Organization, OrganizationMembership, TenantProject
    from enterprise.provider_approval_models import ProviderApprovalDecision
    from fastapi_app.core.dependencies import get_current_user
    from fastapi_app.routers.capabilities import router
    from fastapi_app.services.burp_lab_requests import VERIFIED_STEPS as STEPS
    from fastapi_app.services.lab_verification import record_runtime_inspection
    from fastapi_app.services.web_security_foundation import persist_provider_approval

    if args.action == "prepare":
        if args.state.exists():
            raise SystemExit("Existing P6 context must be reconciled, not overwritten.")
        if args.variant not in {"vulnerable", "patched"}:
            raise SystemExit("--variant is required for prepare.")

        marker = uuid4().hex[:12]
        user = User.objects.create_user(
            email=f"isolated-p6-{marker}@example.invalid", password=None
        )
        project = Project.objects.create(
            name="Isolated P6 measurement", slug="p6-" + marker, owner=user
        )
        asset = Asset.objects.create(
            project=project,
            name="Pinned BAC fixture",
            slug="fixture-" + marker,
            type=Asset.Type.WEBSITE,
            configuration={"url": "http://127.0.0.1:18081", "authorized": True},
        )
        authorization = AssetAuthorization.objects.create(
            asset=asset,
            actor=user,
            authorized=True,
            target_snapshot="http://127.0.0.1:18081",
        )
        organization = Organization.objects.create(
            name="Isolated P6 tenant", slug="p6-" + marker, owner=user
        )
        OrganizationMembership.objects.create(
            organization=organization,
            user=user,
            is_active=True,
            role=OrganizationMembership.Role.OWNER,
        )
        TenantProject.objects.create(organization=organization, project=project)

        refs = []
        for identity in ("alice", "bob"):
            token = identity + "-token"
            credential = CredentialSecret.objects.create(
                project=project,
                created_by=user,
                name=identity,
                kind=CredentialSecret.Kind.TOKEN,
                encrypted_secret=encrypt_secret(token),
                secret_fingerprint=credential_fingerprint(token),
                scope={
                    "browser_origin": "http://127.0.0.1:18081",
                    "browser_identity_ref": identity,
                },
            )
            refs.append(str(credential.id))

        manifest = {
            "license": "synthetic-acceptance-fixture",
            "maintenance": {"status": "active"},
            "sbom": True,
            "supply_chain_integrity": True,
            "sbom_sha256": "a" * 64,
            "provenance_sha256": "b" * 64,
            "artifact_sha256": "c" * 64,
            "signature_identity": "synthetic-test-fixture:not-vendor-signature",
            "signature_verified": True,
            "known_cves": [],
            "container_privileges": [],
            "network_permissions": ["authorized-target-only"],
            "output_quality": {"schema": "mcp-jsonrpc-2.0", "bounded": True},
            "determinism": True,
            "evidence_quality": True,
            "ci_reproducibility": True,
            "unmitigated_critical_cves": [],
            "approval_metadata_synthetic": True,
            "mcp_endpoint": "http://127.0.0.1:9876/",
            "mcp_transport": "sse",
            "mcp_tools": {"burp.http_request": "send_http1_request"},
            "mcp_tool_schema_sha256": (
                "337bfce281301e755dfd4422c79c32c18e672e5b9c492b7974b47777791434e9"
            ),
        }
        persist_provider_approval(
            project,
            str(user.id),
            {
                "provider_name": "burp-suite-mcp",
                "provider_version": "2026.9",
                "status": "approved",
                "capability": "burp.mcp.gateway",
                "manifest": manifest,
                "rationale": (
                    "Isolated P6 integration fixture; no vendor or production trust claim."
                ),
            },
        )
        decision = ProviderApprovalDecision.objects.filter(project=project).latest(
            "decision_version"
        )
        state = {
            "schema": "aegis.web-lab-p6-context.v1",
            "phase": "prepared",
            "source_commit": source_commit,
            "actor_ref": str(user.id),
            "project_ref": str(project.id),
            "asset_ref": str(asset.id),
            "authorization_ref": str(authorization.id),
            "organization_ref": str(organization.id),
            "credential_refs": refs,
            "provider_decision_ref": str(decision.id),
            "variant": args.variant,
            "marker": marker,
        }
        args.state.write_text(json.dumps(state, indent=2))
        print(json.dumps({
            "status": "prepared",
            "actor_ref": state["actor_ref"],
            "project_ref": state["project_ref"],
            "asset_ref": state["asset_ref"],
            "variant": args.variant,
        }))
        return 0

    state = _load_state(args.state)
    if (
        state.get("schema") != "aegis.web-lab-p6-context.v1"
        or state.get("source_commit") != source_commit
    ):
        raise SystemExit("P6 context schema or exact source SHA does not match.")
    user = User.objects.get(pk=state["actor_ref"])

    if args.action == "schedule":
        if state.get("phase") != "prepared":
            raise SystemExit("Only a prepared P6 context can be scheduled.")
        if not args.inspection:
            raise SystemExit("Trusted P5 lifecycle inspection is required.")
        inspected = json.loads(args.inspection.read_text())
        if inspected.get("variant") != state["variant"]:
            raise SystemExit("Runtime inspection variant differs from prepared context.")

        asset = Asset.objects.get(pk=state["asset_ref"], project_id=state["project_ref"])
        runtime_evidence = record_runtime_inspection(
            asset=asset, actor_id=str(user.id), inspection=inspected
        )
        body = {
            "project_id": state["project_ref"],
            "asset_id": state["asset_ref"],
            "credential_refs": state["credential_refs"],
            "options": {
                "provider_decision_ref": state["provider_decision_ref"],
                "mode": "verified_lab_sequence",
                "runtime_evidence_ref": str(runtime_evidence.id),
            },
            "idempotency_key": "live-p6-" + state["marker"],
            "correlation_id": "live-p6-" + state["marker"],
        }

        app = FastAPI()
        app.include_router(router, prefix="/api/v1/capabilities")
        app.dependency_overrides[get_current_user] = lambda: {"user_id": str(user.id)}
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/v1/capabilities/burp.mcp.gateway/execute", json=body
                )
                if response.status_code != 202:
                    raise RuntimeError(
                        "Canonical P6 scheduling rejected: HTTP "
                        + str(response.status_code)
                    )
                result = response.json()
                scan = Scan.objects.get(pk=result["scan"]["id"])
        finally:
            app.dependency_overrides.pop(get_current_user, None)

        state.update(
            phase="scheduled",
            body=body,
            scan_ref=str(scan.id),
            instance_ref=inspected["instance_ref"],
            process_ref=inspected["process_ref"],
            fixture_revision=inspected["fixture_revision"],
        )
        args.state.write_text(json.dumps(state, indent=2))
        print(json.dumps({
            "status": "scheduled",
            "scan_ref": str(scan.id),
            "queue": "scanners",
            "lifecycle_provisioned_before_schedule": True,
        }))
        return 0

    if state.get("phase") != "scheduled" or not state.get("scan_ref"):
        raise SystemExit("P6 collection requires a scheduled context.")
    scan = Scan.objects.get(pk=state["scan_ref"])

    if args.action == "collect-disconnect":
        if state["variant"] != "vulnerable":
            raise SystemExit("The sealed disconnect case uses the vulnerable twin.")
        if scan.status != Scan.Status.FAILED:
            raise SystemExit("Disconnect acceptance requires a failed scan.")
        sessions = list(BurpMCPSession.objects.filter(scan=scan))
        if len(sessions) != 1:
            raise SystemExit("Disconnect case must have exactly one Burp MCP session.")
        session = sessions[0]
        claims = list(
            BurpMCPInvocationClaim.objects.filter(session=session).order_by(
                "invocation_sequence"
            )
        )
        if (
            len(claims) != 1
            or claims[0].state != "indeterminate"
            or claims[0].invocation_id is not None
        ):
            raise SystemExit(
                "Disconnect did not leave exactly one unresolved indeterminate claim."
            )
        if BurpMCPInvocation.objects.filter(session=session).exists():
            raise SystemExit("Disconnect case must not commit provider evidence.")
        if Evidence.objects.filter(scan=scan, source="lab_verification").exists():
            raise SystemExit("Disconnect case must not commit a lab verdict.")
        if Vulnerability.objects.filter(scan=scan).exists():
            raise SystemExit("Disconnect case must not create a finding.")

        engine = (scan.engine_results or {}).get("burp-mcp", {})
        if engine.get("lab_solved") is True:
            raise SystemExit("Disconnect case cannot claim lab_solved.")

        runtime = session.contract_snapshot.get("lab", {}).get("runtime_binding", {})
        if (
            runtime.get("instance_ref") != state["instance_ref"]
            or runtime.get("process_ref") != state["process_ref"]
            or runtime.get("fixture_revision") != state["fixture_revision"]
            or runtime.get("variant") != "vulnerable"
        ):
            raise SystemExit("Disconnect runtime binding changed before failure.")

        proof = {
            "schema": "aegis.web-lab-disconnect-proof.v1",
            "status": "pass",
            "source_commit": source_commit,
            "scan_ref": str(scan.id),
            "session_ref": str(session.id),
            "claim_ref": str(claims[0].id),
            "claim_state": claims[0].state,
            "failure_code": claims[0].failure_code,
            "definition_id": "bac-orders-v1",
            "fixture_revision": state["fixture_revision"],
            "variant": "vulnerable",
            "instance_ref": state["instance_ref"],
            "process_ref": state["process_ref"],
            "verdict": "indeterminate",
            "finding_present": False,
            "lab_solved": False,
            "invocation_claim_count": 1,
            "evidence_refs": [
                "scan:" + str(scan.id),
                "session:" + str(session.id),
                "claim:" + str(claims[0].id),
            ],
        }
        args.state.with_name("disconnect-proof.json").write_text(
            json.dumps(proof, indent=2)
        )
        print(json.dumps(proof))
        return 0

    if scan.status != Scan.Status.COMPLETED:
        print(json.dumps({
            "status": scan.status,
            "error_type": (scan.engine_results or {}).get("burp-mcp", {}).get("error_type"),
        }))
        return 2

    invocations = list(
        BurpMCPInvocation.objects.filter(session__scan=scan).order_by(
            "invocation_sequence"
        )
    )
    claims = list(BurpMCPInvocationClaim.objects.filter(session__scan=scan))
    observations = scan.engine_results["burp-mcp"]["observations"]
    if not (
        len(invocations) == len(claims) == len(observations) == len(STEPS) == 8
    ):
        raise SystemExit("Nominal P6 case has incomplete governed observations.")
    if not all(c.state == "committed" for c in claims):
        raise SystemExit("Nominal P6 case contains an unresolved invocation claim.")
    if not all(i.qualification.qualified for i in invocations):
        raise SystemExit("Nominal P6 case contains unqualified provider evidence.")
    if [o["step_ref"] for o in observations] != list(STEPS):
        raise SystemExit("Nominal P6 recipe order changed.")

    persisted = json.dumps(scan.engine_results)
    persisted += "".join(
        Evidence.objects.filter(scan=scan).values_list("raw_output", flat=True)
    )
    persisted += json.dumps(
        list(ScanLog.objects.filter(scan=scan).values_list("context", flat=True))
    )
    if any(
        secret in persisted
        for secret in ("alice-token", "bob-token", "Authorization:", "Set-Cookie")
    ):
        raise SystemExit("Credential material leaked into persisted P6 evidence.")

    verdict = scan.engine_results["burp-mcp"]["lab_verification"]
    expected = "vulnerable" if state["variant"] == "vulnerable" else "not_vulnerable"
    if (
        verdict["live_fixture_revision_verified"] is not True
        or verdict["instance_ref"] != state["instance_ref"]
        or verdict["process_ref"] != state["process_ref"]
        or verdict["verdict"] != expected
        or verdict["lab_solved"] is (state["variant"] != "vulnerable")
    ):
        raise SystemExit("Nominal P6 verdict differs from the sealed twin expectation.")

    if state["variant"] == "vulnerable":
        finding = Vulnerability.objects.get(pk=verdict["finding_id"])
        if finding.status != "open":
            raise SystemExit("Vulnerable P6 finding is not OPEN for independent review.")
    elif Vulnerability.objects.filter(scan=scan).exists():
        raise SystemExit("Patched P6 twin created a finding.")

    proof = {
        "schema": "aegis.burp-live-lab-verification-proof.v1",
        "status": "pass",
        "scan_ref": str(scan.id),
        "source_commit": source_commit,
        "canonical_route_and_real_broker": True,
        "worker_queue": "scanners",
        "lifecycle_provisioned_before_schedule": True,
        "approval_metadata_synthetic": True,
        "authenticated_principal_synthetic": True,
        "provider_production_admissibility_verified": False,
        "observations": observations,
        "evidence_refs": [str(i.evidence_id) for i in invocations],
        "qualified_evidence_count": len(invocations),
        "raw_request_response_persisted": False,
        "lab_solved": verdict["lab_solved"],
        "live_fixture_revision_verified": True,
        "variant": state["variant"],
        "verdict": verdict,
        "confirmation_ref": None,
    }
    args.state.with_name("live-verification-proof.json").write_text(
        json.dumps(proof, indent=2)
    )
    connections.close_all()
    print(json.dumps(proof))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

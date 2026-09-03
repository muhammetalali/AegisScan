from __future__ import annotations

import hashlib

import pytest

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngineExecution
from django_project.users.models import User
from fastapi_app.tasks.security_scan import run_nmap_scan

pytestmark = pytest.mark.django_db(transaction=True)


def _build_authorized_scan(user, project, asset, authorization):
    return Scan.objects.create(
        project=project,
        name="Real loopback Nmap",
        scan_type=Scan.Type.NETWORK,
        asset=asset,
        authorization_decision=authorization,
        engines=["nmap"],
        depth=Scan.Depth.QUICK,
        config={"target": "127.0.0.1"},
        initiated_by=user,
    )


def test_real_nmap_execution_persists_evidence_end_to_end(monkeypatch):
    monkeypatch.setenv("AUTHORIZED_SCAN_TARGETS", "127.0.0.1")

    user = User.objects.create_user(
        email="real-nmap-e2e@example.invalid",
        password="Strong-Test-Password-123!",
        first_name="Real",
        last_name="Nmap",
    )
    project = Project.objects.create(
        name="Real Nmap E2E",
        slug="real-nmap-e2e",
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        name="loopback-target",
        slug="loopback-target",
        type=Asset.Type.IP_ADDRESS,
        configuration={"host": "127.0.0.1", "authorized": True},
        owner=user,
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot="127.0.0.1",
        reason="controlled CI loopback target",
    )
    scan = _build_authorized_scan(user, project, asset, authorization)

    result = run_nmap_scan.run(str(scan.id))

    scan.refresh_from_db()
    execution = ScanEngineExecution.objects.get(scan=scan)
    evidence = Evidence.objects.get(scan=scan)

    assert result["scan_id"] == str(scan.id)
    assert result["tool"] == "nmap"
    assert result["target"] == "127.0.0.1"
    assert result["parsed"]["host_count"] >= 1
    assert result["authorization_decision_id"] == str(authorization.id)
    assert scan.authorization_decision_id == authorization.id
    assert scan.status == Scan.Status.COMPLETED
    assert scan.progress == 100
    assert execution.status == ScanEngineExecution.ExecutionStatus.COMPLETED
    assert execution.evidences_collected == 1
    assert execution.result_data["evidence_id"] == str(evidence.id)
    assert execution.result_data["authorization_decision_id"] == str(authorization.id)
    assert evidence.asset_id == asset.id
    assert evidence.raw_output.strip()
    assert evidence.sha256 == hashlib.sha256(evidence.raw_output.encode("utf-8", errors="replace")).hexdigest()
    assert authorization.target_snapshot == evidence.metadata["target"]
    assert evidence.metadata["authorization_decision_id"] == str(authorization.id)
    assert evidence.metadata["parsed"]["host_count"] >= 1


def test_nmap_worker_rejects_queued_scan_after_authorization_revocation(monkeypatch):
    monkeypatch.setenv("AUTHORIZED_SCAN_TARGETS", "127.0.0.1")

    user = User.objects.create_user(
        email="nmap-revocation-e2e@example.invalid",
        password="Strong-Test-Password-123!",
    )
    project = Project.objects.create(
        name="Nmap Revocation E2E",
        slug="nmap-revocation-e2e",
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        name="loopback-revocation-target",
        slug="loopback-revocation-target",
        type=Asset.Type.IP_ADDRESS,
        configuration={"host": "127.0.0.1", "authorized": True},
        owner=user,
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot="127.0.0.1",
        reason="controlled CI queued-scan authorization",
    )
    scan = _build_authorized_scan(user, project, asset, authorization)
    revocation = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=False,
        target_snapshot="127.0.0.1",
        reason="authorization revoked before worker execution",
        supersedes=authorization,
    )

    result = run_nmap_scan.run(str(scan.id))

    scan.refresh_from_db()
    assert result == {"status": "blocked", "scan_id": str(scan.id)}
    assert scan.status == Scan.Status.FAILED
    assert "no longer the latest" in scan.error_message
    assert scan.authorization_decision_id == authorization.id
    assert revocation.id != authorization.id
    assert not Evidence.objects.filter(scan=scan).exists()
    assert not ScanEngineExecution.objects.filter(scan=scan).exists()

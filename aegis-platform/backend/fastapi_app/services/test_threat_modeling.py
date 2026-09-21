from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetRelationship
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from enterprise.models import AttackPath, BlastRadiusSnapshot, EvidenceGraphEdge, EvidenceGraphNode
from enterprise.services import ensure_project_tenant
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.main import app
from fastapi_app.services.threat_modeling import build_threat_model, validate_attack_chain

pytestmark = pytest.mark.django_db(transaction=True)


def _user_project(prefix: str = "threat-model"):
    suffix = uuid.uuid4().hex[:10]
    user = User.objects.create_user(
        email=f"{prefix}-{suffix}@example.invalid",
        password="Threat-Model-Test-Only-Password!42",
        first_name="Threat",
        last_name="Model",
    )
    project = Project.objects.create(
        name=f"{prefix}-{suffix}",
        slug=f"{prefix}-{suffix}",
        owner=user,
        environment=Project.Environment.PRODUCTION,
    )
    return user, project


def _scan(project: Project, user: User, suffix: str) -> Scan:
    return Scan.objects.create(
        project=project,
        name=f"Threat Model Scan {suffix}",
        scan_type=Scan.Type.FULL_VALIDATION,
        initiated_by=user,
        engines=["nmap"],
    )


def _finding(
    *,
    project: Project,
    user: User,
    asset: Asset,
    suffix: str,
    title: str,
    category: str,
    cwe_id: str,
    tags: list[str],
    risk_score: float,
    with_evidence: bool = True,
) -> Vulnerability:
    row = Vulnerability.objects.create(
        project=project,
        scan=_scan(project, user, suffix),
        asset=asset,
        title=title,
        description=f"Controlled evidence-backed finding {suffix}",
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.CONFIRMED,
        confidence=Vulnerability.Confidence.CONFIRMED,
        category=category,
        cwe_id=cwe_id,
        tags=tags,
        risk_score=risk_score,
        source_engine="nmap",
    )
    if with_evidence:
        Evidence.objects.create(
            scan=row.scan,
            asset=asset,
            finding=row,
            source="nmap",
            evidence_type="scanner_output",
            raw_output=f"validated evidence for {suffix}",
            collected_by=user,
        )
    return row


def test_threat_model_build_is_evidence_backed_and_does_not_invent_capec():
    user, project = _user_project("frameworks")
    api = Asset.objects.create(
        project=project,
        name="Public API",
        slug="public-api",
        type=Asset.Type.API_ENDPOINT,
        environment=Asset.Environment.PRODUCTION,
        criticality=Asset.Criticality.HIGH,
        configuration={"internet_exposed": True},
    )
    _finding(
        project=project,
        user=user,
        asset=api,
        suffix="authorization",
        title="Broken authorization exposes sensitive personal data",
        category="authorization",
        cwe_id="CWE-284",
        tags=["CAPEC-122", "privacy:data-disclosure"],
        risk_score=8.5,
    )
    _finding(
        project=project,
        user=user,
        asset=api,
        suffix="dos",
        title="Resource exhaustion denial of service",
        category="availability",
        cwe_id="CWE-400",
        tags=[],
        risk_score=6.0,
    )

    result = build_threat_model(project=project, actor_id=str(user.id))

    stride = {
        item["category"]
        for item in result["frameworks"]["STRIDE"]["observations"]
    }
    linddun = {
        item["category"]
        for item in result["frameworks"]["LINDDUN"]["observations"]
    }
    capec = {
        item["category"]
        for item in result["frameworks"]["CAPEC"]["observations"]
    }
    assert "elevation_of_privilege" in stride
    assert "information_disclosure" in stride
    assert "denial_of_service" in stride
    assert "data_disclosure" in linddun
    assert capec == {"CAPEC-122"}
    assert result["frameworks"]["CAPEC"]["claim"].startswith("CAPEC identifiers are preserved only")
    assert result["evidence_graph"]["nodes"] > 0
    assert result["evidence_graph"]["edges"] > 0
    assert len(result["model_sha256"]) == 64

    threat_nodes = EvidenceGraphNode.objects.filter(project=project, kind=EvidenceGraphNode.Kind.THREAT)
    assert threat_nodes.exists()
    assert EvidenceGraphEdge.objects.filter(project=project, edge_type="derived_from").exists()
    assert EvidenceGraphEdge.objects.filter(project=project, edge_type="supports").exists()


def test_attack_chain_validation_requires_confirmed_evidence_on_every_hop_and_persists_blast_radius():
    user, project = _user_project("validated-chain")
    source = Asset.objects.create(
        project=project,
        name="Internet Gateway",
        slug="gateway",
        type=Asset.Type.WEBSITE,
        criticality=Asset.Criticality.MEDIUM,
        configuration={"internet_exposed": True},
    )
    middle = Asset.objects.create(
        project=project,
        name="Application API",
        slug="application-api",
        type=Asset.Type.API_ENDPOINT,
        criticality=Asset.Criticality.HIGH,
    )
    target = Asset.objects.create(
        project=project,
        name="Crown Jewel Data",
        slug="crown-jewel-data",
        type=Asset.Type.CLOUD_RESOURCE,
        criticality=Asset.Criticality.CRITICAL,
        configuration={"crown_jewel": True},
    )
    AssetRelationship.objects.create(
        project=project,
        source=source,
        target=middle,
        relationship_type=AssetRelationship.RelationshipType.CONNECTS_TO,
    )
    AssetRelationship.objects.create(
        project=project,
        source=middle,
        target=target,
        relationship_type=AssetRelationship.RelationshipType.DEPENDS_ON,
    )
    middle_finding = _finding(
        project=project,
        user=user,
        asset=middle,
        suffix="middle",
        title="Authorization bypass enables privilege escalation",
        category="authorization",
        cwe_id="CWE-284",
        tags=["CAPEC-122"],
        risk_score=8.0,
    )
    target_finding = _finding(
        project=project,
        user=user,
        asset=target,
        suffix="target",
        title="Sensitive information disclosure",
        category="data exposure",
        cwe_id="CWE-200",
        tags=["privacy:data-disclosure"],
        risk_score=9.0,
    )
    organization = ensure_project_tenant(project, str(user.id))
    attack_path = AttackPath.objects.create(
        organization=organization,
        project=project,
        source_node={"asset_id": str(source.id), "name": source.name},
        target_node={"asset_id": str(target.id), "name": target.name},
        steps=[str(source.id), str(middle.id), str(target.id)],
        risk_score=90.0,
        evidence={"source": "controlled-test"},
        status=AttackPath.Status.DISCOVERED,
    )

    result = validate_attack_chain(
        project=project,
        actor_id=str(user.id),
        attack_path_id=str(attack_path.id),
    )

    attack_path.refresh_from_db()
    assert attack_path.status == AttackPath.Status.VALIDATED
    assert result["status"] == "validated"
    assert result["hop_count"] == 2
    assert len(result["validation_sha256"]) == 64
    assert {middle_finding.id, target_finding.id} == {
        uuid.UUID(finding_id)
        for hop in result["hops"]
        for finding_id in hop["finding_ids"]
    }
    assert all(hop["evidence_refs"] for hop in result["hops"])

    snapshot = BlastRadiusSnapshot.objects.get(pk=result["blast_radius"]["snapshot_id"])
    assert snapshot.attack_path_id == attack_path.id
    assert str(target.id) in snapshot.crown_jewel_refs
    assert snapshot.score > 0
    assert snapshot.evidence_refs
    assert any(node["id"] == str(target.id) for node in snapshot.impacted_nodes)


def test_attack_chain_validation_fails_closed_when_a_hop_lacks_confirmed_evidence():
    user, project = _user_project("blocked-chain")
    source = Asset.objects.create(project=project, name="Source", slug="source", type=Asset.Type.WEBSITE)
    target = Asset.objects.create(project=project, name="Target", slug="target", type=Asset.Type.API_ENDPOINT)
    AssetRelationship.objects.create(
        project=project,
        source=source,
        target=target,
        relationship_type=AssetRelationship.RelationshipType.CONNECTS_TO,
    )
    _finding(
        project=project,
        user=user,
        asset=target,
        suffix="missing-evidence",
        title="Authorization bypass",
        category="authorization",
        cwe_id="CWE-284",
        tags=[],
        risk_score=8.0,
        with_evidence=False,
    )
    organization = ensure_project_tenant(project, str(user.id))
    attack_path = AttackPath.objects.create(
        organization=organization,
        project=project,
        source_node={"asset_id": str(source.id)},
        target_node={"asset_id": str(target.id)},
        steps=[str(source.id), str(target.id)],
        risk_score=70.0,
        evidence={},
    )

    with pytest.raises(ValueError, match="lacks confirmed finding evidence"):
        validate_attack_chain(
            project=project,
            actor_id=str(user.id),
            attack_path_id=str(attack_path.id),
        )

    attack_path.refresh_from_db()
    assert attack_path.status == AttackPath.Status.DISCOVERED
    assert not BlastRadiusSnapshot.objects.filter(attack_path=attack_path).exists()


def test_threat_model_api_registration_and_tenant_isolation():
    user, project = _user_project("api")
    other, other_project = _user_project("api-other")
    Asset.objects.create(
        project=project,
        name="API",
        slug="api",
        type=Asset.Type.API_ENDPOINT,
    )
    app.dependency_overrides[get_current_user] = lambda: {"user_id": str(user.id)}
    try:
        client = TestClient(app)
        response = client.post(f"/api/v1/threat-model/projects/{project.id}/build")
        assert response.status_code == 200, response.text
        assert response.json()["schema"] == "aegis.threat-model.v1"

        snapshot = client.get(f"/api/v1/threat-model/projects/{project.id}")
        assert snapshot.status_code == 200, snapshot.text
        assert snapshot.json()["schema"] == "aegis.threat-model-snapshot.v1"

        denied = client.get(f"/api/v1/threat-model/projects/{other_project.id}")
        assert denied.status_code == 404
    finally:
        app.dependency_overrides.clear()

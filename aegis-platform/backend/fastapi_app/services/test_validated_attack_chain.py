from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization, AssetRelationship
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from django_project.evidence.models import Evidence
from enterprise.models import AttackPath, AttackPathValidation, BlastRadiusSnapshot, OrganizationMembership
from enterprise.services import ensure_project_tenant
from enterprise.web_security_models import SecurityGraphEdge, SecurityGraphNode
from fastapi_app.services.authorization_guard import asset_target
from fastapi_app.services.threat_modeling import create_threat_model_snapshot
from fastapi_app.services.enterprise_gap_closure import persist_blast_radius
from fastapi_app.services.validated_attack_chain import (
    AttackPathValidationError,
    validate_attack_path,
    verify_attack_path_validation,
)


def _project(prefix: str):
    suffix = uuid.uuid4().hex[:10]
    user = User.objects.create_user(
        email=f"{prefix}-{suffix}@example.invalid",
        password="Validated-Attack-Chain-Test!42",
        first_name="Attack",
        last_name="Chain",
    )
    project = Project.objects.create(
        name=f"{prefix}-{suffix}",
        slug=f"{prefix}-{suffix}",
        owner=user,
        environment=Project.Environment.STAGING,
    )
    organization = ensure_project_tenant(project, str(user.id))
    return user, project, organization


def _asset(project, slug: str, *, criticality=Asset.Criticality.MEDIUM):
    return Asset.objects.create(
        project=project,
        name=slug.replace("-", " ").title(),
        slug=f"{slug}-{uuid.uuid4().hex[:6]}",
        type=Asset.Type.CLOUD_RESOURCE,
        criticality=criticality,
        configuration={"host": f"{slug}.example.invalid"},
    )


def _authorize(asset: Asset, user: User, *, authorized=True, expires_at=None):
    return AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=authorized,
        target_snapshot=asset_target(asset),
        reason="validated attack chain test",
        expires_at=expires_at,
    )


def _confirmed_evidence(*, project: Project, user: User, asset: Asset, suffix: str, risk_score: float):
    scan = Scan.objects.create(
        project=project,
        name=f"Validated attack-chain {suffix}",
        scan_type=Scan.Type.FULL_VALIDATION,
        initiated_by=user,
        engines=["validated-attack-chain-test"],
    )
    finding = Vulnerability.objects.create(
        project=project,
        scan=scan,
        asset=asset,
        title=f"Confirmed path finding {suffix}",
        description="Evidence-backed attack-chain validation fixture.",
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.CONFIRMED,
        confidence=Vulnerability.Confidence.CONFIRMED,
        risk_score=risk_score,
        source_engine="validated-attack-chain-test",
    )
    evidence = Evidence.objects.create(
        scan=scan,
        asset=asset,
        finding=finding,
        source="validated-attack-chain-test",
        evidence_type="validation_output",
        raw_output=f"confirmed path evidence {suffix}",
        metadata={"finding_present": True},
        collected_by=user,
    )
    return finding, evidence


def _fixture(prefix: str = "validated-chain"):
    user, project, organization = _project(prefix)
    source = _asset(project, "internet-edge", criticality=Asset.Criticality.HIGH)
    middle = _asset(project, "application", criticality=Asset.Criticality.HIGH)
    target = _asset(project, "customer-db", criticality=Asset.Criticality.CRITICAL)
    crown = _asset(project, "vault", criticality=Asset.Criticality.CRITICAL)
    rel1 = AssetRelationship.objects.create(
        project=project,
        source=source,
        target=middle,
        relationship_type=AssetRelationship.RelationshipType.CONNECTS_TO,
    )
    rel2 = AssetRelationship.objects.create(
        project=project,
        source=middle,
        target=target,
        relationship_type=AssetRelationship.RelationshipType.CONNECTS_TO,
    )
    AssetRelationship.objects.create(
        project=project,
        source=target,
        target=crown,
        relationship_type=AssetRelationship.RelationshipType.DEPENDS_ON,
    )
    authorizations = [_authorize(asset, user) for asset in (source, middle, target)]

    graph_source = SecurityGraphNode.objects.create(
        project=project,
        plane=SecurityGraphNode.Plane.ATTACK_SURFACE,
        kind=SecurityGraphNode.Kind.ASSET,
        external_ref=f"asset:{source.id}",
        label=source.name,
    )
    graph_target = SecurityGraphNode.objects.create(
        project=project,
        plane=SecurityGraphNode.Plane.APPLICATION,
        kind=SecurityGraphNode.Kind.ASSET,
        external_ref=f"asset:{target.id}",
        label=target.name,
    )
    SecurityGraphEdge.objects.create(
        project=project,
        source=graph_source,
        target=graph_target,
        relation="candidate_attack_path",
    )
    threat_model, _ = create_threat_model_snapshot(
        organization=organization,
        project=project,
        actor_id=str(user.id),
        title="Validated chain threat model",
        methodologies=["STRIDE", "CAPEC", "PASTA"],
        pasta_stage=4,
        scope={"objective": "protect customer database"},
        scenarios=[{
            "ref": "CHAIN-001",
            "title": "External path reaches customer database",
            "description": "Grounded attack-chain scenario.",
            "source_ref": f"asset:{source.id}",
            "target_ref": f"asset:{target.id}",
            "severity": "critical",
            "pasta_stage": 4,
            "stride": ["spoofing", "elevation-of-privilege"],
            "linddun": [],
            "capec_ids": ["CAPEC-115"],
            "assumptions": [],
            "preconditions": [],
            "impacts": ["database compromise"],
            "control_refs": ["control:segmentation"],
            "evidence_refs": [],
        }],
    )
    path = AttackPath.objects.create(
        organization=organization,
        project=project,
        source_node={"asset_id": str(source.id), "name": source.name},
        target_node={"asset_id": str(target.id), "name": target.name},
        steps=[str(source.id), str(middle.id), str(target.id)],
        risk_score=92.0,
        evidence={"source": "attack-path-test"},
    )
    middle_finding, middle_evidence = _confirmed_evidence(
        project=project,
        user=user,
        asset=middle,
        suffix="middle",
        risk_score=8.0,
    )
    target_finding, evidence = _confirmed_evidence(
        project=project,
        user=user,
        asset=target,
        suffix="target",
        risk_score=9.0,
    )
    return {
        "user": user,
        "project": project,
        "organization": organization,
        "source": source,
        "middle": middle,
        "target": target,
        "crown": crown,
        "relationships": [rel1, rel2],
        "authorizations": authorizations,
        "threat_model": threat_model,
        "path": path,
        "middle_finding": middle_finding,
        "target_finding": target_finding,
        "middle_evidence": middle_evidence,
        "evidence": evidence,
        "evidence_ids": [str(middle_evidence.id), str(evidence.id)],
    }


@pytest.mark.django_db(transaction=True)
def test_validated_attack_chain_is_evidence_bound_and_derives_blast_radius():
    data = _fixture()
    row, created = validate_attack_path(
        organization=data["organization"],
        project=data["project"],
        attack_path_id=str(data["path"].id),
        threat_model_snapshot_id=str(data["threat_model"].id),
        scenario_refs=["CHAIN-001"],
        evidence_ids=data["evidence_ids"],
        crown_jewel_asset_ids=[str(data["crown"].id)],
        max_depth=3,
        actor_id=str(data["user"].id),
    )
    assert created is True
    assert len(row.validation_sha256) == 64
    assert row.scenario_refs == ["CHAIN-001"]
    assert set(row.evidence_refs) == set(data["evidence_ids"])
    assert len(row.authorization_refs) == 3
    assert len(row.relationship_refs) == 2
    assert row.proof_material["contract_version"] == "aegis.validated-attack-chain.v1"
    assert row.proof_material["attack_path_id"] == str(data["path"].id)
    assert len(row.proof_material["evidence"]) == 2
    integrity = verify_attack_path_validation(row)
    assert integrity["valid"] is True
    assert integrity["expected_sha256"] == row.validation_sha256

    data["path"].refresh_from_db()
    assert data["path"].status == AttackPath.Status.VALIDATED
    blast = BlastRadiusSnapshot.objects.get(pk=row.blast_radius_snapshot_id)
    assert blast.attack_path_id == data["path"].id
    assert blast.root_ref == str(data["target"].id)
    assert str(data["crown"].id) in blast.crown_jewel_refs
    impacted = {item["id"]: item for item in blast.impacted_nodes}
    assert str(data["target"].id) in impacted
    assert impacted[str(data["target"].id)]["distance"] == 0
    assert str(data["crown"].id) in impacted
    assert blast.score > 0

    repeated, repeated_created = validate_attack_path(
        organization=data["organization"],
        project=data["project"],
        attack_path_id=str(data["path"].id),
        threat_model_snapshot_id=str(data["threat_model"].id),
        scenario_refs=["CHAIN-001"],
        evidence_ids=data["evidence_ids"],
        crown_jewel_asset_ids=[str(data["crown"].id)],
        max_depth=3,
        actor_id=str(data["user"].id),
    )
    assert repeated_created is False
    assert repeated.id == row.id
    assert AttackPathValidation.objects.filter(attack_path=data["path"]).count() == 1
    assert BlastRadiusSnapshot.objects.filter(attack_path=data["path"]).count() == 1

    row.scenario_refs = ["mutated"]
    with pytest.raises(RuntimeError, match="immutable"):
        row.save()
    with pytest.raises(RuntimeError, match="append-only"):
        AttackPathValidation.objects.filter(pk=row.pk).update(scenario_refs=[])

    stored_material = row.proof_material
    row.proof_material = {"tampered": True}
    with pytest.raises(RuntimeError, match="immutable"):
        row.save()
    row.proof_material = stored_material

    blast.score = 0
    with pytest.raises(RuntimeError, match="immutable"):
        blast.save()
    with pytest.raises(RuntimeError, match="append-only"):
        BlastRadiusSnapshot.objects.filter(pk=blast.pk).update(score=0)


@pytest.mark.django_db(transaction=True)
def test_validation_rejects_read_only_tenant_roles():
    data = _fixture("viewer-chain")
    membership = OrganizationMembership.objects.get(
        organization=data["organization"],
        user=data["user"],
    )
    membership.role = OrganizationMembership.Role.VIEWER
    membership.save(update_fields=["role", "updated_at"])

    with pytest.raises(AttackPathValidationError, match="tenant role"):
        validate_attack_path(
            organization=data["organization"],
            project=data["project"],
            attack_path_id=str(data["path"].id),
            threat_model_snapshot_id=str(data["threat_model"].id),
            scenario_refs=["CHAIN-001"],
            evidence_ids=data["evidence_ids"],
            crown_jewel_asset_ids=[],
            max_depth=3,
            actor_id=str(data["user"].id),
        )


@pytest.mark.django_db(transaction=True)
def test_validation_rejects_stale_threat_model_architecture():
    data = _fixture("stale-chain")
    SecurityGraphNode.objects.create(
        project=data["project"],
        plane=SecurityGraphNode.Plane.IDENTITY,
        kind=SecurityGraphNode.Kind.IDENTITY,
        external_ref="identity:new-admin",
        label="New Admin",
    )
    with pytest.raises(AttackPathValidationError, match="architecture binding is stale"):
        validate_attack_path(
            organization=data["organization"],
            project=data["project"],
            attack_path_id=str(data["path"].id),
            threat_model_snapshot_id=str(data["threat_model"].id),
            scenario_refs=["CHAIN-001"],
            evidence_ids=data["evidence_ids"],
            crown_jewel_asset_ids=[],
            max_depth=3,
            actor_id=str(data["user"].id),
        )


@pytest.mark.django_db(transaction=True)
def test_validation_rejects_missing_relationship_and_expired_authorization():
    data = _fixture("relationship-chain")
    data["relationships"][1].delete()
    with pytest.raises(AttackPathValidationError, match="no directionally valid AssetRelationship"):
        validate_attack_path(
            organization=data["organization"],
            project=data["project"],
            attack_path_id=str(data["path"].id),
            threat_model_snapshot_id=str(data["threat_model"].id),
            scenario_refs=["CHAIN-001"],
            evidence_ids=data["evidence_ids"],
            crown_jewel_asset_ids=[],
            max_depth=3,
            actor_id=str(data["user"].id),
        )

    other = _fixture("expired-chain")
    _authorize(
        other["middle"],
        other["user"],
        authorized=True,
        expires_at=timezone.now() - timedelta(seconds=1),
    )
    with pytest.raises(AttackPathValidationError, match="no current governed authorization"):
        validate_attack_path(
            organization=other["organization"],
            project=other["project"],
            attack_path_id=str(other["path"].id),
            threat_model_snapshot_id=str(other["threat_model"].id),
            scenario_refs=["CHAIN-001"],
            evidence_ids=other["evidence_ids"],
            crown_jewel_asset_ids=[],
            max_depth=3,
            actor_id=str(other["user"].id),
        )


@pytest.mark.django_db(transaction=True)
def test_validation_rejects_reversed_directional_relationship():
    data = _fixture("directional-chain")
    relation = data["relationships"][1]
    relation.delete()
    AssetRelationship.objects.create(
        project=data["project"],
        source=data["target"],
        target=data["middle"],
        relationship_type=AssetRelationship.RelationshipType.DEPENDS_ON,
    )

    with pytest.raises(AttackPathValidationError, match="directionally valid"):
        validate_attack_path(
            organization=data["organization"],
            project=data["project"],
            attack_path_id=str(data["path"].id),
            threat_model_snapshot_id=str(data["threat_model"].id),
            scenario_refs=["CHAIN-001"],
            evidence_ids=data["evidence_ids"],
            crown_jewel_asset_ids=[],
            max_depth=3,
            actor_id=str(data["user"].id),
        )


@pytest.mark.django_db(transaction=True)
def test_validation_rejects_evidence_outside_path_and_requires_target_evidence():
    data = _fixture("evidence-chain")
    off_path = _asset(data["project"], "off-path")
    off_path_evidence = Evidence.objects.create(
        asset=off_path,
        source="validated-attack-chain-test",
        evidence_type="scanner_output",
        raw_output="off path evidence",
        collected_by=data["user"],
    )
    with pytest.raises(AttackPathValidationError, match="not bound to a path asset"):
        validate_attack_path(
            organization=data["organization"],
            project=data["project"],
            attack_path_id=str(data["path"].id),
            threat_model_snapshot_id=str(data["threat_model"].id),
            scenario_refs=["CHAIN-001"],
            evidence_ids=[str(off_path_evidence.id)],
            crown_jewel_asset_ids=[],
            max_depth=3,
            actor_id=str(data["user"].id),
        )

    _, source_evidence = _confirmed_evidence(
        project=data["project"],
        user=data["user"],
        asset=data["source"],
        suffix="source-only",
        risk_score=7.0,
    )
    with pytest.raises(AttackPathValidationError, match="each attack-path hop target"):
        validate_attack_path(
            organization=data["organization"],
            project=data["project"],
            attack_path_id=str(data["path"].id),
            threat_model_snapshot_id=str(data["threat_model"].id),
            scenario_refs=["CHAIN-001"],
            evidence_ids=[str(source_evidence.id)],
            crown_jewel_asset_ids=[],
            max_depth=3,
            actor_id=str(data["user"].id),
        )


@pytest.mark.django_db(transaction=True)
def test_validation_requires_confirmed_evidence_for_each_hop_target():
    data = _fixture("hop-proof-chain")

    with pytest.raises(AttackPathValidationError, match="each attack-path hop target"):
        validate_attack_path(
            organization=data["organization"],
            project=data["project"],
            attack_path_id=str(data["path"].id),
            threat_model_snapshot_id=str(data["threat_model"].id),
            scenario_refs=["CHAIN-001"],
            evidence_ids=[str(data["evidence"].id)],
            crown_jewel_asset_ids=[],
            max_depth=3,
            actor_id=str(data["user"].id),
        )

    generic_middle = Evidence.objects.create(
        asset=data["middle"],
        source="validated-attack-chain-test",
        evidence_type="scanner_output",
        raw_output="generic unqualified middle evidence",
        collected_by=data["user"],
    )
    with pytest.raises(AttackPathValidationError, match="bound to a confirmed finding"):
        validate_attack_path(
            organization=data["organization"],
            project=data["project"],
            attack_path_id=str(data["path"].id),
            threat_model_snapshot_id=str(data["threat_model"].id),
            scenario_refs=["CHAIN-001"],
            evidence_ids=[str(generic_middle.id), str(data["evidence"].id)],
            crown_jewel_asset_ids=[],
            max_depth=3,
            actor_id=str(data["user"].id),
        )


@pytest.mark.django_db(transaction=True)
def test_legacy_blast_api_cannot_create_attack_path_bound_snapshot():
    data = _fixture("legacy-blast-bypass")
    with pytest.raises(ValueError, match="validated attack chain workflow"):
        persist_blast_radius(
            project=data["project"],
            root_ref=str(data["target"].id),
            impacted_nodes=[{"id": str(data["target"].id), "risk": 100, "distance": 0}],
            crown_jewel_refs=[str(data["target"].id)],
            evidence_refs=[str(data["evidence"].id)],
            attack_path_id=str(data["path"].id),
        )

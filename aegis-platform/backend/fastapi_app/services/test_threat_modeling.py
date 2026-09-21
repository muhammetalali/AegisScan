from __future__ import annotations

import uuid

import pytest

from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.models import EvidenceGraphEdge, EvidenceGraphNode, ThreatModelSnapshot
from enterprise.services import ensure_project_tenant
from enterprise.web_security_models import SecurityGraphEdge, SecurityGraphNode
from fastapi_app.services.threat_modeling import ThreatModelError, create_threat_model_snapshot


def _project(prefix: str):
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
        environment=Project.Environment.STAGING,
    )
    organization = ensure_project_tenant(project, str(user.id))
    return user, project, organization


def _graph(project):
    source = SecurityGraphNode.objects.create(
        project=project,
        plane=SecurityGraphNode.Plane.ATTACK_SURFACE,
        kind=SecurityGraphNode.Kind.EXTERNAL_SERVICE,
        external_ref="edge:internet",
        label="Internet Edge",
        protocol="https",
        provenance={"source": "threat-model-test"},
    )
    target = SecurityGraphNode.objects.create(
        project=project,
        plane=SecurityGraphNode.Plane.APPLICATION,
        kind=SecurityGraphNode.Kind.DATABASE,
        external_ref="data:customer-db",
        label="Customer Database",
        protocol="postgresql",
        provenance={"source": "threat-model-test"},
    )
    SecurityGraphEdge.objects.create(
        project=project,
        source=source,
        target=target,
        relation="reaches",
        provenance={"source": "threat-model-test"},
    )
    return source, target


def _scenario(**overrides):
    value = {
        "ref": "TM-001",
        "title": "External identity path reaches customer data",
        "description": "Threat scenario grounded in the persisted architecture graph.",
        "source_ref": "edge:internet",
        "target_ref": "data:customer-db",
        "severity": "critical",
        "pasta_stage": 4,
        "stride": ["spoofing", "elevation-of-privilege"],
        "linddun": ["identifiability", "disclosure"],
        "capec_ids": ["CAPEC-115", "CAPEC-233"],
        "assumptions": ["external identity is reachable"],
        "preconditions": ["valid routing path exists"],
        "impacts": ["customer data confidentiality loss"],
        "control_refs": ["control:mfa", "control:db-segmentation"],
        "evidence_refs": ["evidence:architecture-review-001"],
    }
    value.update(overrides)
    return value


@pytest.mark.django_db(transaction=True)
def test_threat_model_snapshot_is_immutable_deduplicated_and_projected():
    user, project, organization = _project("threat-snapshot")
    _graph(project)

    snapshot, created = create_threat_model_snapshot(
        organization=organization,
        project=project,
        actor_id=str(user.id),
        title="Customer data threat model",
        methodologies=["STRIDE", "LINDDUN", "CAPEC", "PASTA"],
        pasta_stage=4,
        scope={"objective": "protect customer data", "trust_boundaries": ["internet-to-app"]},
        scenarios=[_scenario()],
    )
    assert created is True
    assert len(snapshot.model_sha256) == 64
    assert len(snapshot.architecture_sha256) == 64
    assert snapshot.scenarios[0]["scenario_sha256"]
    assert snapshot.scenarios[0]["capec_ids"] == ["CAPEC-115", "CAPEC-233"]

    threat = EvidenceGraphNode.objects.get(
        project=project,
        kind=EvidenceGraphNode.Kind.THREAT,
        external_ref=f"threat-model:{snapshot.model_sha256}:TM-001",
    )
    assert threat.properties["threat_model_id"] == str(snapshot.id)
    assert EvidenceGraphEdge.objects.filter(
        project=project,
        target=threat,
        edge_type="originates_threat",
    ).count() == 1
    assert EvidenceGraphEdge.objects.filter(
        project=project,
        source=threat,
        edge_type="threatens",
    ).count() == 1

    repeated, repeated_created = create_threat_model_snapshot(
        organization=organization,
        project=project,
        actor_id=str(user.id),
        title="Customer data threat model",
        methodologies=["PASTA", "CAPEC", "LINDDUN", "STRIDE"],
        pasta_stage=4,
        scope={"objective": "protect customer data", "trust_boundaries": ["internet-to-app"]},
        scenarios=[_scenario()],
    )
    assert repeated_created is False
    assert repeated.id == snapshot.id
    assert ThreatModelSnapshot.objects.filter(project=project).count() == 1

    snapshot.title = "mutated"
    with pytest.raises(RuntimeError, match="immutable"):
        snapshot.save()
    with pytest.raises(RuntimeError, match="immutable"):
        ThreatModelSnapshot.objects.filter(pk=snapshot.pk).update(title="mutated")


@pytest.mark.django_db(transaction=True)
def test_architecture_drift_creates_new_bound_snapshot():
    user, project, organization = _project("threat-drift")
    _graph(project)
    first, _ = create_threat_model_snapshot(
        organization=organization,
        project=project,
        actor_id=str(user.id),
        title="Drift-aware model",
        methodologies=["STRIDE", "LINDDUN", "CAPEC", "PASTA"],
        pasta_stage=4,
        scope={"objective": "detect architecture drift"},
        scenarios=[_scenario()],
    )

    SecurityGraphNode.objects.create(
        project=project,
        plane=SecurityGraphNode.Plane.IDENTITY,
        kind=SecurityGraphNode.Kind.IDENTITY,
        external_ref="identity:admin",
        label="Admin Identity",
        provenance={"source": "threat-model-test"},
    )
    second, created = create_threat_model_snapshot(
        organization=organization,
        project=project,
        actor_id=str(user.id),
        title="Drift-aware model",
        methodologies=["STRIDE", "LINDDUN", "CAPEC", "PASTA"],
        pasta_stage=4,
        scope={"objective": "detect architecture drift"},
        scenarios=[_scenario()],
    )
    assert created is True
    assert first.architecture_sha256 != second.architecture_sha256
    assert first.model_sha256 != second.model_sha256


@pytest.mark.django_db(transaction=True)
def test_threat_model_rejects_cross_project_architecture_refs():
    user, project, organization = _project("threat-isolation")
    _graph(project)
    _, foreign_project, _ = _project("threat-foreign")
    SecurityGraphNode.objects.create(
        project=foreign_project,
        plane=SecurityGraphNode.Plane.APPLICATION,
        kind=SecurityGraphNode.Kind.DATABASE,
        external_ref="data:foreign-db",
        label="Foreign Database",
    )

    with pytest.raises(ThreatModelError, match="outside the project graph"):
        create_threat_model_snapshot(
            organization=organization,
            project=project,
            actor_id=str(user.id),
            title="Isolation model",
            methodologies=["STRIDE", "PASTA"],
            pasta_stage=4,
            scope={"objective": "tenant isolation"},
            scenarios=[_scenario(target_ref="data:foreign-db", linddun=[], capec_ids=[])],
        )


@pytest.mark.django_db(transaction=True)
def test_threat_model_rejects_methodology_claim_without_scenario_coverage():
    user, project, organization = _project("threat-coverage")
    _graph(project)
    with pytest.raises(ThreatModelError, match="LINDDUN was declared"):
        create_threat_model_snapshot(
            organization=organization,
            project=project,
            actor_id=str(user.id),
            title="Coverage model",
            methodologies=["STRIDE", "LINDDUN", "PASTA"],
            pasta_stage=4,
            scope={"objective": "methodology coverage"},
            scenarios=[_scenario(linddun=[], capec_ids=[])],
        )


@pytest.mark.django_db(transaction=True)
def test_threat_model_rejects_invalid_capec_and_future_pasta_stage():
    user, project, organization = _project("threat-contract")
    _graph(project)
    with pytest.raises(ThreatModelError, match="invalid CAPEC"):
        create_threat_model_snapshot(
            organization=organization,
            project=project,
            actor_id=str(user.id),
            title="CAPEC model",
            methodologies=["STRIDE", "CAPEC", "PASTA"],
            pasta_stage=4,
            scope={},
            scenarios=[_scenario(capec_ids=["CWE-79"], linddun=[])],
        )
    with pytest.raises(ThreatModelError, match="cannot exceed"):
        create_threat_model_snapshot(
            organization=organization,
            project=project,
            actor_id=str(user.id),
            title="PASTA model",
            methodologies=["STRIDE", "PASTA"],
            pasta_stage=3,
            scope={},
            scenarios=[_scenario(pasta_stage=4, linddun=[], capec_ids=[])],
        )

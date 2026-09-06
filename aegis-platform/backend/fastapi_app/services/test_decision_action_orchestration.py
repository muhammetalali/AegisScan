from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from asgiref.sync import async_to_sync
from django.utils import timezone

from enterprise.models import DecisionAction, DecisionActionEvent, OrganizationMembership
from enterprise.services import ensure_project_tenant
from django_project.evidence.models import ValidationRun
from fastapi_app.services import decision_action_orchestration as store
from fastapi_app.services import policy_engine
from fastapi_app.services.assurance_graph_aggregator import build_assurance_graph
from fastapi_app.services.autonomous_triage import build_triage
from fastapi_app.services.graph_intelligence import analyze_graph
from fastapi_app.services.security_decision import build_decision_pack
from fastapi_app.services.workflow_sla import evaluate_sla_actions
from fastapi_app.routers.assurance_graph import _load_validations
from fastapi_app.routers.decision_actions import _resolve_action_scope
from django_project.projects.models import Project, ProjectMembership
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability


@pytest.mark.parametrize("module,initializer", [
    (store, store.initialize_action_store),
    (policy_engine, policy_engine.initialize_policy_store),
])
def test_runtime_initializers_never_execute_schema_ddl(monkeypatch, module, initializer):
    monkeypatch.setattr(module, "_schema_ready", False)
    initializer()
    assert module._schema_ready is True


def _lineage(user, suffix: str):
    project = Project.objects.create(name=f"Project {suffix}", slug=f"project-{suffix}", owner=user)
    organization = ensure_project_tenant(project, str(user.id))
    scan = Scan.objects.create(project=project, name=f"Scan {suffix}", scan_type=Scan.Type.IP, initiated_by=user)
    finding = Vulnerability.objects.create(
        scan=scan, project=project, title=f"Finding {suffix}", description="Persisted tenant-lineage finding",
        severity=Vulnerability.Severity.HIGH, source_engine="nmap",
    )
    validation = ValidationRun.objects.create(
        user=user, finding=finding, target_type="ip", target_value="192.0.2.10", scope="192.0.2.10",
        engines=["nmap"], authorized=True,
    )
    decision = {
        "decisionId":f"decision-{suffix}", "nodeId":f"finding:{validation.id}:nmap",
        "label":f"Finding {suffix}", "risk":80, "confidence":95, "priority":90,
        "recommendedAction":"Remediate", "revalidationPlan":["validate"],
        "validationId":str(validation.id), "projectId":str(project.id),
    }
    return organization, project, validation, decision


def test_validation_lineage_survives_graph_triage_and_decision() -> None:
    validation_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    graph = build_assurance_graph({validation_id: {
        "status":"completed", "progress":100, "engines":["nmap"],
        "engines_state":{"nmap":{"findings":1,"evidence":1}},
        "validation_id":validation_id, "project_id":project_id,
    }})
    pack = build_decision_pack(build_triage(analyze_graph(graph)))
    scoped = [item for item in pack["decisions"] if item.get("validationId") == validation_id]
    assert scoped
    assert {item["projectId"] for item in scoped} == {project_id}
    assert all(item["actionable"] for item in scoped)
    assert pack["summary"]["actionable"] == len(scoped)
    unscoped_engine = next(item for item in pack["decisions"] if item["nodeId"] == "engine:nmap")
    assert unscoped_engine["validationId"] is None
    assert unscoped_engine["projectId"] is None
    assert unscoped_engine["actionable"] is False


@pytest.mark.django_db(transaction=True)
def test_decision_actions_are_tenant_isolated(django_user_model) -> None:
    suffix = uuid.uuid4().hex[:10]
    user_a = django_user_model.objects.create_user(email=f"a-{suffix}@example.test")
    user_b = django_user_model.objects.create_user(email=f"b-{suffix}@example.test")
    org_a, project_a, validation_a, decision_a = _lineage(user_a, f"a-{suffix}")
    org_b, project_b, validation_b, decision_b = _lineage(user_b, f"b-{suffix}")
    action_a = store.create_action(
        decision_a,"owner-a",24,str(user_a.id),organization=org_a,project=project_a,validation=validation_a,
    )
    action_b = store.create_action(
        decision_b,"owner-b",24,str(user_b.id),organization=org_b,project=project_b,validation=validation_b,
    )
    assert [item["actionId"] for item in store.list_actions(str(user_a.id))] == [action_a["actionId"]]
    assert [item["actionId"] for item in store.list_actions(str(user_b.id))] == [action_b["actionId"]]
    assert store.get_action(action_a["actionId"],str(user_a.id))["organizationId"] == str(org_a.id)
    assert store.get_action(action_b["actionId"],str(user_a.id)) is None
    with pytest.raises(KeyError):
        store.transition(action_b["actionId"],"approved",str(user_a.id))
    transitioned = store.transition(action_b["actionId"],"approved",str(user_b.id))
    assert transitioned["state"] == "approved"
    assert transitioned["version"] == 2
    assert [event["type"] for event in transitioned["events"]] == ["action.created","action.approved"]


@pytest.mark.django_db(transaction=True)
def test_revoked_project_membership_revokes_action_access(django_user_model) -> None:
    suffix = uuid.uuid4().hex[:10]
    owner = django_user_model.objects.create_user(email=f"owner-{suffix}@example.test")
    member = django_user_model.objects.create_user(email=f"member-{suffix}@example.test")
    organization,project,_,_ = _lineage(owner,suffix)
    ProjectMembership.objects.create(project=project,user=member,role=ProjectMembership.Role.MEMBER)
    OrganizationMembership.objects.create(
        organization=organization,user=member,role=OrganizationMembership.Role.ANALYST,
    )
    scan = Scan.objects.create(project=project,name="Member scan",scan_type=Scan.Type.IP,initiated_by=member)
    finding = Vulnerability.objects.create(
        scan=scan,project=project,title="Member finding",description="Scoped",severity=Vulnerability.Severity.HIGH,
    )
    validation = ValidationRun.objects.create(
        user=member,finding=finding,target_type="ip",target_value="192.0.2.20",scope="192.0.2.20",authorized=True,
    )
    decision = {"decisionId":"member","nodeId":"node","validationId":str(validation.id),"projectId":str(project.id)}
    action = store.create_action(
        decision,"member",24,str(member.id),organization=organization,project=project,validation=validation,
    )
    assert store.get_action(action["actionId"],str(member.id)) is not None
    ProjectMembership.objects.filter(project=project,user=member).delete()
    assert store.get_action(action["actionId"],str(member.id)) is None
    with pytest.raises(KeyError):
        store.transition(action["actionId"],"approved",str(member.id))


@pytest.mark.django_db(transaction=True)
def test_action_rejects_cross_project_validation_lineage(django_user_model) -> None:
    suffix = uuid.uuid4().hex[:10]
    user = django_user_model.objects.create_user(email=f"lineage-{suffix}@example.test")
    org_a,project_a,validation_a,decision_a = _lineage(user,f"a-{suffix}")
    org_b,project_b,_,_ = _lineage(user,f"b-{suffix}")
    with pytest.raises(ValueError,match="Validation project lineage"):
        store.create_action(
            decision_a,"owner",24,str(user.id),organization=org_b,project=project_b,validation=validation_a,
        )
    assert not DecisionAction.objects.filter(validation=validation_a).exists()


@pytest.mark.django_db(transaction=True)
def test_persisted_validation_to_decision_to_action_lineage(django_user_model) -> None:
    suffix = uuid.uuid4().hex[:10]
    user = django_user_model.objects.create_user(email=f"chain-{suffix}@example.test")
    organization,project,validation,_ = _lineage(user,suffix)
    validations = async_to_sync(_load_validations)(str(user.id))
    pack = build_decision_pack(build_triage(analyze_graph(build_assurance_graph(validations))))
    decision = next(
        item for item in pack["decisions"]
        if item["nodeId"] == f"validation:{validation.id}"
    )
    resolved_org,resolved_project,resolved_validation = _resolve_action_scope(decision,str(user.id))
    action = store.create_action(
        decision,"Security Operations",24,str(user.id),
        organization=resolved_org,project=resolved_project,validation=resolved_validation,
    )
    assert decision["actionable"] is True
    assert resolved_org.id == organization.id
    assert resolved_project.id == project.id
    assert action["validationId"] == str(validation.id)
    assert action["projectId"] == str(project.id)
    assert action["organizationId"] == str(organization.id)


@pytest.mark.django_db(transaction=True)
def test_action_and_creation_event_are_atomic(monkeypatch, django_user_model) -> None:
    suffix = uuid.uuid4().hex[:10]
    user = django_user_model.objects.create_user(email=f"atomic-{suffix}@example.test")
    organization,project,validation,decision = _lineage(user,suffix)

    def fail_event(*args, **kwargs):
        raise RuntimeError("event persistence failed")

    monkeypatch.setattr(DecisionActionEvent.objects,"create",fail_event)
    with pytest.raises(RuntimeError,match="event persistence failed"):
        store.create_action(
            decision,"owner",4,str(user.id),organization=organization,project=project,validation=validation,
        )
    assert not DecisionAction.objects.filter(requested_by=str(user.id)).exists()


@pytest.mark.django_db(transaction=True)
def test_sla_breach_is_durable_versioned_and_idempotent(django_user_model) -> None:
    suffix = uuid.uuid4().hex[:10]
    user = django_user_model.objects.create_user(email=f"sla-{suffix}@example.test")
    organization,project,validation,decision = _lineage(user,suffix)
    action = store.create_action(
        decision,"owner",1,str(user.id),organization=organization,project=project,validation=validation,
    )
    evaluation_time = timezone.now() + timedelta(hours=2)
    first = evaluate_sla_actions(evaluation_time)
    second = evaluate_sla_actions(evaluation_time)
    persisted = store.get_action(action["actionId"],str(user.id))
    assert [item["actionId"] for item in first] == [action["actionId"]]
    assert second == []
    assert persisted["slaStatus"] == "breached"
    assert persisted["escalationLevel"] == 2
    assert persisted["version"] == 2
    assert [event["type"] for event in persisted["events"]] == ["action.created","action.sla_breached"]

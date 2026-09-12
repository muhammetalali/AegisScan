import pytest

from enterprise.models import Organization, TenantProject
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.enterprise_gap_closure import (
    append_finding_decision,
    contextual_priority,
    persist_blast_radius,
    persist_evidence_graph,
    predict_novel_exposure,
    update_feedback_weights,
    verify_finding_decision_chain,
    verify_policy_constraints,
)


def _fixture():
    user=User.objects.create_user(username='gap-user',email='gap@example.com',password='Passw0rd!gap')
    project=Project.objects.create(name='Gap Project',slug='gap-project',owner=user)
    organization=Organization.objects.create(name='Gap Org',slug='gap-org',owner=user)
    TenantProject.objects.create(organization=organization,project=project)
    scan=Scan.objects.create(project=project,name='gap',scan_type=Scan.Type.IP,engines=['nmap'],initiated_by=user)
    finding=Vulnerability.objects.create(
        scan=scan,project=project,title='Gap finding',description='x',
        severity=Vulnerability.Severity.HIGH,status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,cvss_score=8.0,exploitability=70,business_impact=80,
    )
    return user,project,scan,finding


@pytest.mark.django_db
def test_decision_chain_priority_feedback_and_formal_proof():
    user,project,scan,finding=_fixture()
    row=append_finding_decision(
        vulnerability_id=str(finding.id),actor_id=str(user.id),decision='confirm',
        policy_ref='POL-1',reason='validated evidence and policy',evidence_refs=[],
        new_status=Vulnerability.Status.CONFIRMED,
    )
    assert len(row.entry_hash)==64
    assert verify_finding_decision_chain(str(finding.id))['valid'] is True
    finding.refresh_from_db()
    assert finding.status==Vulnerability.Status.CONFIRMED
    score=contextual_priority(finding)
    assert 0 <= score['priority'] <= 100
    profile=update_feedback_weights(project=project,features={key:1 for key in score['weights']},reward=1)
    assert profile.learned_from==1
    assert abs(sum(profile.weights.values())-1)<1e-6
    prediction=predict_novel_exposure({'novelty':1,'surface_change':1,'reachability':1,'control_gap':1})
    assert 0 < prediction['probability'] < 1
    assert prediction['claim']=='exposure-risk-estimate-not-zero-day-discovery'
    proof=verify_policy_constraints(
        project=project,proof_type='scan-authorization',
        facts={'authorized':True,'in_scope':True,'destructive':False,'privileged':True,'explicit_approval':True},
    )
    assert proof.satisfiable is True


@pytest.mark.django_db
def test_formal_policy_rejects_destructive_execution_and_persists_graph():
    user,project,scan,finding=_fixture()
    proof=verify_policy_constraints(
        project=project,proof_type='destructive-block',
        facts={'authorized':True,'in_scope':True,'destructive':True,'privileged':False,'explicit_approval':False},
    )
    assert proof.satisfiable is False
    graph=persist_evidence_graph(
        project=project,
        nodes=[
            {'kind':'finding','external_ref':str(finding.id),'label':finding.title},
            {'kind':'scan','external_ref':str(scan.id),'label':scan.name},
        ],
        edges=[{'source':str(finding.id),'target':str(scan.id),'edge_type':'observed_in'}],
    )
    assert graph=={'nodes':2,'edges':1}
    blast=persist_blast_radius(
        project=project,root_ref=str(finding.id),
        impacted_nodes=[{'id':'crown','risk':90,'distance':1},{'id':'other','risk':60,'distance':2}],
        crown_jewel_refs=['crown'],evidence_refs=[],
    )
    assert blast.score > 0

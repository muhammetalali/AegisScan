from __future__ import annotations

import json
import uuid

import pytest

from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from enterprise.services import ensure_project_tenant
from fastapi_app.services.decision_action_orchestration import create_action, transition


def _context(django_user_model, suffix: str):
    user = django_user_model.objects.create_user(email=f"verify-{suffix}@example.test")
    project = Project.objects.create(name=f"Verify {suffix}", slug=f"verify-{suffix}", owner=user)
    organization = ensure_project_tenant(project, str(user.id))
    scan = Scan.objects.create(project=project, name="verification scan", scan_type=Scan.Type.IP, initiated_by=user)
    finding = Vulnerability.objects.create(
        scan=scan, project=project, title="Remediation verification finding",
        description="Must not close without independent proof", severity=Vulnerability.Severity.HIGH,
        source_engine="nmap",
    )
    original = ValidationRun.objects.create(
        user=user, finding=finding, target_type="ip", target_value="192.0.2.10",
        scope="192.0.2.10", engines=["nmap"], authorized=True,
        status=ValidationRun.Status.COMPLETED, progress=100,
    )
    decision = {
        "decisionId": f"decision-{suffix}", "nodeId": f"validation:{original.id}",
        "label": finding.title, "risk": 80, "confidence": 90, "priority": 80,
        "recommendedAction": "Remediate and independently revalidate",
        "revalidationPlan": ["rerun exact validation"],
        "validationId": str(original.id), "projectId": str(project.id),
    }
    action = create_action(
        decision, "Security Operations", 24, str(user.id),
        organization=organization, project=project, validation=original,
    )
    for state in ("approved", "assigned", "in_progress", "awaiting_revalidation"):
        action = transition(action["actionId"], state, str(user.id))
    return user, project, scan, finding, original, action


def _verification(user, finding, *, status=ValidationRun.Status.COMPLETED):
    return ValidationRun.objects.create(
        user=user, finding=finding, target_type="ip", target_value="192.0.2.10",
        scope="192.0.2.10", engines=["nmap"], authorized=True, status=status, progress=100,
    )


def _evidence(user, scan, finding, verification, finding_present: bool):
    return Evidence.objects.create(
        scan=scan, finding=finding, source="nmap", evidence_type="validation_output",
        raw_output="finding absent" if not finding_present else "finding still present",
        metadata={"validation_run_id": str(verification.id), "finding_present": finding_present},
        collected_by=user,
    )


@pytest.mark.django_db(transaction=True)
def test_verified_requires_independent_completed_negative_revalidation(django_user_model):
    suffix = uuid.uuid4().hex[:10]
    user, _, scan, finding, _, action = _context(django_user_model, suffix)
    verification = _verification(user, finding)
    evidence = _evidence(user, scan, finding, verification, False)

    verified = transition(
        action["actionId"], "verified", str(user.id), "fixed and rechecked", str(verification.id),
    )

    assert verified["state"] == "verified"
    assert verified["verificationValidationId"] == str(verification.id)
    assert verified["verificationEvidenceIds"] == [str(evidence.id)]
    assert verified["verificationEvidenceSha256"] == [evidence.sha256]
    payload = json.loads(verified["events"][-1]["note"])
    assert payload["verification_validation_id"] == str(verification.id)
    assert payload["operator_note"] == "fixed and rechecked"


@pytest.mark.django_db(transaction=True)
def test_verified_rejects_status_only_transition_without_revalidation(django_user_model):
    suffix = uuid.uuid4().hex[:10]
    user, _, _, _, _, action = _context(django_user_model, suffix)
    with pytest.raises(ValueError, match="independent verification validation id"):
        transition(action["actionId"], "verified", str(user.id))


@pytest.mark.django_db(transaction=True)
def test_verified_rejects_original_validation_as_verification(django_user_model):
    suffix = uuid.uuid4().hex[:10]
    user, _, _, _, original, action = _context(django_user_model, suffix)
    with pytest.raises(ValueError, match="independent validation run"):
        transition(action["actionId"], "verified", str(user.id), verification_validation_id=str(original.id))


@pytest.mark.django_db(transaction=True)
def test_verified_rejects_revalidation_that_still_reproduces_finding(django_user_model):
    suffix = uuid.uuid4().hex[:10]
    user, _, scan, finding, _, action = _context(django_user_model, suffix)
    verification = _verification(user, finding)
    _evidence(user, scan, finding, verification, True)
    with pytest.raises(ValueError, match="still reproduces"):
        transition(action["actionId"], "verified", str(user.id), verification_validation_id=str(verification.id))


@pytest.mark.django_db(transaction=True)
def test_verified_rejects_cross_finding_verification(django_user_model):
    suffix = uuid.uuid4().hex[:10]
    user, project, scan, _, _, action = _context(django_user_model, suffix)
    other = Vulnerability.objects.create(
        scan=scan, project=project, title="Other finding", description="Different lineage",
        severity=Vulnerability.Severity.HIGH, source_engine="nmap",
    )
    verification = _verification(user, other)
    _evidence(user, scan, other, verification, False)
    with pytest.raises(ValueError, match="finding lineage"):
        transition(action["actionId"], "verified", str(user.id), verification_validation_id=str(verification.id))

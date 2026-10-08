from pathlib import Path
import os
import subprocess

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/production-live-deploy.yml"
REALITY_WORKFLOW = ROOT / ".github/workflows/production-live-deploy-reality.yml"
CLOUD_LIVE_WORKFLOW = ROOT / ".github/workflows/cloud-live-provider-reality.yml"
IDENTITY_LIVE_WORKFLOW = ROOT / ".github/workflows/external-identity-live-provider-reality.yml"
PROD_COMPOSE = ROOT / "aegis-platform/docker-compose.prod.yml"
BASE_COMPOSE = ROOT / "aegis-platform/docker-compose.yml"


class ComposeLoader(yaml.SafeLoader):
    """Parse Docker Compose override tags without weakening SafeLoader."""


def _construct_compose_tag(loader: ComposeLoader, node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


ComposeLoader.add_constructor("!reset", _construct_compose_tag)
ComposeLoader.add_constructor("!override", _construct_compose_tag)


def _workflow() -> dict:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_live_production_workflow_has_only_manual_or_one_time_main_request_triggers():
    data = _workflow()
    triggers = data.get("on")
    assert isinstance(triggers, dict)
    assert set(triggers) == {"workflow_dispatch", "push"}
    assert triggers["push"]["branches"] == ["main"]
    assert triggers["push"]["paths"] == [".github/deployment-requests/internal-production.json"]

    jobs = data["jobs"]
    readiness = jobs["resilience-runner-readiness"]
    assert readiness["runs-on"] == ["self-hosted", "linux", "x64", "aegisscan-resilience"]
    assert readiness["timeout-minutes"] == 10
    assert "AEGISSCAN_RESILIENCE_RUNNER_READINESS=PASS" in readiness["steps"][0]["run"]
    assert "for command_name in git ssh ssh-keygen python3; do" in readiness["steps"][0]["run"]
    assert "docker" not in readiness["steps"][0]["run"]
    deploy = jobs["deploy-and-accept"]
    assert deploy["needs"] == "resilience-runner-readiness"
    assert deploy["environment"] == "production"
    assert deploy["if"] == "github.ref == 'refs/heads/main'"
    assert deploy["runs-on"] == ["self-hosted", "linux", "x64", "aegisscan-production"]
    assert data["concurrency"]["group"] == "aegisscan-internal-production-${{ github.sha }}"
    assert data["concurrency"]["cancel-in-progress"] is False


def test_checkout_repair_is_explicit_manual_opt_in_and_uses_protected_transport():
    data = _workflow()
    repair_input = data["on"]["workflow_dispatch"]["inputs"]["repair_checkout"]
    assert repair_input["type"] == "boolean"
    assert repair_input["default"] is False
    steps = data["jobs"]["deploy-and-accept"]["steps"]
    deploy = next(step for step in steps if step.get("name") == "Deploy exact main SHA through private enterprise perimeter")
    script = deploy["run"]
    assert '[ "${{ github.event_name }}" = \'workflow_dispatch\' ]' in script
    assert '[ "${{ inputs.repair_checkout }}" = \'true\' ]' in script
    assert "repair_args=()" in script
    assert "repair_args+=(--repair-current-checkout)" in script
    assert '--private-key /tmp/aegis-production/id' in script
    assert '--known-hosts /tmp/aegis-production/known_hosts' in script
    assert '--output-json /tmp/aegis-production/deploy.json' in script
    assert 'tee /tmp/aegis-production/deploy.json' not in script



def test_live_workflows_wait_for_exact_sha_required_ci_before_live_execution():
    cases = [
        (WORKFLOW, "deploy-and-accept", "Validate protected internal production transport material"),
        (CLOUD_LIVE_WORKFLOW, "live-provider-reality", "Install exact cloud runtime dependencies"),
        (IDENTITY_LIVE_WORKFLOW, "external-identity-live", "Install live identity dependencies"),
    ]
    for workflow_path, job_name, next_step_name in cases:
        data = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        assert data["permissions"]["contents"] == "read"
        assert data["permissions"]["actions"] == "read"
        steps = data["jobs"][job_name]["steps"]
        names = [step.get("name") for step in steps]
        barrier_index = names.index("Wait for exact-SHA Required CI Governance")
        authorization_index = next(
            index
            for index, name in enumerate(names)
            if name and (
                "Authorize exact-main" in name
                or "Require explicit bounded production authorization" in name
            )
        )
        assert authorization_index < barrier_index < names.index(next_step_name)
        barrier = steps[barrier_index]
        assert barrier["env"]["GITHUB_TOKEN"] == "${{ github.token }}"
        assert "scripts/ci/wait_for_required_ci.py" in barrier["run"]
        assert '--sha "$GITHUB_SHA"' in barrier["run"]
        assert "--branch main" in barrier["run"]
        assert '--workflow-name "Required CI Governance"' in barrier["run"]
        assert "--event push" in barrier["run"]

    cloud = yaml.safe_load(CLOUD_LIVE_WORKFLOW.read_text(encoding="utf-8"))
    identity = yaml.safe_load(IDENTITY_LIVE_WORKFLOW.read_text(encoding="utf-8"))
    assert cloud["jobs"]["live-provider-reality"]["timeout-minutes"] >= 90
    assert identity["jobs"]["external-identity-live"]["timeout-minutes"] >= 90


def test_live_production_workflow_pins_python_312_in_isolated_venv():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "uses: actions/setup-python@v6" in text
    assert "python-version: '3.12'" in text
    assert "command -v python" in text
    assert "sys.version_info[:2] != (3, 12)" in text
    assert 'python -m venv "$RUNNER_TEMP/aegis-production-venv"' in text
    assert 'echo "$RUNNER_TEMP/aegis-production-venv/bin" >> "$GITHUB_PATH"' in text
    assert "command -v python3" not in text


def test_live_production_workflow_requires_bounded_authorization_pinned_ssh_enterprise_ca_and_exact_main():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "production_deploy_request.py" in text
    assert "--event-before" in text
    assert ".github/deployment-requests/internal-production.json" in text
    assert "AEGIS_PRODUCTION_SSH_PRIVATE_KEY" in text
    assert "AEGIS_PRODUCTION_SSH_KNOWN_HOSTS" in text
    assert "AEGIS_PRODUCTION_ENTERPRISE_CA_BUNDLE" in text
    for secret_name in (
        "AEGIS_PRODUCTION_BACKUP_S3_ENDPOINT",
        "AEGIS_PRODUCTION_BACKUP_S3_BUCKET",
        "AEGIS_PRODUCTION_BACKUP_S3_CREDENTIALS_JSON",
        "AEGIS_PRODUCTION_BACKUP_ENCRYPTION_KEY_B64",
    ):
        assert secret_name not in text
    assert "Protected production transport material is incomplete" in text
    assert "AEGIS_PRODUCTION_ALERT_WEBHOOK_URL" not in text
    assert "AEGIS_ENTERPRISE_CA_BUNDLE=/tmp/aegis-production/enterprise-ca.pem" in text
    assert "REQUESTS_CA_BUNDLE=/tmp/aegis-production/enterprise-ca.pem" in text
    assert "SSL_CERT_FILE=/tmp/aegis-production/enterprise-ca.pem" in text
    assert "production_remote_deploy.py" in text
    assert 'test "$(git rev-parse origin/main)" = "$GITHUB_SHA"' in text
    assert "StrictHostKeyChecking=no" not in text
    assert "PasswordAuthentication=yes" not in text



def test_live_production_workflow_reclaims_only_non_durable_storage_before_deploy():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "Reclaim bounded non-durable production storage" in text
    assert "production_storage_reclaim.py" in text
    assert "--minimum-free-gib 60" in text
    assert "--target-free-gib 68" in text
    assert "--defer-on-docker-unavailable" in text
    assert "storage-reclaim.json" in text
    assert text.index("Reclaim bounded non-durable production storage") < text.index("Deploy exact main SHA through private enterprise perimeter")
    assert "'storage_volume_prune_performed': host_storage['volume_prune_performed']" in text
    assert "aegisscan.production-host-storage-reclaim.v1" in text
    assert "runner_storage_deferred_to_privileged_deploy" in text

    reality = REALITY_WORKFLOW.read_text(encoding="utf-8")
    assert "'aegis-platform/scripts/production_storage_reclaim.py'" in reality
    assert "'aegis-platform/scripts/production_host_deploy.py'" in reality
    assert "'tests/test_production_storage_reclaim.py'" in reality
    assert "'tests/test_production_host_deploy.py'" in reality
    assert "aegis-platform/scripts/production_storage_reclaim.py \\" in reality
    assert "tests/test_production_storage_reclaim.py \\" in reality


def test_live_production_workflow_requires_operational_backup_alertmanager_black_box_and_cli_acceptance():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "production_remote_operational_acceptance.py" in text
    assert "operational-acceptance.json" in text
    assert "Alertmanager" in text
    assert "committed encrypted remote backup" in text
    assert "Verify internal HTTPS, private resolution, enterprise CA and security headers" in text
    assert "public_acceptance.py" in text
    assert "internal-acceptance.json" in text
    assert "Run real internal-network black-box production E2E" in text
    assert "external_black_box_e2e.py" in text
    assert "internal-black-box.log" in text
    assert "Prove installed CLI against internal production" in text
    assert "AEGIS_VERIFY_TLS: 'true'" in text
    assert "Load one-run governed E2E identities" in text
    assert "::add-mask::" in text
    assert "private E2E fixture file must be mode 0600" in text
    assert "AEGIS_E2E_EPHEMERAL_FIXTURE=true" in text
    assert "--e2e-fixture-output /tmp/aegis-production/e2e-fixture.json" in text
    assert "handle.write(f\"AEGIS_E2E_TARGET={payload[\'target\']}\\n\")" in text
    assert "Deactivate one-run E2E identities" in text
    assert "AEGIS_E2E_CLEANUP_ONLY" in text
    assert "e2e-cleanup.log" in text
    assert "Restore fail-closed production scanner scope" in text
    assert "--cleanup-e2e-scope" in text
    assert "e2e-scope-cleanup.json" in text
    assert "rm -f /tmp/aegis-production/e2e-fixture.json" in text
    assert "AEGIS_PRODUCTION_E2E_" not in text
    assert "aegisscan.go-live-evidence.v3" in text
    assert "'deployment_mode': 'internal'" in text
    assert "'network_scope': 'rfc1918-or-ipv6-ula'" in text
    assert "'internal_origin':" in text
    assert "'enterprise_ca_sha256':" in text
    assert "'alertmanager_status':" in text
    assert "'backup_status':" in text
    assert "'backup_id':" in text
    assert "retention-days: 90" in text


def test_live_production_workflow_preserves_and_validates_ssh_private_key():
    text = WORKFLOW.read_text(encoding="utf-8")
    materialize = text.split(
        "- name: Materialize pinned SSH and enterprise trust material",
        1,
    )[1].split("- name: Install internal acceptance client dependency", 1)[0]
    assert """printf '%s\\n' "$PROD_SSH_PRIVATE_KEY" > /tmp/aegis-production/id""" in materialize
    assert "ssh-keygen -y -f /tmp/aegis-production/id >/dev/null" in materialize


def test_live_production_workflow_materializes_transport_before_fixture_and_guards_cleanup():
    text = WORKFLOW.read_text(encoding="utf-8")
    materialize = text.split(
        "- name: Materialize pinned SSH and enterprise trust material",
        1,
    )[1].split("- name: Install internal acceptance client dependency", 1)[0]
    assert "/tmp/aegis-production/e2e-fixture.json" not in materialize
    assert "AEGIS_PROD_TRANSPORT_READY=true" in materialize

    identity_cleanup = text.split(
        "- name: Deactivate one-run E2E identities",
        1,
    )[1].split("- name: Restore fail-closed production scanner scope", 1)[0]
    assert 'AEGIS_E2E_EPHEMERAL_FIXTURE:-' in identity_cleanup
    assert "identity cleanup is not required" in identity_cleanup

    scope_cleanup = text.split(
        "- name: Restore fail-closed production scanner scope",
        1,
    )[1].split("- name: Build internal go-live evidence manifest", 1)[0]
    assert 'AEGIS_PROD_TRANSPORT_READY:-' in scope_cleanup
    assert "remote scope cleanup is not applicable" in scope_cleanup


@pytest.mark.parametrize("outcome,expected", [
    ("skipped", False), ("", False), ("success", True),
    ("failure", True), ("cancelled", True),
])
def test_scope_cleanup_runs_only_after_operational_acceptance_started(tmp_path, outcome, expected):
    steps = _workflow()["jobs"]["deploy-and-accept"]["steps"]
    acceptance = next(step for step in steps if step.get("id") == "operational_acceptance")
    cleanup = next(step for step in steps if step.get("name") == "Restore fail-closed production scanner scope")
    assert steps.index(acceptance) < steps.index(cleanup)
    assert cleanup["if"] == "always()"
    assert cleanup["env"]["AEGIS_OPERATIONAL_OUTCOME"] == "${{ steps.operational_acceptance.outcome }}"
    executable = tmp_path / "python"
    executable.write_text('#!/bin/sh\nprintf "cleanup-called\\n"\n', encoding="utf-8")
    executable.chmod(0o700)
    script = cleanup["run"].replace("/tmp/aegis-production", str(tmp_path))
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env={
        **os.environ, "PATH": str(tmp_path) + ":" + os.environ["PATH"],
        "AEGIS_OPERATIONAL_OUTCOME": outcome, "AEGIS_PROD_TRANSPORT_READY": "true",
        "PROD_SSH_HOST": "unused", "PROD_SSH_PORT": "22", "PROD_SSH_USER": "unused",
        "GITHUB_SHA": "a" * 40,
    })
    assert result.returncode == 0, result.stderr
    assert ("cleanup-called" in result.stdout) is expected


def test_live_production_workflow_has_no_public_hosted_runner_or_public_evidence_contract():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "runs-on: ubuntu-latest" not in text
    assert "public_origin" not in text
    assert "public-acceptance.json" not in text
    assert "against public production" not in text
    assert "Verify public HTTPS" not in text

def test_production_validation_target_is_internal_only_and_explicitly_authorized():
    data = yaml.load(PROD_COMPOSE.read_text(encoding="utf-8"), Loader=ComposeLoader)
    assert isinstance(data, dict)
    scan_target = data["services"]["scan_target"]
    assert scan_target["profiles"] == ["ci-only"]
    assert "ports" not in scan_target

    text = PROD_COMPOSE.read_text(encoding="utf-8")
    assert "ALLOW_SINGLE_LABEL_SCAN_TARGETS" not in text
    assert "aegis-scan-target" not in text
    assert 'SCANNER_EGRESS_PRIVATE_TARGETS: "${SCANNER_EGRESS_PRIVATE_TARGETS:-},aegis-scan-target"' not in text


def test_production_backend_services_receive_required_runtime_environment():
    data = yaml.load(PROD_COMPOSE.read_text(encoding="utf-8"), Loader=ComposeLoader)
    assert isinstance(data, dict)

    required = {
        "DEBUG",
        "SECRET_KEY",
        "JWT_SECRET_KEY",
        "DATABASE_URL",
        "REDIS_URL",
        "CELERY_BROKER_URL",
        "CELERY_RESULT_BACKEND",
        "CREDENTIAL_VAULT_KEYS",
        "CREDENTIAL_FINGERPRINT_KEY",
        "ALLOWED_HOSTS",
        "CORS_ALLOWED_ORIGINS",
        "CSRF_TRUSTED_ORIGINS",
        "DJANGO_SETTINGS_MODULE",
    }
    interpolated_inputs = required - {"DEBUG", "DJANGO_SETTINGS_MODULE"}
    for service_name in (
        "django",
        "fastapi",
        "celery_worker",
        "scanner_worker",
        "browser_worker",
        "celery_beat",
    ):
        service = data["services"][service_name]
        assert service["env_file"] == []
        environment = service["environment"]
        assert required <= set(environment)
        for name in interpolated_inputs:
            assert environment[name] == f"${{{name}:-}}"

    assert data["services"]["django"]["environment"]["AUTH_COOKIE_SECURE"] == "True"



def test_django_healthcheck_uses_configured_allowed_host_instead_of_localhost():
    data = yaml.safe_load(BASE_COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)

    test = data["services"]["django"]["healthcheck"]["test"]
    assert test[:3] == ["CMD", "python", "-c"]
    script = test[3]
    assert "ALLOWED_HOSTS" in script
    assert "split(',')[0]" in script
    assert "headers={'Host':h}" in script
    assert "127.0.0.1" in script
    assert "localhost:8000" not in script

def test_file_acceptance_is_explicit_one_release_opt_in_with_production_finding_proof():
    data = _workflow()
    file_input = data["on"]["workflow_dispatch"]["inputs"]["file_acceptance"]
    assert file_input["type"] == "boolean"
    assert file_input["default"] is False

    steps = data["jobs"]["deploy-and-accept"]["steps"]
    e2e = next(
        step for step in steps
        if step.get("name") == "Run real internal-network black-box production E2E"
    )
    assert e2e["env"]["AEGIS_E2E_FILE_ACCEPTANCE"] == "${{ inputs.file_acceptance || false }}"
    assert e2e["env"]["AEGIS_E2E_FILE_REQUIRE_FINDING"] == "${{ inputs.file_acceptance || false }}"

    ci = (ROOT / ".github/workflows/external-black-box-e2e.yml").read_text(encoding="utf-8")
    assert "AEGIS_E2E_FILE_ACCEPTANCE: 'true'" in ci
    assert "AEGIS_E2E_FILE_REQUIRE_FINDING: 'false'" in ci


def test_production_zip_acceptance_is_opt_in_and_requires_semgrep_findings():
    workflow = _workflow()
    dispatch_input = workflow["on"]["workflow_dispatch"]["inputs"]["file_acceptance"]
    assert dispatch_input["type"] == "boolean"
    assert dispatch_input["default"] is False

    step = next(
        s for s in workflow["jobs"]["deploy-and-accept"]["steps"]
        if s.get("name") == "Run real internal-network black-box production E2E"
    )
    assert step["env"]["AEGIS_E2E_ZIP_ACCEPTANCE"] == "${{ inputs.file_acceptance || false }}"
    assert step["env"]["AEGIS_E2E_FILE_REQUIRE_FINDING"] == "${{ inputs.file_acceptance || false }}"


def test_zip_acceptance_fixture_contains_only_nested_static_code():
    import importlib.util
    import io
    import sys
    import types
    import zipfile
    from unittest.mock import patch

    harness = ROOT / "aegis-platform/e2e/external_black_box_e2e.py"
    spec = importlib.util.spec_from_file_location("isolated_external_black_box_harness", harness)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Contract-only CI runners install pytest/YAML, not HTTP client packages.
    # Stub transport imports; no network call is made by this pure fixture test.
    with patch.dict(sys.modules, {'requests': types.ModuleType('requests')}):
        spec.loader.exec_module(module)

    standalone_name, plain, standalone_mime = module.file_acceptance_fixture()
    zip_name, archive_bytes, zip_mime = module.file_acceptance_fixture(archive=True)
    assert standalone_name.endswith(".py") and standalone_mime == "text/x-python"
    assert zip_name.endswith(".zip") and zip_mime == "application/zip"
    assert b"eval(user_input)" in plain

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        assert archive.namelist() == ["src/aegis-file-acceptance.py"]
        assert archive.read("src/aegis-file-acceptance.py") == plain

    source = harness.read_text(encoding="utf-8")
    assert "if ZIP_ACCEPTANCE and not FILE_ACCEPTANCE:raise RuntimeError" in source
    assert "if ZIP_ACCEPTANCE:prove_file_assessment(session,approver,project_id,unique,archive=True)" in source
    assert "'CONTROLLED_LAUNCH_ZIP' if archive else 'CONTROLLED_LAUNCH_FILE'" in source

from pathlib import Path
import os
import subprocess

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/production-live-deploy.yml"
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
    deploy = jobs["deploy-and-accept"]
    assert deploy["environment"] == "production"
    assert deploy["if"] == "github.ref == 'refs/heads/main'"
    assert deploy["runs-on"] == ["self-hosted", "linux", "x64", "aegisscan-production"]
    assert data["concurrency"]["cancel-in-progress"] is False


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
    assert "AEGIS_ENTERPRISE_CA_BUNDLE=/tmp/aegis-production/enterprise-ca.pem" in text
    assert "REQUESTS_CA_BUNDLE=/tmp/aegis-production/enterprise-ca.pem" in text
    assert "SSL_CERT_FILE=/tmp/aegis-production/enterprise-ca.pem" in text
    assert "production_remote_deploy.py" in text
    assert 'test "$(git rev-parse origin/main)" = "$GITHUB_SHA"' in text
    assert "StrictHostKeyChecking=no" not in text
    assert "PasswordAuthentication=yes" not in text


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

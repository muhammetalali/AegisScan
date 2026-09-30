import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def _load(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reality = _load(
    "production_host_reality",
    "aegis-platform/scripts/production_host_reality.py",
)
secret_init = _load(
    "production_secret_init",
    "aegis-platform/scripts/production_secret_init.py",
)
operational_acceptance = _load(
    "production_operational_acceptance_for_host_contract",
    "aegis-platform/scripts/production_operational_acceptance.py",
)


def _private_json(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "access_key_id": "ci-access",
                "secret_access_key": "ci-secret-value",
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def test_secret_initializer_writes_private_distinct_material(tmp_path: Path):
    source = _private_json(tmp_path / "source.json")
    output = tmp_path / "production.env"
    secrets_dir = tmp_path / "secrets"

    result = secret_init.initialize(
        domain="security.example.com",
        authorized_targets=["203.0.113.10", "authorized.example.com"],
        alert_webhook="https://security.example.com:8443/_aegis/alerts",
        backup_endpoint="https://backups.example.com",
        backup_bucket="aegisscan-production-backups",
        backup_region="eu-central-1",
        s3_credentials_source=source,
        output_env=output,
        secrets_dir=secrets_dir,
    )

    assert result["status"] == "success"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE((secrets_dir / "s3-credentials.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((secrets_dir / "backup-encryption.key").stat().st_mode) == 0o600
    assert (secrets_dir / "backup-encryption.key").stat().st_size == 32
    assert stat.S_IMODE((secrets_dir / "alert-receiver-token").stat().st_mode) == 0o600

    values = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    assert values["SECRET_KEY"] != values["JWT_SECRET_KEY"]
    assert values["POSTGRES_PASSWORD"] not in {"change-me", "password", "secret"}
    assert values["ALLOWED_HOSTS"] == "security.example.com"
    assert values["AUTHORIZED_SCAN_TARGETS"] == "203.0.113.10,authorized.example.com"
    assert values["AEGIS_REMOTE_BACKUP_ENABLED"] == "true"


@pytest.mark.parametrize(
    ("domain", "targets", "webhook", "endpoint", "bucket"),
    [
        ("localhost", ["203.0.113.10"], "https://alerts.example.com/a", "https://b.example.com", "valid-bucket"),
        ("security.example.com", ["*"], "https://alerts.example.com/a", "https://b.example.com", "valid-bucket"),
        ("security.example.com", ["127.0.0.1"], "https://alerts.example.com/a", "https://b.example.com", "valid-bucket"),
        ("security.example.com", ["203.0.113.10"], "http://alerts.example.com/a", "https://b.example.com", "valid-bucket"),
        ("security.example.com", ["203.0.113.10"], "https://alerts.example.com/a", "http://127.0.0.1:9000", "valid-bucket"),
        ("security.example.com", ["203.0.113.10"], "https://alerts.example.com/a", "https://b.example.com", "INVALID_BUCKET"),
    ],
)
def test_secret_initializer_rejects_unsafe_external_inputs(
    tmp_path: Path,
    domain: str,
    targets: list[str],
    webhook: str,
    endpoint: str,
    bucket: str,
):
    source = _private_json(tmp_path / "source.json")
    with pytest.raises(secret_init.SecretInitError):
        secret_init.initialize(
            domain=domain,
            authorized_targets=targets,
            alert_webhook=webhook,
            backup_endpoint=endpoint,
            backup_bucket=bucket,
            backup_region="eu-central-1",
            s3_credentials_source=source,
            output_env=tmp_path / "production.env",
            secrets_dir=tmp_path / "secrets",
        )


def test_secret_initializer_rejects_non_private_s3_source(tmp_path: Path):
    source = _private_json(tmp_path / "source.json")
    source.chmod(0o644)
    with pytest.raises(secret_init.SecretInitError, match="group or others"):
        secret_init.initialize(
            domain="security.example.com",
            authorized_targets=["203.0.113.10"],
            alert_webhook="https://security.example.com:8443/_aegis/alerts",
            backup_endpoint="https://backups.example.com",
            backup_bucket="aegisscan-production-backups",
            backup_region="eu-central-1",
            s3_credentials_source=source,
            output_env=tmp_path / "production.env",
            secrets_dir=tmp_path / "secrets",
        )



def test_host_reality_operational_material_contract_matches_post_deploy_acceptance():
    assert reality.OPERATIONAL_REQUIRED_ENV == operational_acceptance.OPERATIONAL_REQUIRED_ENV

def test_host_reality_rejects_missing_or_unsafe_operational_material_before_runtime_probes(
    tmp_path: Path, monkeypatch
):
    credentials = _private_json(tmp_path / "s3.json")
    key = tmp_path / "backup.key"
    key.write_bytes(b"x" * 32)
    key.chmod(0o600)
    token = tmp_path / "alert-receiver-token"
    token.write_bytes(b"t" * 64 + b"\n")
    token.chmod(0o600)
    monkeypatch.setattr(reality, "ALERT_RECEIVER_RUNTIME_UID", token.stat().st_uid)
    monkeypatch.setattr(reality, "ALERT_RECEIVER_RUNTIME_GID", token.stat().st_gid)
    env_file = tmp_path / "production.env"
    values = {
        "ALLOWED_HOSTS": "security.example.com",
        "AEGIS_PRODUCTION_DOMAIN": "security.example.com",
        "ALERT_WEBHOOK_URL": "https://security.example.com:8443/_aegis/alerts",
        "AEGIS_ALERT_RECEIVER_TOKEN_FILE": str(token),
        "AEGIS_BACKUP_S3_ENDPOINT": "https://backups.example.com",
        "AEGIS_BACKUP_S3_BUCKET": "aegis-production",
        "AEGIS_BACKUP_S3_CREDENTIALS_FILE": str(credentials),
        "AEGIS_BACKUP_ENCRYPTION_KEY_FILE": str(key),
    }

    def write_env(overrides=None):
        current = dict(values)
        current.update(overrides or {})
        env_file.write_text("\n".join(f"{k}={v}" for k, v in current.items()) + "\n", encoding="utf-8")
        env_file.chmod(0o600)

    write_env()
    evidence = reality._validate_operational_material(env_file)
    assert evidence["alert_webhook_https"] is True
    assert evidence["alert_receiver_mode"] == "internal-authenticated"
    assert evidence["backup_credentials_private"] is True

    write_env({"ALERT_WEBHOOK_URL": "https://alerts.example.com/aegis"})
    with pytest.raises(reality.HostValidationError, match="internal receiver"):
        reality._validate_operational_material(env_file)

    write_env({"ALERT_WEBHOOK_URL": "http://security.example.com:8443/_aegis/alerts"})
    with pytest.raises(reality.HostValidationError, match="HTTPS"):
        reality._validate_operational_material(env_file)

    write_env()
    credentials.chmod(0o640)
    with pytest.raises(reality.HostValidationError, match="0600"):
        reality._validate_operational_material(env_file)


def test_host_reality_allows_missing_webhook_only_when_internal_receiver_can_be_auto_provisioned(tmp_path: Path):
    credentials = _private_json(tmp_path / "s3.json")
    key = tmp_path / "backup.key"
    key.write_bytes(b"x" * 32)
    key.chmod(0o600)
    env_file = tmp_path / "production.env"
    env_file.write_text(
        "\n".join([
            "ALLOWED_HOSTS=security.example.com",
            "ALERT_WEBHOOK_URL=",
            "AEGIS_BACKUP_S3_ENDPOINT=https://backups.example.com",
            "AEGIS_BACKUP_S3_BUCKET=aegis-production",
            f"AEGIS_BACKUP_S3_CREDENTIALS_FILE={credentials}",
            f"AEGIS_BACKUP_ENCRYPTION_KEY_FILE={key}",
        ]) + "\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    evidence = reality._validate_operational_material(env_file)
    assert evidence["alert_webhook_https"] is True
    assert evidence["alert_receiver_mode"] == "auto-internal"


def test_enterprise_ca_must_exist_be_bounded_and_parse_as_trust_anchor(tmp_path: Path, monkeypatch):
    missing = tmp_path / "missing.pem"
    with pytest.raises(reality.HostValidationError, match="missing"):
        reality._enterprise_ca_evidence(missing)

    empty = tmp_path / "empty.pem"
    empty.write_bytes(b"")
    with pytest.raises(reality.HostValidationError, match="invalid size"):
        reality._enterprise_ca_evidence(empty)

    ca = tmp_path / "enterprise-ca.pem"
    ca.write_text("not-a-ca\n", encoding="utf-8")
    with pytest.raises(reality.HostValidationError, match="valid TLS trust anchor"):
        reality._enterprise_ca_evidence(ca)


def test_host_reality_requires_four_vcpu_floor(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("A=B\n", encoding="utf-8")
    monkeypatch.setattr(reality.platform, "system", lambda: "Linux")
    monkeypatch.setattr(reality.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(reality.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reality.os, "cpu_count", lambda: reality.MIN_CPU_COUNT - 1)
    monkeypatch.setattr(reality, "_validate_operational_material", lambda _: {})
    with pytest.raises(reality.HostValidationError, match="vCPU"):
        reality.validate(env_file)


def test_host_reality_requires_production_resource_floor(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("A=B\n", encoding="utf-8")
    monkeypatch.setattr(reality.platform, "system", lambda: "Linux")
    monkeypatch.setattr(reality.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(reality.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reality.os, "cpu_count", lambda: reality.MIN_CPU_COUNT)
    monkeypatch.setattr(reality, "_validate_operational_material", lambda _: {})
    monkeypatch.setattr(reality, "_memory_bytes", lambda: reality.MIN_MEMORY_BYTES - 1)
    with pytest.raises(reality.HostValidationError, match="7 GiB"):
        reality.validate(env_file)


def test_host_reality_keeps_disk_floor_strict_by_default(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("A=B\\n", encoding="utf-8")
    monkeypatch.setattr(reality.platform, "system", lambda: "Linux")
    monkeypatch.setattr(reality.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(reality.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reality.os, "cpu_count", lambda: reality.MIN_CPU_COUNT)
    monkeypatch.setattr(reality, "_validate_operational_material", lambda _: {})
    monkeypatch.setattr(reality, "_memory_bytes", lambda: reality.MIN_MEMORY_BYTES + 1)
    monkeypatch.setattr(reality, "_disk_free_bytes", lambda _: reality.MIN_DISK_BYTES - 1)

    with pytest.raises(reality.HostValidationError, match="60 GiB"):
        reality.validate(env_file)


def test_host_reality_runs_ca_capability_namespace_and_compose_probes(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("A=B\n", encoding="utf-8")
    events = []

    monkeypatch.setattr(reality.platform, "system", lambda: "Linux")
    monkeypatch.setattr(reality.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(reality.platform, "release", lambda: "6.8.0")
    monkeypatch.setattr(reality.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reality.os, "cpu_count", lambda: reality.MIN_CPU_COUNT)
    monkeypatch.setattr(
        reality,
        "_validate_operational_material",
        lambda _: {
            "alert_webhook_https": True,
            "backup_endpoint_https": True,
            "backup_credentials_private": True,
            "backup_encryption_key_private": True,
        },
    )
    monkeypatch.setattr(reality, "_memory_bytes", lambda: reality.MIN_MEMORY_BYTES + 1)
    monkeypatch.setattr(reality, "_disk_free_bytes", lambda _: reality.MIN_DISK_BYTES + 1)
    monkeypatch.setattr(reality, "_kernel_ipv4_forward", lambda: True)
    monkeypatch.setattr(
        reality,
        "_enterprise_ca_evidence",
        lambda: {"path": "/etc/aegisscan/enterprise-ca.pem", "sha256": "a" * 64},
    )
    monkeypatch.setattr(
        reality,
        "_require_commands",
        lambda: {"docker": "Docker version test", "docker_compose": "Docker Compose test"},
    )
    monkeypatch.setattr(
        reality,
        "_docker_info",
        lambda: {
            "server_version": "test",
            "driver": "overlay2",
            "cgroup_driver": "systemd",
            "cgroup_version": "2",
            "security_options": [],
            "os_type": "linux",
            "architecture": "x86_64",
        },
    )
    monkeypatch.setattr(reality, "_probe_capability", lambda cap, command: events.append(("cap", cap)))
    monkeypatch.setattr(reality, "_probe_shared_network_namespace", lambda: events.append(("netns", True)))
    monkeypatch.setattr(reality, "_validate_compose", lambda env: events.append(("compose", env)))

    result = reality.validate(env_file)
    assert result["status"] == "success"
    assert result["deployment_mode"] == "internal"
    assert result["enterprise_ca"]["sha256"] == "a" * 64
    assert result["operational_material"]["alert_webhook_https"] is True
    assert ("cap", "NET_RAW") in events
    assert ("cap", "NET_ADMIN") in events
    assert ("netns", True) in events
    assert ("compose", env_file) in events

    monkeypatch.setattr(reality, "_disk_free_bytes", lambda _: reality.MIN_DISK_BYTES - 1)
    deferred = reality.validate(env_file, defer_disk_capacity=True)
    assert deferred["host"]["free_disk_bytes"] == reality.MIN_DISK_BYTES - 1
    assert deferred["host"]["minimum_free_disk_bytes"] == reality.MIN_DISK_BYTES
    assert deferred["host"]["disk_capacity_satisfied"] is False
    assert deferred["host"]["disk_capacity_deferred_to_privileged_reclaim"] is True

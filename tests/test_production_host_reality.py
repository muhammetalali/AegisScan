import importlib.util
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

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
        alert_webhook="https://alerts.example.com/aegis",
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

    values = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    assert values["SECRET_KEY"] != values["JWT_SECRET_KEY"]
    assert values["POSTGRES_PASSWORD"] not in {
        "change-me",
        "password",
        "secret",
    }
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
            alert_webhook="https://alerts.example.com/aegis",
            backup_endpoint="https://backups.example.com",
            backup_bucket="aegisscan-production-backups",
            backup_region="eu-central-1",
            s3_credentials_source=source,
            output_env=tmp_path / "production.env",
            secrets_dir=tmp_path / "secrets",
        )



def test_host_reality_requires_four_vcpu_floor(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("A=B\n", encoding="utf-8")
    monkeypatch.setattr(reality.platform, "system", lambda: "Linux")
    monkeypatch.setattr(reality.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(reality.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reality.os, "cpu_count", lambda: reality.MIN_CPU_COUNT - 1)
    with pytest.raises(reality.HostValidationError, match="vCPU"):
        reality.validate(env_file)

def test_host_reality_requires_production_resource_floor(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("A=B\n", encoding="utf-8")

    monkeypatch.setattr(reality.platform, "system", lambda: "Linux")
    monkeypatch.setattr(reality.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(reality.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reality.os, "cpu_count", lambda: reality.MIN_CPU_COUNT)
    monkeypatch.setattr(reality, "_memory_bytes", lambda: reality.MIN_MEMORY_BYTES - 1)

    with pytest.raises(reality.HostValidationError, match="7 GiB"):
        reality.validate(env_file)


def test_host_reality_runs_capability_namespace_and_compose_probes(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("A=B\n", encoding="utf-8")
    events = []

    monkeypatch.setattr(reality.platform, "system", lambda: "Linux")
    monkeypatch.setattr(reality.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(reality.platform, "release", lambda: "6.8.0")
    monkeypatch.setattr(reality.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reality.os, "cpu_count", lambda: reality.MIN_CPU_COUNT)
    monkeypatch.setattr(reality, "_memory_bytes", lambda: reality.MIN_MEMORY_BYTES + 1)
    monkeypatch.setattr(reality, "_disk_free_bytes", lambda _: reality.MIN_DISK_BYTES + 1)
    monkeypatch.setattr(reality, "_kernel_ipv4_forward", lambda: True)
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
    monkeypatch.setattr(
        reality,
        "_probe_capability",
        lambda cap, command: events.append(("cap", cap)),
    )
    monkeypatch.setattr(
        reality,
        "_probe_shared_network_namespace",
        lambda: events.append(("netns", True)),
    )
    monkeypatch.setattr(
        reality,
        "_validate_compose",
        lambda env: events.append(("compose", env)),
    )

    result = reality.validate(env_file)
    assert result["status"] == "success"
    assert ("cap", "NET_RAW") in events
    assert ("cap", "NET_ADMIN") in events
    assert ("netns", True) in events
    assert ("compose", env_file) in events

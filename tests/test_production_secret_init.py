from __future__ import annotations

import base64
import os
import stat
import re
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


PATH = Path(__file__).parents[1] / "aegis-platform/scripts/production_secret_init.py"
SPEC = spec_from_file_location("production_secret_init", PATH)
assert SPEC and SPEC.loader
MODULE = module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, value = line.split("=", 1)
        values[name] = value
    return values


def test_secret_init_generates_private_vault_material(tmp_path: Path):
    source = tmp_path / "s3-source.json"
    source.write_text(
        '{"access_key_id":"proof-access","secret_access_key":"proof-secret"}',
        encoding="utf-8",
    )
    source.chmod(0o600)
    env_file = tmp_path / "production.env"
    secrets_dir = tmp_path / "secrets"

    result = MODULE.initialize(
        domain="security.example.com",
        authorized_targets=["authorized.example.com"],
        alert_webhook="https://alerts.example.com/aegis",
        backup_endpoint="https://backups.example.com",
        backup_bucket="aegisscan-production-backups",
        backup_region="us-east-1",
        s3_credentials_source=source,
        output_env=env_file,
        secrets_dir=secrets_dir,
    )

    assert result["status"] == "success"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    values = _parse_env(env_file)

    vault_key = values["CREDENTIAL_VAULT_KEYS"]
    decoded = base64.urlsafe_b64decode(vault_key.encode("ascii"))
    assert len(decoded) == 32

    fingerprint_key = values["CREDENTIAL_FINGERPRINT_KEY"]
    assert len(fingerprint_key) >= 32
    assert fingerprint_key not in {
        values["SECRET_KEY"],
        values["JWT_SECRET_KEY"],
        vault_key,
    }

    assert values["DATABASE_URL"].startswith("postgresql://aegis:")
    assert values["AEGIS_SCAN_SCOPE_MODE"] == "asset-authorization"
    assert values["AUTHORIZED_SCAN_TARGETS"] == "authorized.example.com"
    assert values["AEGIS_RECON_PROVIDER"] == "default-kali"
    assert values["AEGIS_RECON_LEGACY_DISABLED"] == "true"
    assert values["AEGIS_KALI_RECON_CANARY_BPS"] == "0"
    assert values["AEGIS_NMAP_PROVIDER"] == "default-kali"
    assert values["AEGIS_MASSCAN_PROVIDER"] == "default-kali"
    assert values["AEGIS_NUCLEI_PROVIDER"] == "default-kali"
    assert values["AEGIS_SEMGREP_PROVIDER"] == "default-kali"
    for name in (
        "AEGIS_KALI_RECON_AUTH_TOKEN",
        "AEGIS_KALI_NETWORK_AUTH_TOKEN",
        "AEGIS_KALI_MASSCAN_AUTH_TOKEN",
        "AEGIS_KALI_WEB_AUTH_TOKEN",
        "AEGIS_KALI_CODE_AUTH_TOKEN",
    ):
        assert re.fullmatch(r"[0-9a-f]{64}", values[name])
    assert Path(result["s3_credentials_file"]).is_file()
    assert Path(result["backup_encryption_key_file"]).is_file()

def test_secret_init_main_emits_structured_failure(monkeypatch, capsys, tmp_path: Path):
    def fail_initialize(**_kwargs):
        raise MODULE.SecretInitError("synthetic-secret-init-failure")

    monkeypatch.setattr(MODULE, "initialize", fail_initialize)
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        [
            str(PATH),
            "--domain",
            "security.example.com",
            "--authorized-target",
            "authorized.example.com",
            "--alert-webhook",
            "https://alerts.example.com/aegis",
            "--backup-endpoint",
            "https://backups.example.com",
            "--backup-bucket",
            "aegisscan-production-backups",
            "--s3-credentials-source",
            str(tmp_path / "missing-s3.json"),
        ],
    )

    assert MODULE.main() == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert '"schema": "aegisscan.production-secret-init.v1"' in captured.err
    assert '"status": "failed"' in captured.err
    assert '"error": "synthetic-secret-init-failure"' in captured.err


def test_secret_init_supports_ddns_default_scope_without_static_targets_or_webhook(tmp_path: Path):
    source = tmp_path / "s3-source.json"
    source.write_text(
        '{"access_key_id":"proof-access","secret_access_key":"proof-secret"}',
        encoding="utf-8",
    )
    source.chmod(0o600)
    env_file = tmp_path / "production.env"
    secrets_dir = tmp_path / "secrets"

    result = MODULE.initialize(
        domain=MODULE.DEFAULT_PRODUCTION_DOMAIN,
        authorized_targets=[],
        alert_webhook="",
        backup_endpoint="https://backups.example.com",
        backup_bucket="aegisscan-production-backups",
        backup_region="us-east-1",
        s3_credentials_source=source,
        output_env=env_file,
        secrets_dir=secrets_dir,
    )

    values = _parse_env(env_file)
    assert result["domain"] == "aegis-prod.aegis.internal"
    assert values["ALLOWED_HOSTS"] == "aegis-prod.aegis.internal"
    assert values["AEGIS_SCAN_SCOPE_MODE"] == "asset-authorization"
    assert values["AUTHORIZED_SCAN_TARGETS"] == ""
    assert values["ALERT_WEBHOOK_URL"] == ""

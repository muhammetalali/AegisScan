from __future__ import annotations

import base64
import os
import stat
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
    assert values["AUTHORIZED_SCAN_TARGETS"] == "authorized.example.com"
    assert Path(result["s3_credentials_file"]).is_file()
    assert Path(result["backup_encryption_key_file"]).is_file()

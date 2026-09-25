from __future__ import annotations

import importlib.util
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "aegis-platform/scripts/production_execution_trust_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("production_execution_trust_bootstrap", SCRIPT)
assert SPEC and SPEC.loader
trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trust)

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def test_trust_values_bind_exact_image_and_manifest_digest():
    image_id = "sha256:" + "a" * 64
    manifest = {
        "runner_version": "0.1.0",
        "build_commit": "b" * 40,
        "base_image_digest": "sha256:" + "c" * 64,
        "tool_manifest_digest": "sha256:" + "d" * 64,
    }
    raw = b'{"proof":"runtime"}\n'

    values = trust._trust_values("RECON", image_id, manifest, raw)

    assert values["AEGIS_KALI_RECON_IMAGE"] == image_id
    assert values["AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST"] == image_id
    assert values["AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT"] == "b" * 40
    assert values["AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST"] == "sha256:" + "c" * 64
    assert values["AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST"] == "sha256:" + "d" * 64
    assert values["AEGIS_KALI_RECON_EXPECTED_RUNTIME_MANIFEST_DIGEST"].startswith("sha256:")
    assert len(values["AEGIS_KALI_RECON_EXPECTED_RUNTIME_MANIFEST_DIGEST"]) == 71


def test_missing_provider_tokens_are_generated_once_and_existing_token_is_preserved():
    existing = "e" * 64
    values = {"AEGIS_KALI_RECON_AUTH_TOKEN": existing}

    trust._ensure_tokens(values)

    assert values["AEGIS_KALI_RECON_AUTH_TOKEN"] == existing
    generated = [values[name] for name in trust.TOKEN_NAMES if name != "AEGIS_KALI_RECON_AUTH_TOKEN"]
    assert len(generated) == 4
    assert len(set(generated)) == 4
    assert all(HEX64.fullmatch(value) for value in generated)


def test_malformed_existing_provider_token_fails_closed():
    with pytest.raises(trust.TrustBootstrapError, match="exists but is not"):
        trust._ensure_tokens({"AEGIS_KALI_RECON_AUTH_TOKEN": "not-a-token"})


def test_bootstrap_derives_all_active_provider_trust_before_env_commit(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("DEBUG=False\nSECRET_KEY=proof\n", encoding="utf-8")
    env_file.chmod(0o600)

    release_sha = "b" * 40
    monkeypatch.setattr(trust.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        trust,
        "_require_private_env",
        lambda _path: SimpleNamespace(st_uid=os.getuid(), st_gid=os.getgid(), st_size=10, st_mode=0o100600),
    )
    monkeypatch.setattr(trust, "_validate_release", lambda _sha: (_sha, "1790000000"))
    monkeypatch.setattr(
        trust,
        "_build_images",
        lambda *_args: {
            "RECON": "tag-recon",
            "NETWORK": "tag-network",
            "MASSCAN": "tag-masscan",
            "WEB": "tag-web",
            "CODE": "tag-code",
        },
    )

    image_ids = {
        "tag-recon": "sha256:" + "1" * 64,
        "tag-network": "sha256:" + "2" * 64,
        "tag-masscan": "sha256:" + "3" * 64,
        "tag-web": "sha256:" + "4" * 64,
        "tag-code": "sha256:" + "5" * 64,
    }
    monkeypatch.setattr(trust, "_image_id", lambda tag: image_ids[tag])

    def manifest(image_id: str, requested_sha: str):
        assert requested_sha == release_sha
        return (
            {
                "runner_version": "0.1.0",
                "build_commit": release_sha,
                "base_image_digest": "sha256:" + "a" * 64,
                "tool_manifest_digest": "sha256:" + "c" * 64,
            },
            (image_id + "\n").encode(),
        )

    monkeypatch.setattr(trust, "_manifest", manifest)

    committed: dict[str, str] = {}

    def capture_write(_path, values, owner):
        assert owner == (os.getuid(), os.getgid())
        committed.update(values)

    monkeypatch.setattr(trust, "_write_env", capture_write)

    result = trust.bootstrap(env_file, release_sha)

    assert result["status"] == "success"
    assert result["release_sha"] == release_sha
    assert set(result["images"]) == {"recon", "network", "masscan", "web", "code"}
    assert committed["AEGIS_RECON_PROVIDER"] == "default-kali"
    assert committed["AEGIS_RECON_LEGACY_DISABLED"] == "true"
    assert committed["AEGIS_KALI_RECON_CANARY_BPS"] == "0"
    assert committed["AEGIS_NMAP_PROVIDER"] == "default-kali"
    assert committed["AEGIS_MASSCAN_PROVIDER"] == "default-kali"
    assert committed["AEGIS_NUCLEI_PROVIDER"] == "default-kali"
    assert committed["AEGIS_SEMGREP_PROVIDER"] == "default-kali"
    assert committed["AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT"] == release_sha
    assert committed["AEGIS_KALI_NETWORK_EXPECTED_BUILD_COMMIT"] == release_sha
    assert committed["AEGIS_KALI_MASSCAN_EXPECTED_BUILD_COMMIT"] == release_sha
    assert committed["AEGIS_KALI_WEB_EXPECTED_BUILD_COMMIT"] == release_sha
    assert committed["AEGIS_KALI_CODE_EXPECTED_BUILD_COMMIT"] == release_sha
    assert all(HEX64.fullmatch(committed[name]) for name in trust.TOKEN_NAMES)


def test_production_compose_accepts_empty_static_target_projection():
    text = (ROOT / "aegis-platform/docker-compose.prod.yml").read_text(encoding="utf-8")
    assert "AUTHORIZED_SCAN_TARGETS:?AUTHORIZED_SCAN_TARGETS is required in production" not in text
    assert text.count("AUTHORIZED_SCAN_TARGETS: ${AUTHORIZED_SCAN_TARGETS:-}") >= 5
    assert "AEGIS_SCAN_SCOPE_MODE: ${AEGIS_SCAN_SCOPE_MODE:-asset-authorization}" in text

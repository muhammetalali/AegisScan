#!/usr/bin/env python3
"""Build exact production Kali providers and bind immutable runtime trust into production.env."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RUNNER_VERSION = "0.1.0"

SCRIPT_DIR = Path(__file__).resolve().parent
PLATFORM_DIR = SCRIPT_DIR.parent
REPO_ROOT = PLATFORM_DIR.parent

PROFILE_TARGETS = {
    "recon": "profile-recon",
    "network": "profile-network",
    "web": "profile-web",
    "code": "profile-code",
}

PROVIDER_SPECS = {
    "RECON": {
        "profile": "recon",
        "dockerfile": None,
        "base_arg": None,
        "service_tag": "recon",
    },
    "NETWORK": {
        "profile": "network",
        "dockerfile": "Dockerfile.network-provider",
        "base_arg": "AEGIS_NETWORK_BASE_IMAGE",
        "service_tag": "network-provider",
    },
    "MASSCAN": {
        "profile": "network",
        "dockerfile": "Dockerfile.masscan-provider",
        "base_arg": "AEGIS_MASSCAN_BASE_IMAGE",
        "service_tag": "masscan-provider",
    },
    "WEB": {
        "profile": "web",
        "dockerfile": "Dockerfile.web-provider",
        "base_arg": "AEGIS_WEB_BASE_IMAGE",
        "service_tag": "web-provider",
    },
    "CODE": {
        "profile": "code",
        "dockerfile": "Dockerfile.code-provider",
        "base_arg": "AEGIS_CODE_BASE_IMAGE",
        "service_tag": "code-provider",
    },
}

POLICY_DEFAULTS = {
    "AEGIS_RECON_PROVIDER": "default-kali",
    "AEGIS_RECON_LEGACY_DISABLED": "true",
    "AEGIS_KALI_RECON_CANARY_BPS": "0",
    "AEGIS_KALI_RECON_URL": "http://127.0.0.1:18765",
    "AEGIS_NMAP_PROVIDER": "default-kali",
    "AEGIS_NMAP_LEGACY_DISABLED": "true",
    "AEGIS_KALI_NMAP_CANARY_BPS": "0",
    "AEGIS_KALI_NETWORK_URL": "http://127.0.0.1:18766",
    "AEGIS_MASSCAN_PROVIDER": "default-kali",
    "AEGIS_MASSCAN_LEGACY_DISABLED": "true",
    "AEGIS_KALI_MASSCAN_CANARY_BPS": "0",
    "AEGIS_KALI_MASSCAN_URL": "http://127.0.0.1:18767",
    "AEGIS_NUCLEI_PROVIDER": "default-kali",
    "AEGIS_NUCLEI_LEGACY_DISABLED": "true",
    "AEGIS_KALI_NUCLEI_CANARY_BPS": "0",
    "AEGIS_KALI_WEB_URL": "http://127.0.0.1:18770",
    "AEGIS_SEMGREP_PROVIDER": "default-kali",
    "AEGIS_SEMGREP_LEGACY_DISABLED": "true",
    "AEGIS_KALI_SEMGREP_CANARY_BPS": "0",
    "AEGIS_KALI_CODE_URL": "http://127.0.0.1:18771",
}

TOKEN_NAMES = (
    "AEGIS_KALI_RECON_AUTH_TOKEN",
    "AEGIS_KALI_NETWORK_AUTH_TOKEN",
    "AEGIS_KALI_MASSCAN_AUTH_TOKEN",
    "AEGIS_KALI_WEB_AUTH_TOKEN",
    "AEGIS_KALI_CODE_AUTH_TOKEN",
)


class TrustBootstrapError(RuntimeError):
    pass


def _run(
    argv: list[str],
    *,
    cwd: Path = REPO_ROOT,
    capture: bool = True,
    timeout: int = 7200,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        text=True,
        capture_output=capture,
        timeout=timeout,
    )


def _git(*args: str) -> str:
    return _run(
        ["git", "-c", f"safe.directory={REPO_ROOT}", *args],
        timeout=600,
    ).stdout.strip()


def _require_private_env(path: Path) -> os.stat_result:
    if not path.is_file():
        raise TrustBootstrapError(f"production env file does not exist: {path}")
    state = path.stat()
    mode = stat.S_IMODE(state.st_mode)
    if mode & 0o077:
        raise TrustBootstrapError(f"production env file must be mode 0600 or stricter: {path}")
    if state.st_size <= 0 or state.st_size > 1024 * 1024:
        raise TrustBootstrapError("production env file has invalid size")
    return state


def _load_env(path: Path) -> dict[str, str]:
    _require_private_env(path)
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise TrustBootstrapError(f"invalid production env assignment at line {line_number}")
        name, value = line.split("=", 1)
        name = name.strip()
        if not ENV_KEY_RE.fullmatch(name):
            raise TrustBootstrapError(f"invalid production env key at line {line_number}: {name!r}")
        value = value.strip()
        if value and value[0] in {'"', "'"}:
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                raise TrustBootstrapError(f"unterminated quoted env value at line {line_number}")
            value = value[1:-1]
        if any(ch in value for ch in "\r\n\x00"):
            raise TrustBootstrapError(f"control character in production env line {line_number}")
        values[name] = value
    return values


def _write_env(path: Path, values: dict[str, str], owner: tuple[int, int]) -> None:
    for name, value in values.items():
        if not ENV_KEY_RE.fullmatch(name):
            raise TrustBootstrapError(f"invalid env key: {name!r}")
        if any(ch in value for ch in "\r\n\x00"):
            raise TrustBootstrapError(f"control character in env value: {name}")

    payload = "\n".join(
        [
            "# Generated/updated by AegisScan production bootstrap. Keep mode 0600.",
            *(f"{name}={values[name]}" for name in sorted(values)),
            "",
        ]
    ).encode("utf-8")

    temporary = path.with_name(f".{path.name}.trust-{os.getpid()}")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        os.chown(path, owner[0], owner[1])
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_release(release_sha: str) -> tuple[str, str]:
    if not SHA_RE.fullmatch(release_sha):
        raise TrustBootstrapError("release SHA must be exactly 40 lowercase hexadecimal characters")
    current = _git("rev-parse", "HEAD")
    if current != release_sha:
        raise TrustBootstrapError(
            f"production checkout does not match requested release: current={current} requested={release_sha}"
        )
    dirty = _git("status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise TrustBootstrapError("production checkout has tracked local modifications")
    epoch = _git("log", "-1", "--pretty=%ct", release_sha)
    if not epoch.isdigit() or int(epoch) <= 0:
        raise TrustBootstrapError("release commit timestamp is invalid")
    return current, epoch


def _build_images(release_sha: str, source_date_epoch: str) -> dict[str, str]:
    short = release_sha[:12]
    base_tag = f"aegis-kali-production:base-{short}"

    _run(
        [
            "docker",
            "build",
            "--pull",
            "--no-cache",
            "--build-arg",
            f"BUILD_COMMIT={release_sha}",
            "--build-arg",
            f"AEGIS_RUNNER_VERSION={RUNNER_VERSION}",
            "--build-arg",
            f"SOURCE_DATE_EPOCH={source_date_epoch}",
            "-t",
            base_tag,
            "-f",
            str(PLATFORM_DIR / "kali" / "Dockerfile.base"),
            str(PLATFORM_DIR / "kali"),
        ],
        capture=False,
    )

    profile_tags: dict[str, str] = {}
    for profile, target in PROFILE_TARGETS.items():
        tag = f"aegis-kali-production:profile-{profile}-{short}"
        _run(
            [
                "docker",
                "build",
                "--no-cache",
                "--build-arg",
                f"AEGIS_BASE_IMAGE={base_tag}",
                "--build-arg",
                f"SOURCE_DATE_EPOCH={source_date_epoch}",
                "--target",
                target,
                "-t",
                tag,
                "-f",
                str(PLATFORM_DIR / "kali" / "Dockerfile.profiles"),
                str(REPO_ROOT),
            ],
            capture=False,
        )
        profile_tags[profile] = tag

    final_tags: dict[str, str] = {}
    for prefix, spec in PROVIDER_SPECS.items():
        profile_tag = profile_tags[str(spec["profile"])]
        dockerfile = spec["dockerfile"]
        if dockerfile is None:
            final_tags[prefix] = profile_tag
            continue

        tag = f"aegis-kali-production:{spec['service_tag']}-{short}"
        _run(
            [
                "docker",
                "build",
                "--no-cache",
                "--build-arg",
                f"{spec['base_arg']}={profile_tag}",
                "-t",
                tag,
                "-f",
                str(PLATFORM_DIR / "kali" / str(dockerfile)),
                str(PLATFORM_DIR / "kali"),
            ],
            capture=False,
        )
        final_tags[prefix] = tag

    return final_tags


def _image_id(tag: str) -> str:
    image_id = _run(
        ["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
        timeout=120,
    ).stdout.strip()
    if not SHA256_RE.fullmatch(image_id):
        raise TrustBootstrapError(f"unexpected Docker image ID for {tag}: {image_id!r}")
    return image_id


def _manifest(image_id: str, release_sha: str) -> tuple[dict[str, object], bytes]:
    raw_text = _run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "cat",
            image_id,
            "/opt/aegis-runner/runtime-manifest.json",
        ],
        timeout=120,
    ).stdout
    raw = raw_text.encode("utf-8")
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise TrustBootstrapError(f"runtime manifest is invalid JSON for {image_id}") from exc
    if not isinstance(payload, dict):
        raise TrustBootstrapError("runtime manifest must be a JSON object")
    if payload.get("build_commit") != release_sha:
        raise TrustBootstrapError(
            f"runtime manifest build_commit does not match release SHA for {image_id}"
        )
    if payload.get("runner_version") != RUNNER_VERSION:
        raise TrustBootstrapError(f"unexpected runner version for {image_id}")
    for field in ("base_image_digest", "tool_manifest_digest"):
        if not SHA256_RE.fullmatch(str(payload.get(field, ""))):
            raise TrustBootstrapError(f"runtime manifest field {field} is not an immutable sha256 digest")
    return payload, raw


def _trust_values(prefix: str, image_id: str, manifest: dict[str, object], raw: bytes) -> dict[str, str]:
    root = f"AEGIS_KALI_{prefix}"
    return {
        f"{root}_IMAGE": image_id,
        f"{root}_EXPECTED_RUNNER_VERSION": str(manifest["runner_version"]),
        f"{root}_EXPECTED_BUILD_COMMIT": str(manifest["build_commit"]),
        f"{root}_EXPECTED_BASE_IMAGE_DIGEST": str(manifest["base_image_digest"]),
        f"{root}_EXPECTED_TOOL_MANIFEST_DIGEST": str(manifest["tool_manifest_digest"]),
        f"{root}_EXPECTED_IMAGE_DIGEST": image_id,
        f"{root}_EXPECTED_RUNTIME_MANIFEST_DIGEST": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }


def _ensure_tokens(values: dict[str, str]) -> None:
    for name in TOKEN_NAMES:
        existing = values.get(name, "").strip()
        if existing:
            if not TOKEN_RE.fullmatch(existing):
                raise TrustBootstrapError(f"{name} exists but is not a 64-character lowercase hex token")
            continue
        values[name] = secrets.token_hex(32)


def bootstrap(env_file: Path, release_sha: str) -> dict[str, object]:
    if os.geteuid() != 0:
        raise TrustBootstrapError("production execution trust bootstrap must run as root")

    state = _require_private_env(env_file)
    _current, epoch = _validate_release(release_sha)
    values = _load_env(env_file)
    _ensure_tokens(values)
    values.update(POLICY_DEFAULTS)

    final_tags = _build_images(release_sha, epoch)
    image_results: dict[str, str] = {}
    for prefix, tag in final_tags.items():
        image_id = _image_id(tag)
        manifest, raw = _manifest(image_id, release_sha)
        values.update(_trust_values(prefix, image_id, manifest, raw))
        image_results[prefix.lower()] = image_id

    _write_env(env_file, values, (state.st_uid, state.st_gid))

    return {
        "schema": "aegisscan.production-execution-trust-bootstrap.v1",
        "status": "success",
        "release_sha": release_sha,
        "env_file": str(env_file),
        "images": dict(sorted(image_results.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=Path("/etc/aegisscan/production.env"))
    parser.add_argument("--release-sha", required=True)
    args = parser.parse_args()
    try:
        result = bootstrap(args.env_file.resolve(), args.release_sha.strip())
    except (
        TrustBootstrapError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        OSError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema": "aegisscan.production-execution-trust-bootstrap.v1",
                    "status": "failed",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 18769
MAX_BODY_BYTES = 16 * 1024
CAPABILITY_ID = "code.semgrep"
SCHEMA_VERSION = 1
DEFAULT_SOURCE_ROOT = "/workspace/source"
DEFAULT_RULE_PATH = "/opt/aegis-parity-rules/semgrep-parity.yml"
SEMGREP_PATH = "/opt/aegis-code-tools/bin/semgrep"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}$")


class RequestError(ValueError):
    pass


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RequestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_sha256(root: Path) -> str:
    if not root.is_dir() or root.is_symlink():
        raise SystemExit("Semgrep parity source root must be a regular directory")
    digest = hashlib.sha256()
    files = sorted(
        (path for path in root.rglob("*") if path.is_file() or path.is_symlink()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    if not files:
        raise SystemExit("Semgrep parity source root cannot be empty")
    for path in files:
        if path.is_symlink():
            raise SystemExit("Semgrep parity source tree cannot contain symlinks")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _read_proc_status() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key] = value.strip()
    return result


@dataclass(frozen=True)
class Config:
    auth_token: str
    authorization_ref: str
    scope_ref: str
    source_ref: str
    source_root: Path
    source_sha256: str
    rule_path: Path
    rule_sha256: str
    semgrep_path: str = SEMGREP_PATH


def load_config() -> Config:
    auth_token = os.environ.get("AEGIS_KALI_SEMGREP_PARITY_AUTH_TOKEN", "").strip()
    authorization_ref = os.environ.get("AEGIS_KALI_SEMGREP_EXPECTED_AUTHORIZATION_REF", "").strip()
    scope_ref = os.environ.get("AEGIS_KALI_SEMGREP_EXPECTED_SCOPE_REF", "").strip()
    source_ref = os.environ.get("AEGIS_KALI_SEMGREP_EXPECTED_SOURCE_REF", "").strip()
    source_root = Path(
        os.environ.get("AEGIS_KALI_SEMGREP_SOURCE_ROOT", DEFAULT_SOURCE_ROOT)
    )
    source_sha256 = os.environ.get("AEGIS_KALI_SEMGREP_SOURCE_SHA256", "").strip().lower()
    rule_path = Path(
        os.environ.get("AEGIS_KALI_SEMGREP_RULE_PATH", DEFAULT_RULE_PATH)
    )
    rule_sha256 = os.environ.get("AEGIS_KALI_SEMGREP_RULE_SHA256", "").strip().lower()

    if len(auth_token) < 32:
        raise SystemExit("Semgrep parity auth token must contain at least 32 characters")
    for label, value in (
        ("authorization reference", authorization_ref),
        ("scope reference", scope_ref),
        ("source reference", source_ref),
    ):
        if not _REF_RE.fullmatch(value):
            raise SystemExit(f"Invalid expected {label}")
    if not _HEX64_RE.fullmatch(source_sha256):
        raise SystemExit("Expected source digest must be a lowercase SHA-256")
    if not _HEX64_RE.fullmatch(rule_sha256):
        raise SystemExit("Expected rule digest must be a lowercase SHA-256")
    if not source_root.is_absolute():
        raise SystemExit("Semgrep parity source root must be absolute")
    if _tree_sha256(source_root) != source_sha256:
        raise SystemExit("Semgrep parity source-tree digest mismatch")
    if not rule_path.is_absolute() or not rule_path.is_file() or rule_path.is_symlink():
        raise SystemExit("Semgrep parity rule must be an existing absolute regular file")
    if _file_sha256(rule_path) != rule_sha256:
        raise SystemExit("Semgrep parity rule digest mismatch")
    semgrep = Path(SEMGREP_PATH)
    if not semgrep.is_file():
        raise SystemExit("Semgrep executable is missing from the governed code profile")

    return Config(
        auth_token=auth_token,
        authorization_ref=authorization_ref,
        scope_ref=scope_ref,
        source_ref=source_ref,
        source_root=source_root,
        source_sha256=source_sha256,
        rule_path=rule_path,
        rule_sha256=rule_sha256,
    )


def validate_payload(payload: Any, config: Config) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RequestError("request body must be a JSON object")
    allowed = {
        "schema_version",
        "execution_ref",
        "authorization_ref",
        "scope_ref",
        "capability_id",
        "source_ref",
        "timeout_seconds",
    }
    unknown = sorted(set(payload) - allowed)
    missing = sorted(allowed - set(payload))
    if unknown:
        raise RequestError(f"unknown request fields: {','.join(unknown)}")
    if missing:
        raise RequestError(f"missing request fields: {','.join(missing)}")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise RequestError("unsupported schema_version")
    if payload["capability_id"] != CAPABILITY_ID:
        raise RequestError("capability_id must be code.semgrep")
    execution_ref = str(payload["execution_ref"]).strip()
    if not _REF_RE.fullmatch(execution_ref):
        raise RequestError("invalid execution_ref")
    if payload["authorization_ref"] != config.authorization_ref:
        raise RequestError("authorization_ref does not match bound execution")
    if payload["scope_ref"] != config.scope_ref:
        raise RequestError("scope_ref does not match bound execution")
    if payload["source_ref"] != config.source_ref:
        raise RequestError("source_ref does not match bound execution")
    timeout = payload["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 900:
        raise RequestError("timeout_seconds must be an integer between 1 and 900")
    return {
        "execution_ref": execution_ref,
        "timeout_seconds": timeout,
    }


def _runtime_identity(config: Config) -> dict[str, Any]:
    status = _read_proc_status()
    uid_fields = status.get("Uid", "").split()
    uid = int(uid_fields[0]) if uid_fields else -1
    cap_eff = status.get("CapEff", "").lower()
    no_new_privs = status.get("NoNewPrivs", "")
    if uid == 0:
        raise SystemExit("Governed Semgrep parity service must run as non-root")
    if cap_eff != "0000000000000000":
        raise SystemExit(
            "Governed Semgrep parity service must have zero effective capabilities: "
            + cap_eff
        )
    if no_new_privs != "1":
        raise SystemExit("Governed Semgrep parity service requires no_new_privs")

    version = subprocess.run(
        [config.semgrep_path, "--version"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        shell=False,
        env={
            "PATH": "/opt/aegis-code-tools/bin:/usr/local/bin:/usr/bin:/bin",
            "SEMGREP_SEND_METRICS": "off",
        },
    )
    version_text = (version.stdout + version.stderr).strip()
    if version.returncode != 0 or "1.177.0" not in version_text:
        raise SystemExit(f"Unexpected Semgrep runtime version: {version_text}")

    return {
        "profile": "code",
        "tool": "semgrep",
        "tool_version": "1.177.0",
        "linux_privilege": {
            "uid": uid,
            "effective": cap_eff,
            "allowed_capabilities": [],
            "no_new_privs": True,
        },
        "source_sha256": config.source_sha256,
        "rule_sha256": config.rule_sha256,
        "binding": {
            "authorization_ref": config.authorization_ref,
            "scope_ref": config.scope_ref,
            "source_ref": config.source_ref,
        },
    }


def execute(config: Config, validated: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-semgrep-", dir="/tmp") as temp_dir:
        home = Path(temp_dir) / "home"
        config_dir = Path(temp_dir) / "config"
        cache_dir = Path(temp_dir) / "cache"
        home.mkdir()
        config_dir.mkdir()
        cache_dir.mkdir()
        env = {
            "PATH": "/opt/aegis-code-tools/bin:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config_dir),
            "XDG_CACHE_HOME": str(cache_dir),
            "TMPDIR": temp_dir,
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
        argv = [
            config.semgrep_path,
            "--config",
            str(config.rule_path),
            "--json",
            "--error",
            "--no-git-ignore",
            str(config.source_root),
        ]
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=validated["timeout_seconds"],
                check=False,
                shell=False,
                env=env,
                cwd=temp_dir,
            )
        except subprocess.TimeoutExpired as exc:
            raise RequestError("Semgrep parity execution timed out") from exc

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "completed" if completed.returncode in {0, 1} else "failed",
        "execution_ref": validated["execution_ref"],
        "capability_id": CAPABILITY_ID,
        "source_ref": config.source_ref,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "semantic_intent": {
            "output_format": "json",
            "error_on_findings": True,
            "git_ignore_disabled": True,
            "source_sha256": config.source_sha256,
            "rule_sha256": config.rule_sha256,
        },
        "runtime": runtime,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AegisSemgrepParity/1"

    @property
    def config(self) -> Config:
        return self.server.config  # type: ignore[attr-defined]

    @property
    def runtime(self) -> dict[str, Any]:
        return self.server.runtime  # type: ignore[attr-defined]

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self._json(404, {"error": "not found"})
            return
        self._json(200, {"status": "ok", "runtime": self.runtime})

    def do_POST(self) -> None:
        if self.path != "/v1/execute":
            self._json(404, {"error": "not found"})
            return
        supplied = self.headers.get("X-Aegis-Semgrep-Parity-Token", "")
        if not hmac.compare_digest(supplied, self.config.auth_token):
            self._json(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "invalid content length"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(413, {"error": "request body size rejected"})
            return
        try:
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object_pairs)
            validated = validate_payload(payload, self.config)
            result = execute(self.config, validated, self.runtime)
        except (UnicodeDecodeError, json.JSONDecodeError, RequestError) as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(200, result)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    if os.environ.get("AEGIS_KALI_SEMGREP_PARITY_MODE", "").strip().lower() not in {
        "1",
        "true",
        "yes",
    }:
        raise SystemExit("Semgrep parity service requires explicit parity mode")
    config = load_config()
    runtime = _runtime_identity(config)
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.config = config  # type: ignore[attr-defined]
    server.runtime = runtime  # type: ignore[attr-defined]
    print(
        json.dumps(
            {
                "event": "aegis_semgrep_parity_ready",
                "host": LISTEN_HOST,
                "port": LISTEN_PORT,
                "source_sha256": config.source_sha256,
                "rule_sha256": config.rule_sha256,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

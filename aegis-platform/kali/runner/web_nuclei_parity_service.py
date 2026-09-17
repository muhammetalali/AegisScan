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
from urllib.parse import urlsplit

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 18768
MAX_BODY_BYTES = 16 * 1024
CAPABILITY_ID = "web.nuclei"
SCHEMA_VERSION = 1
DEFAULT_TEMPLATE_PATH = "/opt/aegis-parity-templates/nuclei-parity.yaml"
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    target: str
    template_path: Path
    template_sha256: str
    nuclei_path: str = "/usr/local/bin/nuclei"


def load_config() -> Config:
    auth_token = os.environ.get("AEGIS_KALI_NUCLEI_PARITY_AUTH_TOKEN", "").strip()
    authorization_ref = os.environ.get("AEGIS_KALI_NUCLEI_EXPECTED_AUTHORIZATION_REF", "").strip()
    scope_ref = os.environ.get("AEGIS_KALI_NUCLEI_EXPECTED_SCOPE_REF", "").strip()
    target = os.environ.get("AEGIS_KALI_NUCLEI_EXPECTED_TARGET", "").strip()
    template_path = Path(
        os.environ.get("AEGIS_KALI_NUCLEI_TEMPLATE_PATH", DEFAULT_TEMPLATE_PATH)
    )
    template_sha256 = os.environ.get("AEGIS_KALI_NUCLEI_TEMPLATE_SHA256", "").strip().lower()

    if len(auth_token) < 32:
        raise SystemExit("Nuclei parity auth token must contain at least 32 characters")
    if not _REF_RE.fullmatch(authorization_ref):
        raise SystemExit("Invalid expected authorization reference")
    if not _REF_RE.fullmatch(scope_ref):
        raise SystemExit("Invalid expected scope reference")
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit("Expected Nuclei target must be an http/https URL")
    if parsed.username is not None or parsed.password is not None:
        raise SystemExit("Expected Nuclei target cannot contain userinfo")
    if any(char in target for char in "\r\n\x00"):
        raise SystemExit("Expected Nuclei target contains control characters")
    if not _HEX64_RE.fullmatch(template_sha256):
        raise SystemExit("Expected Nuclei template digest must be a lowercase SHA-256")
    if not template_path.is_absolute() or not template_path.is_file() or template_path.is_symlink():
        raise SystemExit("Nuclei parity template must be an existing absolute regular file")
    if _sha256(template_path) != template_sha256:
        raise SystemExit("Nuclei parity template digest mismatch")
    nuclei = Path("/usr/local/bin/nuclei")
    if not nuclei.is_file():
        raise SystemExit("Nuclei executable is missing from the governed web profile")

    return Config(
        auth_token=auth_token,
        authorization_ref=authorization_ref,
        scope_ref=scope_ref,
        target=target,
        template_path=template_path,
        template_sha256=template_sha256,
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
        "target",
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
        raise RequestError("capability_id must be web.nuclei")
    execution_ref = str(payload["execution_ref"]).strip()
    if not _REF_RE.fullmatch(execution_ref):
        raise RequestError("invalid execution_ref")
    if payload["authorization_ref"] != config.authorization_ref:
        raise RequestError("authorization_ref does not match bound execution")
    if payload["scope_ref"] != config.scope_ref:
        raise RequestError("scope_ref does not match bound execution")
    if payload["target"] != config.target:
        raise RequestError("target does not match bound execution")
    timeout = payload["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
        raise RequestError("timeout_seconds must be an integer between 1 and 600")
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
        raise SystemExit("Governed Nuclei parity service must run as non-root")
    if cap_eff != "0000000000000000":
        raise SystemExit(f"Governed Nuclei parity service must have zero effective capabilities: {cap_eff}")
    if no_new_privs != "1":
        raise SystemExit("Governed Nuclei parity service requires no_new_privs")

    version = subprocess.run(
        [config.nuclei_path, "-version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    version_text = (version.stdout + version.stderr).strip()
    if version.returncode != 0 or "3.11.1" not in version_text:
        raise SystemExit(f"Unexpected Nuclei runtime version: {version_text}")

    return {
        "profile": "web",
        "tool": "nuclei",
        "tool_version": "3.11.1",
        "linux_privilege": {
            "uid": uid,
            "effective": cap_eff,
            "allowed_capabilities": [],
            "no_new_privs": True,
        },
        "template_sha256": config.template_sha256,
        "binding": {
            "authorization_ref": config.authorization_ref,
            "scope_ref": config.scope_ref,
            "target": config.target,
        },
    }


def execute(config: Config, validated: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-nuclei-", dir="/tmp") as temp_dir:
        home = Path(temp_dir) / "home"
        config_dir = Path(temp_dir) / "config"
        cache_dir = Path(temp_dir) / "cache"
        home.mkdir()
        config_dir.mkdir()
        cache_dir.mkdir()
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config_dir),
            "XDG_CACHE_HOME": str(cache_dir),
            "TMPDIR": temp_dir,
        }
        argv = [
            config.nuclei_path,
            "-u",
            config.target,
            "-t",
            str(config.template_path),
            "-jsonl",
            "-silent",
            "-no-color",
            "-dr",
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
            raise RequestError("Nuclei parity execution timed out") from exc

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "completed" if completed.returncode == 0 else "failed",
        "execution_ref": validated["execution_ref"],
        "capability_id": CAPABILITY_ID,
        "target": config.target,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "semantic_intent": {
            "output_format": "jsonl",
            "redirects_disabled": True,
            "template_sha256": config.template_sha256,
        },
        "runtime": runtime,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AegisNucleiParity/1"

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
        supplied = self.headers.get("X-Aegis-Nuclei-Parity-Token", "")
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
    if os.environ.get("AEGIS_KALI_NUCLEI_PARITY_MODE", "").strip().lower() not in {"1", "true", "yes"}:
        raise SystemExit("Nuclei parity service requires explicit parity mode")
    config = load_config()
    runtime = _runtime_identity(config)
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.config = config  # type: ignore[attr-defined]
    server.runtime = runtime  # type: ignore[attr-defined]
    print(
        json.dumps(
            {
                "event": "aegis_nuclei_parity_ready",
                "host": LISTEN_HOST,
                "port": LISTEN_PORT,
                "template_sha256": config.template_sha256,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

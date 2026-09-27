#!/usr/bin/env python3
"""Close AegisScan external provider acceptance from exact-SHA live evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "aegisscan.external-provider-acceptance-closure.v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

CLOUD_WORKFLOW = (
    "Cloud Live Provider Reality",
    ".github/workflows/cloud-live-provider-reality.yml",
)
IDENTITY_WORKFLOW = (
    "External Identity Live Provider Reality",
    ".github/workflows/external-identity-live-provider-reality.yml",
)


class ProviderClosureError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, label: str, *, max_bytes: int = 16 * 1024 * 1024) -> dict[str, Any]:
    if not path.is_file():
        raise ProviderClosureError(f"{label} is missing: {path}")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ProviderClosureError(f"{label} has invalid size")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderClosureError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ProviderClosureError(f"{label} must be a JSON object")
    return value


def _require_executed_step(run: dict[str, Any], step_name: str) -> None:
    jobs = run.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        raise ProviderClosureError(f"{run.get('name')} has no executed job evidence")
    matches: list[dict[str, Any]] = []
    for job in jobs:
        if not isinstance(job, dict):
            continue
        if (
            job.get("status") != "completed"
            or job.get("conclusion") != "success"
            or job.get("head_sha") != run.get("head_sha")
        ):
            continue
        for step in job.get("steps") or []:
            if isinstance(step, dict) and step.get("name") == step_name:
                matches.append(step)
    if len(matches) != 1:
        raise ProviderClosureError(
            f"{run.get('name')} must contain exactly one executed {step_name!r} step"
        )
    step = matches[0]
    if step.get("status") != "completed" or step.get("conclusion") != "success":
        raise ProviderClosureError(
            f"{run.get('name')} did not execute {step_name!r} successfully"
        )


def _verify_run(
    run: dict[str, Any],
    *,
    expected_name: str,
    expected_path: str,
    release_sha: str,
    repository: str,
    required_steps: tuple[str, ...],
) -> dict[str, Any]:
    repo = run.get("repository") or {}
    checks = {
        "name": run.get("name") == expected_name,
        "path": run.get("path") == expected_path,
        "status": run.get("status") == "completed",
        "conclusion": run.get("conclusion") == "success",
        "head_sha": run.get("head_sha") == release_sha,
        "head_branch": run.get("head_branch") == "main",
        "repository": isinstance(repo, dict) and repo.get("full_name") == repository,
        "event": run.get("event") in {"push", "workflow_dispatch"},
    }
    failures = [key for key, passed in checks.items() if not passed]
    if failures:
        raise ProviderClosureError(
            f"{expected_name} workflow metadata failed checks: {failures}"
        )
    run_id = run.get("id")
    attempt = run.get("run_attempt")
    if not isinstance(run_id, int) or run_id <= 0:
        raise ProviderClosureError(f"{expected_name} run id is invalid")
    if not isinstance(attempt, int) or attempt <= 0:
        raise ProviderClosureError(f"{expected_name} run attempt is invalid")
    for step_name in required_steps:
        _require_executed_step(run, step_name)
    return {
        "run_id": run_id,
        "run_attempt": attempt,
        "event": run.get("event"),
        "updated_at": run.get("updated_at"),
    }


def _cloud_proofs(root: Path, release_sha: str) -> dict[str, Any]:
    paths = sorted(path for path in root.rglob("*-proof.json") if path.is_file())
    if not paths:
        raise ProviderClosureError("cloud acceptance contains no live provider proof")
    providers: dict[str, dict[str, Any]] = {}
    digests: dict[str, str] = {}
    for path in paths:
        proof = _load_json(path, f"cloud proof {path.name}")
        if proof.get("schema") != "aegis.cloud-live-provider-proof.v1":
            raise ProviderClosureError(f"cloud proof schema mismatch: {path}")
        provider = str(proof.get("provider") or "").strip().lower()
        if provider not in {"aws", "azure", "gcp"}:
            raise ProviderClosureError(f"cloud proof provider is invalid: {provider!r}")
        if provider in providers:
            raise ProviderClosureError(f"duplicate cloud live proof for provider: {provider}")
        checks = {
            "source_sha": proof.get("source_sha") == release_sha,
            "identity_verified": proof.get("identity_verified") is True,
            "read_only": proof.get("read_only") is True,
            "ambient_credentials_used": proof.get("ambient_credentials_used") is False,
            "credential_source": proof.get("credential_source") == "vault-materialized-file",
            "result_sha256": bool(SHA256_RE.fullmatch(str(proof.get("result_sha256") or ""))),
            "target": bool(str(proof.get("target") or "").strip()),
        }
        failures = [key for key, passed in checks.items() if not passed]
        if failures:
            raise ProviderClosureError(
                f"cloud {provider} proof failed checks: {failures}"
            )
        providers[provider] = {
            "target": str(proof["target"]),
            "finding_count": int(proof.get("finding_count") or 0),
            "coverage_gap_count": int(proof.get("coverage_gap_count") or 0),
            "result_sha256": str(proof["result_sha256"]),
        }
        digests[path.name] = _sha256_file(path)
    return {
        "providers": providers,
        "artifact_sha256": digests,
    }


def _identity_proof(root: Path, release_sha: str) -> dict[str, Any]:
    candidates = [
        path
        for path in root.rglob("proof.json")
        if path.is_file()
    ]
    if len(candidates) != 1:
        raise ProviderClosureError(
            f"external identity acceptance must contain exactly one proof.json; found {len(candidates)}"
        )
    path = candidates[0]
    proof = _load_json(path, "external identity proof")
    configured = proof.get("configured_types")
    if (
        proof.get("schema") != "aegis.external-identity-live-proof.v1"
        or proof.get("status") != "success"
        or proof.get("source_sha") != release_sha
        or proof.get("read_only") is not True
        or proof.get("ambient_credentials_used") is not False
        or not isinstance(configured, list)
        or not configured
    ):
        raise ProviderClosureError("external identity proof failed authoritative checks")
    normalized = sorted({str(value).strip().lower() for value in configured})
    if not set(normalized) <= {"oidc", "saml", "scim"}:
        raise ProviderClosureError("external identity proof contains an unsupported provider type")
    if len(normalized) != len(configured):
        raise ProviderClosureError("external identity proof configured types are duplicated or malformed")
    for provider_type in normalized:
        detail = proof.get(provider_type)
        if not isinstance(detail, dict) or not detail:
            raise ProviderClosureError(
                f"external identity proof is missing evidence for configured type: {provider_type}"
            )
    return {
        "configured_types": normalized,
        "completed_at": proof.get("completed_at"),
        "artifact_sha256": _sha256_file(path),
    }


def build_closure(
    *,
    release_sha: str,
    repository: str,
    cloud_run_metadata: Path,
    identity_run_metadata: Path,
    cloud_evidence_root: Path,
    identity_evidence_root: Path,
    output: Path,
) -> dict[str, Any]:
    release_sha = release_sha.strip().lower()
    if not SHA_RE.fullmatch(release_sha):
        raise ProviderClosureError("release SHA must be exactly 40 lowercase hexadecimal characters")
    repository = repository.strip()
    if repository != "muhammetalali/AegisScan":
        raise ProviderClosureError("external provider closure is bound to the canonical AegisScan repository")

    cloud_run = _load_json(cloud_run_metadata, "cloud workflow metadata")
    identity_run = _load_json(identity_run_metadata, "identity workflow metadata")
    cloud_run_summary = _verify_run(
        cloud_run,
        expected_name=CLOUD_WORKFLOW[0],
        expected_path=CLOUD_WORKFLOW[1],
        release_sha=release_sha,
        repository=repository,
        required_steps=(
            "Require at least one complete live-provider binding",
            "Wait for exact-SHA Required CI Governance",
            "Execute and validate configured live providers",
            "Prove artifacts contain no raw credential material",
        ),
    )
    identity_run_summary = _verify_run(
        identity_run,
        expected_name=IDENTITY_WORKFLOW[0],
        expected_path=IDENTITY_WORKFLOW[1],
        release_sha=release_sha,
        repository=repository,
        required_steps=(
            "Require at least one complete external identity binding",
            "Wait for exact-SHA Required CI Governance",
            "Execute real read-only external identity validation",
            "Prove secret-safe immutable identity evidence",
        ),
    )

    cloud = _cloud_proofs(cloud_evidence_root, release_sha)
    identity = _identity_proof(identity_evidence_root, release_sha)

    closure: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "success",
        "decision": "ACCEPTED",
        "repository": repository,
        "release_sha": release_sha,
        "cloud": cloud,
        "external_identity": identity,
        "workflow_runs": {
            CLOUD_WORKFLOW[0]: cloud_run_summary,
            IDENTITY_WORKFLOW[0]: identity_run_summary,
        },
        "controls": {
            "exact_sha": True,
            "real_cloud_provider_execution": True,
            "cloud_credentials_secret_safe": True,
            "cloud_read_only": True,
            "real_external_identity_execution": True,
            "external_identity_secret_safe": True,
            "external_identity_read_only": True,
        },
    }
    digest_payload = dict(closure)
    closure["closure_sha256"] = hashlib.sha256(_canonical(digest_payload)).hexdigest()

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(closure, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return closure


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--cloud-run-metadata", type=Path, required=True)
    parser.add_argument("--identity-run-metadata", type=Path, required=True)
    parser.add_argument("--cloud-evidence-root", type=Path, required=True)
    parser.add_argument("--identity-evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        result = build_closure(
            release_sha=args.release_sha,
            repository=args.repository,
            cloud_run_metadata=args.cloud_run_metadata,
            identity_run_metadata=args.identity_run_metadata,
            cloud_evidence_root=args.cloud_evidence_root,
            identity_evidence_root=args.identity_evidence_root,
            output=args.output,
        )
    except ProviderClosureError as exc:
        print(f"EXTERNAL_PROVIDER_CLOSURE_FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

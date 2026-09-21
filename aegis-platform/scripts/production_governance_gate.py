#!/usr/bin/env python3
"""Fail-closed final production governance decision from internal AegisScan evidence."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_RUNS = {
    "live_deploy": {
        "path": ".github/workflows/production-live-deploy.yml",
        "events": ("push", "workflow_dispatch"),
    },
    "resilience": {
        "path": ".github/workflows/production-resilience-acceptance.yml",
        "events": ("workflow_run", "workflow_dispatch"),
    },
    "supply_chain": {
        "path": ".github/workflows/supply-chain-release.yml",
        "events": ("push",),
    },
}
COMPONENTS = ("django", "fastapi", "frontend")
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
IPV6_ULA = ipaddress.ip_network("fc00::/7")


class GovernanceError(RuntimeError):
    pass


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise GovernanceError(f"{label} does not exist: {path}")
    if path.stat().st_size <= 0 or path.stat().st_size > 128 * 1024 * 1024:
        raise GovernanceError(f"{label} has invalid size: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GovernanceError(f"{label} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise GovernanceError(f"{label} must contain a JSON object")
    return payload


def _unique(root: Path, name: str, label: str) -> Path:
    matches = [path for path in root.rglob(name) if path.is_file()]
    if len(matches) != 1:
        raise GovernanceError(f"{label} must contain exactly one {name}; found {len(matches)}")
    return matches[0]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_enterprise_private(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return any(address in network for network in RFC1918_NETWORKS)
    return address in IPV6_ULA


def _private_address_evidence(values: Any, label: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise GovernanceError(f"{label} is missing private address evidence")
    normalized = [str(value).strip() for value in values]
    if any(not _is_enterprise_private(value) for value in normalized):
        raise GovernanceError(f"{label} contains an address outside RFC1918/IPv6-ULA")
    return normalized


def _verify_digest_manifest(root: Path, manifest: dict[str, Any], label: str) -> None:
    digests = manifest.get("sha256")
    if not isinstance(digests, dict) or not digests:
        raise GovernanceError(f"{label} is missing SHA-256 evidence map")
    for name, expected in digests.items():
        if not isinstance(name, str) or "/" in name or "\\" in name or name in {"", ".", ".."}:
            raise GovernanceError(f"{label} contains unsafe evidence filename")
        if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
            raise GovernanceError(f"{label} contains invalid SHA-256 for {name}")
        evidence = _unique(root, name, label)
        actual = _sha256(evidence)
        if actual != expected:
            raise GovernanceError(f"{label} evidence digest mismatch for {name}: {actual} != {expected}")


def _verify_run_metadata(path: Path, kind: str, release_sha: str) -> dict[str, Any]:
    payload = _load_json(path, f"{kind} run metadata")
    expected = EXPECTED_RUNS[kind]
    if payload.get("conclusion") != "success" or payload.get("status") != "completed":
        raise GovernanceError(f"{kind} workflow run is not completed successfully")
    if payload.get("head_sha") != release_sha:
        raise GovernanceError(f"{kind} workflow run is not bound to release SHA")
    if payload.get("path") != expected["path"]:
        raise GovernanceError(f"{kind} workflow path mismatch: {payload.get('path')!r}")
    if payload.get("event") not in expected["events"]:
        raise GovernanceError(
            f"{kind} workflow trigger mismatch: {payload.get('event')!r}; "
            f"expected one of {expected['events']!r}"
        )
    run_id = payload.get("id")
    if not isinstance(run_id, int) or run_id <= 0:
        raise GovernanceError(f"{kind} workflow run id is invalid")
    return payload


def _verify_internal_acceptance(payload: dict[str, Any], internal_origin: str, label: str) -> dict[str, Any]:
    checks = payload.get("checks")
    tls = checks.get("tls") if isinstance(checks, dict) else None
    ca = payload.get("enterprise_ca")
    addresses = payload.get("resolved_addresses")
    addresses_after = payload.get("resolved_addresses_after")
    if (
        payload.get("schema") != "aegisscan.internal-production-acceptance.v1"
        or payload.get("status") != "success"
        or payload.get("deployment_mode") != "internal"
        or payload.get("network_scope") != "rfc1918-or-ipv6-ula"
        or payload.get("origin") != internal_origin
        or not isinstance(ca, dict)
        or not SHA256_RE.fullmatch(str(ca.get("sha256", "")))
        or not isinstance(checks, dict)
        or checks.get("verified_https") is not True
        or checks.get("internal_only_resolution") is not True
        or checks.get("enterprise_ca_verified") is not True
        or checks.get("health_200") is not True
        or checks.get("ready_200") is not True
        or checks.get("frontend_200") is not True
        or not isinstance(tls, dict)
        or not SHA256_RE.fullmatch(str(tls.get("certificate_sha256", "")))
        or not str(tls.get("version", "")).startswith("TLS")
    ):
        raise GovernanceError(f"{label} internal HTTPS acceptance evidence is incomplete")
    _private_address_evidence(addresses, f"{label} initial resolution")
    _private_address_evidence(addresses_after, f"{label} final resolution")
    return payload


def _verify_go_live(root: Path, release_sha: str) -> dict[str, Any]:
    manifest_path = _unique(root, "manifest.json", "go-live evidence")
    manifest = _load_json(manifest_path, "go-live manifest")
    if manifest.get("schema") != "aegisscan.go-live-evidence.v3":
        raise GovernanceError("go-live manifest schema is invalid")
    if manifest.get("status") != "success" or manifest.get("deployment_mode") != "internal":
        raise GovernanceError("go-live manifest is not successful internal production evidence")
    if manifest.get("network_scope") != "rfc1918-or-ipv6-ula":
        raise GovernanceError("go-live manifest network scope is invalid")
    if manifest.get("release_sha") != release_sha:
        raise GovernanceError("go-live manifest release SHA mismatch")
    internal_origin = str(manifest.get("internal_origin", "")).strip()
    if not internal_origin.startswith("https://"):
        raise GovernanceError("go-live manifest does not contain an HTTPS internal origin")
    manifest_ca = str(manifest.get("enterprise_ca_sha256", ""))
    if not SHA256_RE.fullmatch(manifest_ca):
        raise GovernanceError("go-live manifest enterprise CA evidence is invalid")
    alertmanager_status = str(manifest.get("alertmanager_status", ""))
    backup_status = str(manifest.get("backup_status", ""))
    backup_id = str(manifest.get("backup_id", "")).strip()
    if alertmanager_status != "ready":
        raise GovernanceError("go-live manifest Alertmanager readiness evidence is invalid")
    if backup_status != "healthy" or not backup_id:
        raise GovernanceError("go-live manifest backup operational readiness evidence is invalid")
    _verify_digest_manifest(root, manifest, "go-live manifest")

    deploy = _load_json(_unique(root, "deploy.json", "go-live evidence"), "deploy evidence")
    if (
        deploy.get("schema") != "aegisscan.remote-production-deploy.v1"
        or deploy.get("status") != "success"
        or deploy.get("deployment_mode") != "internal"
        or deploy.get("network_scope") != "rfc1918-or-ipv6-ula"
        or deploy.get("release_sha") != release_sha
        or deploy.get("origin") != internal_origin
    ):
        raise GovernanceError("remote deployment evidence is not bound to the approved internal release/origin")
    _private_address_evidence(deploy.get("host_resolved_addresses"), "deployment SSH host")
    _private_address_evidence(deploy.get("origin_resolved_addresses"), "deployment origin")

    acceptance = _verify_internal_acceptance(
        _load_json(
            _unique(root, "internal-acceptance.json", "go-live evidence"),
            "internal acceptance evidence",
        ),
        internal_origin,
        "go-live",
    )
    if acceptance["enterprise_ca"]["sha256"] != manifest_ca:
        raise GovernanceError("go-live enterprise CA digest does not match internal acceptance")

    black_box = _unique(root, "internal-black-box.log", "go-live evidence")
    if black_box.stat().st_size <= 0:
        raise GovernanceError("internal black-box evidence is empty")
    black_box_text = black_box.read_text(encoding="utf-8", errors="replace")
    if "EXTERNAL_REAL_E2E=PASS" not in black_box_text:
        raise GovernanceError("internal black-box evidence does not contain the real E2E PASS marker")

    cli = _load_json(
        _unique(root, "cli-platform-status.json", "go-live evidence"),
        "CLI production evidence",
    )
    if not cli:
        raise GovernanceError("CLI production evidence is empty")

    return {
        "internal_origin": internal_origin,
        "enterprise_ca_sha256": manifest_ca,
        "manifest_sha256": _sha256(manifest_path),
        "tls_certificate_sha256": acceptance["checks"]["tls"]["certificate_sha256"],
        "alertmanager_status": alertmanager_status,
        "backup_status": backup_status,
        "backup_id": backup_id,
    }


def _verify_resilience(root: Path, release_sha: str) -> dict[str, Any]:
    manifest_path = _unique(root, "manifest.json", "resilience evidence")
    manifest = _load_json(manifest_path, "resilience manifest")
    if manifest.get("schema") != "aegisscan.production-resilience-evidence.v1":
        raise GovernanceError("resilience manifest schema is invalid")
    if manifest.get("status") != "success":
        raise GovernanceError("resilience manifest is not successful")
    if manifest.get("release_sha") != release_sha:
        raise GovernanceError("resilience manifest release SHA mismatch")
    for key in ("backup_id", "manifest_version_id", "object_version_id"):
        if not str(manifest.get(key, "")).strip():
            raise GovernanceError(f"resilience manifest is missing {key}")
    _verify_digest_manifest(root, manifest, "resilience manifest")

    backup = _load_json(
        _unique(root, "remote-backup.json", "resilience evidence"),
        "remote backup evidence",
    )
    if backup.get("schema") != "aegisscan.production-resilience-backup.v1" or backup.get("status") != "success":
        raise GovernanceError("remote production backup evidence is invalid")
    inner = backup.get("backup")
    if not isinstance(inner, dict):
        raise GovernanceError("remote production backup record is missing")
    if (
        inner.get("backup_id") != manifest["backup_id"]
        or inner.get("manifest_version_id") != manifest["manifest_version_id"]
        or inner.get("object_version_id") != manifest["object_version_id"]
    ):
        raise GovernanceError("resilience backup versions do not match the manifest")

    restore = _load_json(
        _unique(root, "remote-restore.json", "resilience evidence"),
        "remote restore evidence",
    )
    if (
        restore.get("status") != "restored-locally"
        or restore.get("backup_id") != manifest["backup_id"]
        or restore.get("manifest_version_id") != manifest["manifest_version_id"]
        or restore.get("object_version_id") != manifest["object_version_id"]
    ):
        raise GovernanceError("remote restore evidence does not match the committed backup")

    restore_text = _unique(root, "postgres-restore.txt", "resilience evidence").read_text(
        encoding="utf-8", errors="replace"
    )
    if "RESTORE_VERIFICATION=PASS" not in restore_text:
        raise GovernanceError("disposable PostgreSQL restore was not verified")

    alert = _load_json(
        _unique(root, "external-alert-delivery.json", "resilience evidence"),
        "external alert delivery evidence",
    )
    try:
        baseline = float(alert.get("baseline"))
        current = float(alert.get("current"))
        failed = float(alert.get("failed"))
    except (TypeError, ValueError) as exc:
        raise GovernanceError("external alert delivery counters are invalid") from exc
    if alert.get("status") != "success" or current <= baseline or failed != 0:
        raise GovernanceError("external alert delivery did not complete successfully")

    return {
        "backup_id": manifest["backup_id"],
        "manifest_version_id": manifest["manifest_version_id"],
        "object_version_id": manifest["object_version_id"],
        "manifest_sha256": _sha256(manifest_path),
    }


def _verify_supply_chain(root: Path, release_sha: str) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for component in COMPONENTS:
        provenance = _unique(root, f"{component}.provenance.json", "supply-chain evidence")
        sbom = _unique(root, f"{component}.cdx.json", "supply-chain evidence")
        predicate = _load_json(provenance, f"{component} provenance")
        config = predicate.get("invocation", {}).get("configSource", {})
        materials = predicate.get("materials")
        parameters = predicate.get("invocation", {}).get("parameters", {})
        if (
            config.get("digest") != {"sha1": release_sha}
            or config.get("entryPoint") != ".github/workflows/supply-chain-release.yml"
            or not isinstance(materials, list)
            or not materials
            or materials[0].get("digest") != {"sha1": release_sha}
            or not str(parameters.get("image", "")).endswith(f"/aegisscan-{component}")
        ):
            raise GovernanceError(f"{component} provenance is not bound to the approved release")
        sbom_payload = _load_json(sbom, f"{component} SBOM")
        if str(sbom_payload.get("bomFormat", "")).lower() != "cyclonedx":
            raise GovernanceError(f"{component} SBOM is not CycloneDX")
        evidence[component] = {
            "provenance_sha256": _sha256(provenance),
            "sbom_sha256": _sha256(sbom),
        }
    return evidence


def _verify_current_internal(path: Path, internal_origin: str, enterprise_ca_sha256: str) -> dict[str, Any]:
    payload = _verify_internal_acceptance(
        _load_json(path, "current internal acceptance"),
        internal_origin,
        "current",
    )
    if payload["enterprise_ca"]["sha256"] != enterprise_ca_sha256:
        raise GovernanceError("enterprise CA changed between go-live and final governance")
    return payload


def decide(
    *,
    release_sha: str,
    go_live_root: Path,
    resilience_root: Path,
    supply_chain_root: Path,
    live_run_metadata: Path,
    resilience_run_metadata: Path,
    supply_chain_run_metadata: Path,
    current_internal_acceptance: Path | None = None,
    current_public_acceptance: Path | None = None,
    output: Path,
) -> dict[str, Any]:
    if not SHA_RE.fullmatch(release_sha):
        raise GovernanceError("release SHA must be exactly 40 lowercase hexadecimal characters")
    current_path = current_internal_acceptance or current_public_acceptance
    if current_path is None:
        raise GovernanceError("current internal acceptance evidence is required")

    runs = {
        "live_deploy": _verify_run_metadata(live_run_metadata, "live_deploy", release_sha),
        "resilience": _verify_run_metadata(resilience_run_metadata, "resilience", release_sha),
        "supply_chain": _verify_run_metadata(supply_chain_run_metadata, "supply_chain", release_sha),
    }
    go_live = _verify_go_live(go_live_root, release_sha)
    resilience = _verify_resilience(resilience_root, release_sha)
    supply_chain = _verify_supply_chain(supply_chain_root, release_sha)
    current = _verify_current_internal(
        current_path,
        go_live["internal_origin"],
        go_live["enterprise_ca_sha256"],
    )

    decision = {
        "schema": "aegisscan.production-governance-decision.v2",
        "status": "success",
        "decision": "APPROVED",
        "deployment_mode": "internal",
        "network_scope": "rfc1918-or-ipv6-ula",
        "release_sha": release_sha,
        "internal_origin": go_live["internal_origin"],
        "decided_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "controls": {
            "exact_release_deployed": True,
            "internal_https_revalidated": True,
            "private_dns_perimeter": True,
            "enterprise_ca_verified": True,
            "internal_black_box_evidence": True,
            "remote_encrypted_backup": True,
            "version_pinned_restore": True,
            "disposable_database_restore": True,
            "external_alert_delivery": True,
            "supply_chain_provenance": True,
            "cyclonedx_sbom": True,
        },
        "evidence": {
            "go_live": go_live,
            "resilience": resilience,
            "supply_chain": supply_chain,
            "current_tls_certificate_sha256": current["checks"]["tls"]["certificate_sha256"],
            "current_enterprise_ca_sha256": current["enterprise_ca"]["sha256"],
            "workflow_runs": {
                key: {"id": payload["id"], "html_url": payload.get("html_url")}
                for key, payload in runs.items()
            },
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(decision, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return decision


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--go-live-root", type=Path, required=True)
    parser.add_argument("--resilience-root", type=Path, required=True)
    parser.add_argument("--supply-chain-root", type=Path, required=True)
    parser.add_argument("--live-run-metadata", type=Path, required=True)
    parser.add_argument("--resilience-run-metadata", type=Path, required=True)
    parser.add_argument("--supply-chain-run-metadata", type=Path, required=True)
    parser.add_argument("--current-internal-acceptance", type=Path)
    parser.add_argument("--current-public-acceptance", dest="legacy_current_acceptance", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    current = args.current_internal_acceptance or args.legacy_current_acceptance
    if current is None:
        parser.error("--current-internal-acceptance is required")

    try:
        decision = decide(
            release_sha=args.release_sha,
            go_live_root=args.go_live_root.resolve(),
            resilience_root=args.resilience_root.resolve(),
            supply_chain_root=args.supply_chain_root.resolve(),
            live_run_metadata=args.live_run_metadata.resolve(),
            resilience_run_metadata=args.resilience_run_metadata.resolve(),
            supply_chain_run_metadata=args.supply_chain_run_metadata.resolve(),
            current_internal_acceptance=current.resolve(),
            output=args.output.resolve(),
        )
    except GovernanceError as exc:
        print(json.dumps({
            "schema": "aegisscan.production-governance-decision.v2",
            "status": "failed",
            "decision": "REJECTED",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1

    print(json.dumps(decision, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

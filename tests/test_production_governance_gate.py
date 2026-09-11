import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/production_governance_gate.py"
SPEC = importlib.util.spec_from_file_location("production_governance_gate", PATH)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

RELEASE = "a" * 40
ORIGIN = "https://security.example.com"


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_metadata(tmp_path: Path, kind: str, run_id: int) -> Path:
    expected = gate.EXPECTED_RUNS[kind]
    return _write_json(
        tmp_path / f"{kind}-run.json",
        {
            "id": run_id,
            "status": "completed",
            "conclusion": "success",
            "head_sha": RELEASE,
            "path": expected["path"],
            "event": expected["event"],
            "html_url": f"https://github.com/example/aegis/actions/runs/{run_id}",
        },
    )


def _go_live(tmp_path: Path) -> Path:
    root = tmp_path / "go-live" / "artifact"
    root.mkdir(parents=True)
    _write_json(
        root / "deploy.json",
        {
            "schema": "aegisscan.remote-production-deploy.v1",
            "status": "success",
            "release_sha": RELEASE,
            "origin": ORIGIN,
        },
    )
    _write_json(
        root / "public-acceptance.json",
        {
            "schema": "aegisscan.public-acceptance.v1",
            "status": "success",
            "origin": ORIGIN,
            "checks": {
                "verified_https": True,
                "health_200": True,
                "ready_200": True,
                "frontend_200": True,
                "tls": {
                    "version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "certificate_sha256": "b" * 64,
                    "not_after": "Dec 31 23:59:59 2026 GMT",
                },
            },
        },
    )
    (root / "external-black-box.log").write_text("external-black-box=PASS\n", encoding="utf-8")
    _write_json(root / "cli-platform-status.json", {"status": "ok"})

    evidence = ["deploy.json", "public-acceptance.json", "external-black-box.log", "cli-platform-status.json"]
    _write_json(
        root / "manifest.json",
        {
            "schema": "aegisscan.go-live-evidence.v1",
            "status": "success",
            "release_sha": RELEASE,
            "public_origin": ORIGIN,
            "sha256": {name: _sha(root / name) for name in evidence},
        },
    )
    return tmp_path / "go-live"


def _resilience(tmp_path: Path) -> Path:
    root = tmp_path / "resilience" / "artifact"
    root.mkdir(parents=True)
    backup_id = "backup-123"
    manifest_version = "manifest-version-1"
    object_version = "object-version-1"
    _write_json(
        root / "remote-backup.json",
        {
            "schema": "aegisscan.production-resilience-backup.v1",
            "status": "success",
            "backup": {
                "backup_id": backup_id,
                "manifest_version_id": manifest_version,
                "object_version_id": object_version,
                "source_sha256": "c" * 64,
            },
        },
    )
    _write_json(
        root / "remote-restore.json",
        {
            "status": "restored-locally",
            "backup_id": backup_id,
            "manifest_version_id": manifest_version,
            "object_version_id": object_version,
            "source_sha256": "c" * 64,
        },
    )
    (root / "postgres-restore.txt").write_text(
        "RESTORE_VERIFICATION=PASS database=aegis_restore_verify_test\n",
        encoding="utf-8",
    )
    _write_json(
        root / "external-alert-delivery.json",
        {"status": "success", "baseline": 0, "current": 1, "failed": 0},
    )
    (root / "alertmanager-metrics.txt").write_text(
        'alertmanager_notifications_total{integration="webhook"} 1\n',
        encoding="utf-8",
    )

    evidence = [
        "remote-backup.json",
        "remote-restore.json",
        "postgres-restore.txt",
        "external-alert-delivery.json",
        "alertmanager-metrics.txt",
    ]
    _write_json(
        root / "manifest.json",
        {
            "schema": "aegisscan.production-resilience-evidence.v1",
            "status": "success",
            "release_sha": RELEASE,
            "backup_id": backup_id,
            "manifest_version_id": manifest_version,
            "object_version_id": object_version,
            "sha256": {name: _sha(root / name) for name in evidence},
        },
    )
    return tmp_path / "resilience"


def _supply_chain(tmp_path: Path) -> Path:
    root = tmp_path / "supply-chain"
    for component in gate.COMPONENTS:
        artifact = root / f"supply-chain-{component}"
        _write_json(
            artifact / f"{component}.provenance.json",
            {
                "invocation": {
                    "configSource": {
                        "digest": {"sha1": RELEASE},
                        "entryPoint": ".github/workflows/supply-chain-release.yml",
                    },
                    "parameters": {
                        "image": f"ghcr.io/example/aegisscan-{component}",
                    },
                },
                "materials": [
                    {
                        "uri": "git+https://github.com/example/aegis",
                        "digest": {"sha1": RELEASE},
                    }
                ],
            },
        )
        _write_json(
            artifact / f"{component}.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [],
            },
        )
    return root


def _current_public(tmp_path: Path) -> Path:
    return _write_json(
        tmp_path / "current-public.json",
        {
            "schema": "aegisscan.public-acceptance.v1",
            "status": "success",
            "origin": ORIGIN,
            "checks": {
                "verified_https": True,
                "health_200": True,
                "ready_200": True,
                "frontend_200": True,
                "tls": {
                    "version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "certificate_sha256": "d" * 64,
                    "not_after": "Dec 31 23:59:59 2026 GMT",
                },
            },
        },
    )


def _inputs(tmp_path: Path) -> dict:
    return {
        "release_sha": RELEASE,
        "go_live_root": _go_live(tmp_path),
        "resilience_root": _resilience(tmp_path),
        "supply_chain_root": _supply_chain(tmp_path),
        "live_run_metadata": _run_metadata(tmp_path, "live_deploy", 101),
        "resilience_run_metadata": _run_metadata(tmp_path, "resilience", 102),
        "supply_chain_run_metadata": _run_metadata(tmp_path, "supply_chain", 103),
        "current_public_acceptance": _current_public(tmp_path),
        "output": tmp_path / "decision.json",
    }


def test_final_governance_approves_only_complete_bound_evidence(tmp_path: Path):
    decision = gate.decide(**_inputs(tmp_path))
    assert decision["status"] == "success"
    assert decision["decision"] == "APPROVED"
    assert decision["release_sha"] == RELEASE
    assert decision["public_origin"] == ORIGIN
    assert all(decision["controls"].values())
    assert (tmp_path / "decision.json").is_file()


def test_final_governance_rejects_tampered_go_live_evidence(tmp_path: Path):
    inputs = _inputs(tmp_path)
    log = next(inputs["go_live_root"].rglob("external-black-box.log"))
    log.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(gate.GovernanceError, match="digest mismatch"):
        gate.decide(**inputs)


def test_final_governance_rejects_mismatched_workflow_release(tmp_path: Path):
    inputs = _inputs(tmp_path)
    payload = json.loads(inputs["resilience_run_metadata"].read_text(encoding="utf-8"))
    payload["head_sha"] = "f" * 40
    _write_json(inputs["resilience_run_metadata"], payload)
    with pytest.raises(gate.GovernanceError, match="not bound to release SHA"):
        gate.decide(**inputs)


def test_final_governance_rejects_unverified_external_alert(tmp_path: Path):
    inputs = _inputs(tmp_path)
    alert = next(inputs["resilience_root"].rglob("external-alert-delivery.json"))
    _write_json(alert, {"status": "success", "baseline": 0, "current": 0, "failed": 1})
    manifest = next(inputs["resilience_root"].rglob("manifest.json"))
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["sha256"]["external-alert-delivery.json"] = _sha(alert)
    _write_json(manifest, payload)
    with pytest.raises(gate.GovernanceError, match="external alert delivery"):
        gate.decide(**inputs)


def test_final_governance_rejects_supply_chain_provenance_from_other_sha(tmp_path: Path):
    inputs = _inputs(tmp_path)
    provenance = next(inputs["supply_chain_root"].rglob("django.provenance.json"))
    payload = json.loads(provenance.read_text(encoding="utf-8"))
    payload["materials"][0]["digest"]["sha1"] = "e" * 40
    _write_json(provenance, payload)
    with pytest.raises(gate.GovernanceError, match="django provenance"):
        gate.decide(**inputs)

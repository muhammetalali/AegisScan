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
ORIGIN = "https://security.internal"
CA_SHA = "e" * 64


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
            "event": expected["events"][0],
            "html_url": f"https://github.com/example/aegis/actions/runs/{run_id}",
        },
    )


def _acceptance_payload(cert_sha: str = "b" * 64) -> dict:
    return {
        "schema": "aegisscan.internal-production-acceptance.v1",
        "status": "success",
        "deployment_mode": "internal",
        "network_scope": "rfc1918-or-ipv6-ula",
        "origin": ORIGIN,
        "resolved_addresses": ["10.20.30.20"],
        "resolved_addresses_after": ["10.20.30.20"],
        "enterprise_ca": {
            "path": "/etc/aegisscan/enterprise-ca.pem",
            "sha256": CA_SHA,
        },
        "checks": {
            "verified_https": True,
            "internal_only_resolution": True,
            "enterprise_ca_verified": True,
            "health_200": True,
            "ready_200": True,
            "frontend_200": True,
            "tls": {
                "version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "certificate_sha256": cert_sha,
                "not_after": "Dec 31 23:59:59 2026 GMT",
            },
        },
    }


def _go_live(tmp_path: Path) -> Path:
    root = tmp_path / "go-live" / "artifact"
    root.mkdir(parents=True)
    _write_json(
        root / "deploy.json",
        {
            "schema": "aegisscan.remote-production-deploy.v1",
            "status": "success",
            "deployment_mode": "internal",
            "network_scope": "rfc1918-or-ipv6-ula",
            "release_sha": RELEASE,
            "origin": ORIGIN,
            "host_resolved_addresses": ["10.20.30.10"],
            "origin_resolved_addresses": ["10.20.30.20"],
        },
    )
    _write_json(root / "internal-acceptance.json", _acceptance_payload())
    (root / "internal-black-box.log").write_text("EXTERNAL_REAL_E2E=PASS\n", encoding="utf-8")
    _write_json(root / "cli-platform-status.json", {"status": "ok"})

    evidence = ["deploy.json", "internal-acceptance.json", "internal-black-box.log", "cli-platform-status.json"]
    _write_json(
        root / "manifest.json",
        {
            "schema": "aegisscan.go-live-evidence.v3",
            "status": "success",
            "deployment_mode": "internal",
            "network_scope": "rfc1918-or-ipv6-ula",
            "release_sha": RELEASE,
            "internal_origin": ORIGIN,
            "enterprise_ca_sha256": CA_SHA,
            "alertmanager_status": "ready",
            "backup_status": "healthy",
            "backup_id": "go-live-backup-123",
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
                    "parameters": {"image": f"ghcr.io/example/aegisscan-{component}"},
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


def _current_internal(tmp_path: Path) -> Path:
    return _write_json(tmp_path / "current-internal.json", _acceptance_payload("d" * 64))


def _inputs(tmp_path: Path) -> dict:
    return {
        "release_sha": RELEASE,
        "go_live_root": _go_live(tmp_path),
        "resilience_root": _resilience(tmp_path),
        "supply_chain_root": _supply_chain(tmp_path),
        "live_run_metadata": _run_metadata(tmp_path, "live_deploy", 101),
        "resilience_run_metadata": _run_metadata(tmp_path, "resilience", 102),
        "supply_chain_run_metadata": _run_metadata(tmp_path, "supply_chain", 103),
        "current_internal_acceptance": _current_internal(tmp_path),
        "output": tmp_path / "decision.json",
    }


def test_final_governance_approves_only_complete_internal_bound_evidence(tmp_path: Path):
    decision = gate.decide(**_inputs(tmp_path))
    assert decision["schema"] == "aegisscan.production-governance-decision.v2"
    assert decision["status"] == "success"
    assert decision["decision"] == "APPROVED"
    assert decision["deployment_mode"] == "internal"
    assert decision["release_sha"] == RELEASE
    assert decision["internal_origin"] == ORIGIN
    assert decision["evidence"]["current_enterprise_ca_sha256"] == CA_SHA
    assert decision["evidence"]["go_live"]["alertmanager_status"] == "ready"
    assert decision["evidence"]["go_live"]["backup_status"] == "healthy"
    assert decision["evidence"]["go_live"]["backup_id"] == "go-live-backup-123"
    assert all(decision["controls"].values())
    assert (tmp_path / "decision.json").is_file()


def test_final_governance_rejects_tampered_go_live_evidence(tmp_path: Path):
    inputs = _inputs(tmp_path)
    log = next(inputs["go_live_root"].rglob("internal-black-box.log"))
    log.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(gate.GovernanceError, match="digest mismatch"):
        gate.decide(**inputs)


def test_final_governance_rejects_incomplete_go_live_operational_evidence(tmp_path: Path):
    inputs = _inputs(tmp_path)
    manifest = next(inputs["go_live_root"].rglob("manifest.json"))
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["backup_status"] = "degraded"
    _write_json(manifest, payload)
    with pytest.raises(gate.GovernanceError, match="backup operational readiness"):
        gate.decide(**inputs)


def test_final_governance_rejects_public_address_in_deployment_evidence(tmp_path: Path):
    inputs = _inputs(tmp_path)
    deploy = next(inputs["go_live_root"].rglob("deploy.json"))
    payload = json.loads(deploy.read_text(encoding="utf-8"))
    payload["origin_resolved_addresses"] = ["8.8.8.8"]
    _write_json(deploy, payload)
    manifest = next(inputs["go_live_root"].rglob("manifest.json"))
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_payload["sha256"]["deploy.json"] = _sha(deploy)
    _write_json(manifest, manifest_payload)
    with pytest.raises(gate.GovernanceError, match="outside RFC1918/IPv6-ULA"):
        gate.decide(**inputs)


def test_final_governance_rejects_enterprise_ca_drift(tmp_path: Path):
    inputs = _inputs(tmp_path)
    current = inputs["current_internal_acceptance"]
    payload = json.loads(current.read_text(encoding="utf-8"))
    payload["enterprise_ca"]["sha256"] = "f" * 64
    _write_json(current, payload)
    with pytest.raises(gate.GovernanceError, match="enterprise CA changed"):
        gate.decide(**inputs)


def test_final_governance_accepts_automated_release_chain_events(tmp_path: Path):
    inputs = _inputs(tmp_path)
    live = json.loads(inputs["live_run_metadata"].read_text(encoding="utf-8"))
    live["event"] = "push"
    _write_json(inputs["live_run_metadata"], live)
    resilience = json.loads(inputs["resilience_run_metadata"].read_text(encoding="utf-8"))
    resilience["event"] = "workflow_run"
    _write_json(inputs["resilience_run_metadata"], resilience)
    decision = gate.decide(**inputs)
    assert decision["decision"] == "APPROVED"


def test_final_governance_rejects_unapproved_workflow_trigger(tmp_path: Path):
    inputs = _inputs(tmp_path)
    live = json.loads(inputs["live_run_metadata"].read_text(encoding="utf-8"))
    live["event"] = "pull_request"
    _write_json(inputs["live_run_metadata"], live)
    with pytest.raises(gate.GovernanceError, match="workflow trigger mismatch"):
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

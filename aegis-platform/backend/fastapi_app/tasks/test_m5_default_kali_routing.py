from __future__ import annotations

from types import SimpleNamespace

from fastapi_app.services.native_tool_runtime import get_native_tool_spec
from fastapi_app.services.scanner_adapters import ScanResult
from fastapi_app.tasks import native_capabilities as native_task


def _scan(scan_id: str):
    return SimpleNamespace(id=scan_id, project_id="project-m5", asset_id="asset-m5")


def _authorization():
    return SimpleNamespace(id="authorization-m5")


def test_default_kali_executes_parity_approved_recon_through_provider(monkeypatch):
    monkeypatch.setenv("AEGIS_RECON_PROVIDER", "default-kali")
    monkeypatch.setenv("AEGIS_KALI_RECON_CANARY_BPS", "0")
    captured = {}

    monkeypatch.setattr(
        native_task,
        "run_native_tool",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("parity-approved default Kali execution reached legacy runtime")
        ),
    )

    def kali(**kwargs):
        captured.update(kwargs)
        return {
            "tool": "fierce",
            "target": "parity.test",
            "exit_code": 0,
            "stdout": "kali",
            "stderr": "",
            "runtime": {
                "provider": "aegis-kali-recon",
                "profile": "recon",
                "provenance_authority": "control-plane-deployment-pins",
            },
        }

    monkeypatch.setattr(native_task, "execute_kali_recon", kali)

    result, provenance = native_task._execute_runtime(
        capability_id="recon.fierce",
        target="parity.test",
        options={},
        scan=_scan("m5-approved"),
        authorization=_authorization(),
        spec=get_native_tool_spec("recon.fierce"),
        credential_materials=(),
    )

    assert result.stdout == "kali"
    assert captured["execution_ref"] == "m5-approved"
    assert captured["authorization_ref"] == "authorization-m5"
    assert captured["scope_ref"] == "project:project-m5:asset:asset-m5"
    assert provenance["provider"] == "aegis-kali-recon"
    assert provenance["routing_decision"]["selected_provider"] == "kali"
    assert provenance["routing_decision"]["reason"] == "default-kali-parity-approved"


def test_default_kali_keeps_unapproved_recon_on_legacy(monkeypatch):
    monkeypatch.setenv("AEGIS_RECON_PROVIDER", "default-kali")
    monkeypatch.setenv("AEGIS_KALI_RECON_CANARY_BPS", "0")
    calls = []

    def legacy(*args, **kwargs):
        calls.append((args, kwargs))
        return ScanResult(
            tool="subfinder",
            target="example.com",
            exit_code=0,
            stdout="legacy",
            stderr="",
        )

    monkeypatch.setattr(native_task, "run_native_tool", legacy)
    monkeypatch.setattr(
        native_task,
        "execute_kali_recon",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("unapproved Recon capability reached Kali provider")
        ),
    )

    result, provenance = native_task._execute_runtime(
        capability_id="recon.subfinder",
        target="example.com",
        options={},
        scan=_scan("m5-unapproved"),
        authorization=_authorization(),
        spec=get_native_tool_spec("recon.subfinder"),
        credential_materials=(),
    )

    assert result.stdout == "legacy"
    assert len(calls) == 1
    assert provenance["provider"] == "legacy-native-worker"
    assert provenance["routing_decision"]["selected_provider"] == "legacy"
    assert provenance["routing_decision"]["reason"] == "capability-not-parity-approved"

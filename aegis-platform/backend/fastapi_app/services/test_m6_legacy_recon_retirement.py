from __future__ import annotations

import pytest

from fastapi_app.services import kali_recon_provider as provider


@pytest.mark.parametrize(("mode", "bps"), (("legacy", "0"), ("canary", "0")))
def test_retirement_lock_rejects_every_legacy_recon_route(
    monkeypatch, mode, bps
):
    monkeypatch.setenv("AEGIS_RECON_LEGACY_DISABLED", "true")
    monkeypatch.setenv("AEGIS_RECON_PROVIDER", mode)
    monkeypatch.setenv("AEGIS_KALI_RECON_CANARY_BPS", bps)

    with pytest.raises(provider.KaliReconProviderError, match="Legacy Recon execution is retired"):
        provider.recon_provider_decision("recon.amass")


def test_retirement_lock_rejects_active_canary_holdback(monkeypatch):
    monkeypatch.setenv("AEGIS_RECON_LEGACY_DISABLED", "true")
    monkeypatch.setenv("AEGIS_RECON_PROVIDER", "canary")
    monkeypatch.setenv("AEGIS_KALI_RECON_CANARY_BPS", "2500")
    routing_key = next(
        f"retired-holdback-{index}"
        for index in range(100)
        if provider._routing_key_digest("recon.amass", f"retired-holdback-{index}")[1] >= 2500
    )

    with pytest.raises(provider.KaliReconProviderError, match="canary-holdback"):
        provider.recon_provider_decision("recon.amass", routing_key=routing_key)


@pytest.mark.parametrize(
    "capability",
    ("recon.amass", "recon.dnsenum", "recon.fierce", "recon.subfinder"),
)
def test_retirement_lock_routes_all_approved_recon_to_kali(monkeypatch, capability):
    monkeypatch.setenv("AEGIS_RECON_LEGACY_DISABLED", "true")
    monkeypatch.setenv("AEGIS_RECON_PROVIDER", "default-kali")
    monkeypatch.setenv("AEGIS_KALI_RECON_CANARY_BPS", "0")

    decision = provider.recon_provider_decision(capability)
    assert decision.selected_provider == "kali"
    assert decision.parity_approved is True
    assert decision.reason == "default-kali-parity-approved"


def test_retirement_lock_does_not_reclassify_non_recon_native_capabilities(monkeypatch):
    monkeypatch.setenv("AEGIS_RECON_LEGACY_DISABLED", "true")
    monkeypatch.setenv("AEGIS_RECON_PROVIDER", "default-kali")

    decision = provider.recon_provider_decision("web.httpx")
    assert decision.recon_capability is False
    assert decision.selected_provider == "legacy"
    assert decision.reason == "capability-not-kali-recon"


def test_retirement_lock_rejects_unadmitted_future_recon_namespace(monkeypatch):
    monkeypatch.setenv("AEGIS_RECON_LEGACY_DISABLED", "true")
    monkeypatch.setenv("AEGIS_RECON_PROVIDER", "default-kali")

    with pytest.raises(provider.KaliReconProviderError, match="unknown Recon capability"):
        provider.recon_provider_decision("recon.future-tool")

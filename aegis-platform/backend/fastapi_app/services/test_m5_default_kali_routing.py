from __future__ import annotations

from fastapi_app.services import kali_recon_provider as provider


def test_default_kali_routes_only_parity_approved_capabilities(monkeypatch):
    monkeypatch.setenv("AEGIS_RECON_PROVIDER", "default-kali")
    monkeypatch.setenv("AEGIS_KALI_RECON_CANARY_BPS", "0")

    for capability in ("recon.fierce", "recon.dnsenum"):
        approved = provider.recon_provider_decision(capability)
        assert approved.selected_provider == "kali"
        assert approved.recon_capability is True
        assert approved.parity_approved is True
        assert approved.canary_bps == 0
        assert approved.bucket is None
        assert approved.routing_key_digest == ""
        assert approved.reason == "default-kali-parity-approved"

    for capability in ("recon.amass", "recon.subfinder"):
        decision = provider.recon_provider_decision(capability)
        assert decision.selected_provider == "legacy"
        assert decision.recon_capability is True
        assert decision.parity_approved is False
        assert decision.canary_bps == 0
        assert decision.bucket is None
        assert decision.routing_key_digest == ""
        assert decision.reason == "capability-not-parity-approved"

    non_recon = provider.recon_provider_decision("web.httpx")
    assert non_recon.selected_provider == "legacy"
    assert non_recon.recon_capability is False
    assert non_recon.reason == "capability-not-kali-recon"


def test_default_kali_requires_no_canary_assignment_key(monkeypatch):
    monkeypatch.setenv("AEGIS_RECON_PROVIDER", "default-kali")
    monkeypatch.setenv("AEGIS_KALI_RECON_CANARY_BPS", "0")

    first = provider.recon_provider_decision("recon.fierce")
    second = provider.recon_provider_decision("recon.fierce", routing_key="ignored-for-default")
    dnsenum = provider.recon_provider_decision("recon.dnsenum", routing_key="ignored-for-default")

    assert first == second
    assert dnsenum.selected_provider == "kali"
    assert dnsenum.parity_approved is True
    assert provider.should_use_kali_recon("recon.fierce") is True
    assert provider.should_use_kali_recon("recon.dnsenum") is True
    assert provider.should_use_kali_recon("recon.subfinder") is False

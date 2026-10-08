"""Bounded, fail-closed temporary egress admission on the existing scanner sidecar."""
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "aegis-platform/docker/scanner-egress/control.py"
SPEC = importlib.util.spec_from_file_location("aegis_scanner_egress_lease_test", SOURCE)
assert SPEC and SPEC.loader
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


@pytest.fixture(autouse=True)
def isolated_leases(monkeypatch):
    control._LEASES.clear()
    control._LEASE_TARGETS.clear()
    statements = []
    monkeypatch.setattr(control, "_run_nft",
                        lambda statement, **kwargs: statements.append((statement, kwargs)))
    return statements


@pytest.mark.parametrize("address,set_name", [
    ("10.1.2.3", "leased_ipv4"), ("172.21.0.8", "leased_ipv4"),
    ("192.168.2.5", "leased_ipv4"), ("100.77.2.3", "leased_ipv4"),
    ("fd12::44", "leased_ipv6"),
])
def test_temporary_admission_accepts_exact_company_private_addresses(address, set_name):
    assert control._private_exact_address(address) == (address, set_name)


@pytest.mark.parametrize("address", [
    "1.1.1.1", "8.8.8.8", "10.0.0.0/8", "172.20.0.1/32",
    "::1", "127.0.0.1", "169.254.169.254", "0.0.0.0",
    "224.1.1.1", "2001:4860::8888", "fe80::1", "*.example.com",
    "192.0.2.2", "not-an-ip", "", "10.1.2.3\\nflush ruleset",
])
def test_temporary_admission_rejects_non_exact_or_untrusted_targets(address):
    with pytest.raises(ValueError):
        control._private_exact_address(address)


@pytest.mark.parametrize("ttl", [-10, 0, 14, 901, 10000, True, "100", None, 1.5])
def test_lease_ttl_is_bounded(ttl):
    with pytest.raises(ValueError):
        control._create_lease({"target": "172.21.0.8", "ttl_seconds": ttl})


def test_kernel_timed_lease_revocation_is_exact_and_idempotent(isolated_leases):
    result = control._create_lease({"target": "172.21.0.8", "ttl_seconds": 90})
    lease_id = result["lease_id"]
    assert result["status"] == "leased"
    assert len(lease_id) >= 32
    assert len(isolated_leases) == 1
    add, flags = isolated_leases[0]
    assert "leased_ipv4" in add and "172.21.0.8 timeout 90s" in add
    assert "dynamic_ipv4" not in add and flags["ignore_exists"] is False
    with pytest.raises(ValueError, match="active"):
        control._create_lease({"target": "172.21.0.8", "ttl_seconds": 90})
    with pytest.raises(ValueError, match="unknown"):
        control._revoke_lease({"lease_id": "bad-reference-with-32-characters-12345678"})
    assert len(isolated_leases) == 1
    removed = control._revoke_lease({"lease_id": lease_id})
    assert removed == {"status": "revoked", "target": "172.21.0.8"}
    assert len(isolated_leases) == 2
    remove, flags = isolated_leases[-1]
    assert "delete element" in remove and "leased_ipv4" in remove
    assert "dynamic_ipv4" not in remove and flags["ignore_exists"] is False
    assert control._revoke_lease({"lease_id": lease_id}) == {"status": "already_inactive"}
    assert len(isolated_leases) == 2


def test_expired_lease_never_revokes_a_new_lease_for_the_same_target(monkeypatch, isolated_leases):
    clock = [1000.0]
    monkeypatch.setattr(control, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    original = control._create_lease({"target": "10.1.2.3", "ttl_seconds": 15})
    clock[0] += 16
    replacement = control._create_lease({"target": "10.1.2.3", "ttl_seconds": 30})
    assert original["lease_id"] != replacement["lease_id"]
    before = len(isolated_leases)
    assert control._revoke_lease({"lease_id": original["lease_id"]}) == {
        "status": "already_inactive"
    }
    assert len(isolated_leases) == before
    assert control._LEASE_TARGETS["10.1.2.3"] == replacement["lease_id"]


def test_kernel_failure_does_not_materialize_lease(monkeypatch):
    def failure(*_args, **_kwargs):
        raise RuntimeError("simulated nft rejection")
    monkeypatch.setattr(control, "_run_nft", failure)
    with pytest.raises(RuntimeError, match="nft"):
        control._create_lease({"target": "172.21.0.8", "ttl_seconds": 45})
    assert control._LEASES == {} and control._LEASE_TARGETS == {}


def test_one_lease_per_address_and_bounded_capacity(monkeypatch):
    monkeypatch.setattr(control, "LEASE_CAPACITY", 1)
    control._create_lease({"target": "172.21.0.8", "ttl_seconds": 40})
    with pytest.raises(ValueError, match="capacity"):
        control._create_lease({"target": "172.21.0.9", "ttl_seconds": 40})


def _post(path, body, token):
    instance = control.Handler.__new__(control.Handler)
    instance.path = path
    instance.headers = {
        "Content-Length": str(len(body)),
        "X-Aegis-Egress-Token": token,
    }
    instance.rfile = io.BytesIO(body)
    responses = []
    instance._json = lambda status, payload: responses.append((status, payload))
    instance.do_POST()
    return responses[0]


def test_handler_denies_missing_auth_before_any_nft_changes(isolated_leases, monkeypatch):
    monkeypatch.setattr(control, "TOKEN", "expected-private-auth-token")
    request = json.dumps({"target": "172.21.0.8", "ttl_seconds": 45}).encode()
    assert _post("/v1/lease", request, "")[0] == 403
    assert _post("/v1/lease", request, "incorrect")[0] == 403
    assert _post("/v1/revoke", b'{"lease_id":"fake"}', "")[0] == 403
    assert _post("/v1/unknown", request, "expected-private-auth-token")[0] == 404
    assert isolated_leases == []


def test_handler_temporary_lease_http_lifecycle_and_existing_allow_unchanged(monkeypatch):
    monkeypatch.setattr(control, "TOKEN", "expected-private-auth-token")
    token = control.TOKEN
    create = json.dumps({"target": "172.21.0.8", "ttl_seconds": 45}).encode()
    code, lease = _post("/v1/lease", create, token)
    assert code == 200 and lease["status"] == "leased"
    code, revoked = _post("/v1/revoke", json.dumps({"lease_id": lease["lease_id"]}).encode(), token)
    assert code == 200 and revoked["status"] == "revoked"
    code, again = _post("/v1/revoke", json.dumps({"lease_id": lease["lease_id"]}).encode(), token)
    assert code == 200 and again["status"] == "already_inactive"
    code, existing = _post("/v1/allow", b'{"target":"172.21.0.11"}', token)
    assert code == 200 and existing == {"status": "ok", "target": "172.21.0.11"}


def test_kernel_timeout_sets_remain_separate_from_existing_persistent_sets():
    script = (ROOT / "aegis-platform/docker/scanner-egress/entrypoint.sh").read_text()
    assert "add set netdev $TABLE leased_ipv4 { type ipv4_addr; flags timeout; }" in script
    assert "add set netdev $TABLE leased_ipv6 { type ipv6_addr; flags timeout; }" in script
    assert "ip daddr @leased_ipv4 accept" in script
    assert "ip6 daddr @leased_ipv6 accept" in script
    assert "dynamic_ipv4" in script and "dynamic_ipv6" in script


def test_revocation_fails_closed_if_kernel_cannot_remove_element(monkeypatch):
    calls = []
    def nft(statement, **kwargs):
        calls.append(statement)
        if statement.startswith("delete element"):
            raise RuntimeError("simulated nft kernel failure")
    monkeypatch.setattr(control, "_run_nft", nft)
    lease_id = control._create_lease(
        {"target": "172.21.0.8", "ttl_seconds": 70}
    )["lease_id"]
    with pytest.raises(RuntimeError, match="kernel failure"):
        control._revoke_lease({"lease_id": lease_id})
    assert control._LEASES[lease_id]["active"]
    assert control._LEASE_TARGETS["172.21.0.8"] == lease_id
    assert len(calls) == 2


def test_retained_revoked_records_are_bounded(monkeypatch):
    monkeypatch.setattr(control, "LEASE_RECORD_CAPACITY", 1)
    lease_id = control._create_lease({
        "target": "172.21.0.8", "ttl_seconds": 45,
    })["lease_id"]
    control._revoke_lease({"lease_id": lease_id})
    with pytest.raises(ValueError, match="capacity"):
        control._create_lease({
            "target": "172.21.0.9", "ttl_seconds": 45,
        })


def test_kernel_timeout_race_requires_existing_lease_set(monkeypatch):
    """Do not mistake an absent firewall table for a harmless expired element."""
    nft_calls = []
    def nft(command, **_kwargs):
        nft_calls.append(command)
        if command.startswith("delete element"):
            raise RuntimeError("No such file or directory")
        if command.startswith("list set"):
            raise RuntimeError("No such file or directory")
    monkeypatch.setattr(control, "_run_nft", nft)
    lease_id = control._create_lease({
        "target": "172.21.0.8", "ttl_seconds": 80,
    })["lease_id"]
    with pytest.raises(RuntimeError, match="No such file"):
        control._revoke_lease({"lease_id": lease_id})
    assert control._LEASES[lease_id]["active"] is True
    assert len(nft_calls) == 3


def test_kernel_timeout_race_allows_already_expired_element_only_when_set_exists(monkeypatch):
    nft_calls = []
    def nft(command, **_kwargs):
        nft_calls.append(command)
        if command.startswith("delete element"):
            raise RuntimeError("No such file or directory")
    monkeypatch.setattr(control, "_run_nft", nft)
    lease_id = control._create_lease({
        "target": "172.21.0.8", "ttl_seconds": 80,
    })["lease_id"]
    assert control._revoke_lease({"lease_id": lease_id})["status"] == "revoked"
    assert any(cmd.startswith("list set") for cmd in nft_calls)

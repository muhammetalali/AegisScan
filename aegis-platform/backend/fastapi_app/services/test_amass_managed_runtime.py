from __future__ import annotations

import socket
from pathlib import Path

import pytest

from fastapi_app.services import amass_managed_runtime as amass


def _fake_amass(tmp_path: Path) -> str:
    script = tmp_path / "fake-amass"
    script.write_text(
        """#!/usr/bin/env python3
import socket
import sys
import time
from pathlib import Path

args = sys.argv[1:]
if args[0] == "engine":
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 4000))
    sock.listen(8)
    try:
        while True:
            time.sleep(1)
    finally:
        sock.close()
elif args[0] == "enum":
    assert args[args.index("-engine") + 1] == "http://127.0.0.1:4000"
    output = Path(args[args.index("-dir") + 1])
    output.mkdir(parents=True, exist_ok=True)
    (output / "asset.db").write_text("fixture", encoding="utf-8")
elif args[0] == "subs":
    output = Path(args[args.index("-dir") + 1])
    assert (output / "asset.db").is_file()
    print("www.parity.test")
    print("api.parity.test")
    print("mail.parity.test")
else:
    raise SystemExit(2)
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return str(script)


def test_managed_amass_owns_engine_collects_discovered_names_and_tears_down(tmp_path):
    binary = _fake_amass(tmp_path)
    code, stdout, stderr = amass.run_managed_amass(
        target="Parity.Test",
        timeout_minutes=1,
        amass_binary=binary,
        root_dir=str(tmp_path),
    )
    assert code == 0
    assert set(stdout.splitlines()) == {
        "www.parity.test",
        "api.parity.test",
        "mail.parity.test",
    }
    assert stderr == ""
    assert amass._listener_inodes() == set()
    assert not list(tmp_path.glob("aegis-amass-*"))


def test_managed_amass_rejects_preexisting_engine_listener(tmp_path):
    binary = _fake_amass(tmp_path)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 4000))
    listener.listen(1)
    try:
        with pytest.raises(amass.AmassRuntimeError, match="already occupied"):
            amass.run_managed_amass(
                target="parity.test",
                timeout_minutes=1,
                amass_binary=binary,
                root_dir=str(tmp_path),
            )
    finally:
        listener.close()


def test_managed_amass_child_environment_excludes_worker_secrets_and_proxy_state(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid")
    environment = amass._minimal_environment(tmp_path / "runtime")
    assert set(environment) == {
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "PATH",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
    }
    assert "DATABASE_URL" not in environment
    assert "HTTPS_PROXY" not in environment


@pytest.mark.parametrize("target", ("localhost", "-bad.example", "bad..example", "https://example.com"))
def test_managed_amass_rejects_noncanonical_domains(target):
    with pytest.raises(amass.AmassRuntimeError):
        amass._canonical_domain(target)


@pytest.mark.parametrize("value", (0, 31, True))
def test_managed_amass_rejects_out_of_bounds_timeout(value):
    with pytest.raises(amass.AmassRuntimeError):
        amass._bounded_timeout_minutes(value)

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]
DOCKERFILE = ROOT / "aegis-platform/kali/Dockerfile.base"


def test_kali_foundation_pins_direct_dependency_boundary() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "kalilinux/kali-rolling@sha256:" in text
    for pin in (
        "ca-certificates=20260601", "coreutils=9.10-1", "jq=1.8.2-1",
        "procps=2:4.0.6-3", "python3=3.14.7-3", "tini=0.19.0-6+b2",
    ):
        assert pin in text
    assert text.count("dpkg-query -W") >= 6


def test_kali_foundation_does_not_pin_transitive_dependency_graph() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    for package in (
        "libexpat1=", "libffi8=", "libjq1=", "libncursesw6=", "libonig5=",
        "libproc2-1=", "libpython3-stdlib=", "libpython3.14-minimal=",
        "libpython3.14-stdlib=", "libreadline8t64=", "libsqlite3-0=", "openssl=",
        "python3-minimal=", "python3.14=", "python3.14-minimal=", "readline-common=",
    ):
        assert package not in text

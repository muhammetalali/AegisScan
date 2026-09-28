from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]
DOCKERFILE = ROOT / "aegis-platform/kali/Dockerfile.base"


def test_kali_foundation_uses_snapshot_repository_for_exact_package_lock() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")

    assert "kalilinux/kali-rolling@sha256:" in text
    assert "Suites: kali-last-snapshot" in text
    assert " kali-last-snapshot " in text
    assert "apt-get update" in text
    assert "ca-certificates=20260601" in text
    assert "openssl=3.6.3-1" in text
    assert "procps=2:4.0.6-3" in text
    assert "python3=3.14.7-3" in text
    assert "tini=0.19.0-6+b2" in text
    assert "dpkg-query -W" in text


def test_kali_foundation_does_not_refresh_exact_pins_from_moving_rolling_metadata() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    source_freeze = text.index("kali-last-snapshot")
    apt_refresh = text.index("apt-get update")
    package_install = text.index("apt-get install")

    assert source_freeze < apt_refresh < package_install

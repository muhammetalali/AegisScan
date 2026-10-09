"""Non-network regression tests for the owner SSH maintenance reconnect helper."""
from pathlib import Path
import os
import shutil
import subprocess


SCRIPT = Path(__file__).resolve().parents[1] / "aegis-platform" / "scripts" / "owner_admin_reconnect.sh"


def test_script_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_requires_explicit_ssh_host_alias():
    for alias in ("-oProxyCommand=unsafe", "a;echo bad", "../host", ""):
        args = [alias] if alias else []
        result = subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=5)
        assert result.returncode == 2


def test_network_loss_reconnects_and_attaches_to_one_session(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "ssh_calls.txt"
    fake_ssh = bin_dir / "ssh"
    fake_ssh.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$CALLS_FILE\"\n"
        'n=$(wc -l < "$CALLS_FILE")\n'
        '[ "$n" -gt 1 ] && exit 0\n'
        "exit 255\n"
    )
    fake_ssh.chmod(0o755)
    fake_sleep = bin_dir / "sleep"
    fake_sleep.write_text("#!/bin/sh\nexit 0\n")
    fake_sleep.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + os.environ["PATH"]
    env["CALLS_FILE"] = str(calls)
    result = subprocess.run(
        ["bash", str(SCRIPT), "managed-lab-01"],
        env=env, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    lines = calls.read_text().splitlines()
    assert len(lines) == 2
    assert all("StrictHostKeyChecking=yes" in line for line in lines)
    assert all("tmux new-session -A -s aegis-owner-maintenance" in line for line in lines)
    assert "retrying" in result.stderr


def test_non_network_error_is_not_retried(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_ssh = bin_dir / "ssh"
    fake_ssh.write_text("#!/bin/sh\nexit 127\n")
    fake_ssh.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + os.environ["PATH"]
    result = subprocess.run(["bash", str(SCRIPT), "managed-lab-01"], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 127
    assert "not retrying" in result.stderr

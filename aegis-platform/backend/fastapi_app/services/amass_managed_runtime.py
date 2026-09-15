#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

AMASS_BINARY = "/usr/local/bin/amass"
ENGINE_PORT = 4000
ENGINE_URL = "http://127.0.0.1:4000"
MAX_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 256 * 1024
_ENGINE_START_TIMEOUT_SECONDS = 20.0
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SOCKET_RE = re.compile(r"^socket:\[(?P<inode>\d+)\]$")


class AmassRuntimeError(RuntimeError):
    pass


def _canonical_domain(value: str) -> str:
    target = str(value or "").strip().rstrip(".").lower()
    if not target or len(target) > 253 or any(ch in target for ch in "\r\n\x00"):
        raise AmassRuntimeError("Amass target must be a bounded DNS domain")
    labels = target.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise AmassRuntimeError("Amass target must be a canonical DNS domain")
    return target


def _bounded_timeout_minutes(value: int) -> int:
    try:
        minutes = int(value)
    except (TypeError, ValueError) as exc:
        raise AmassRuntimeError("Amass timeout_minutes must be an integer") from exc
    if minutes < 1 or minutes > 30:
        raise AmassRuntimeError("Amass timeout_minutes must be between 1 and 30")
    return minutes


def _minimal_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    cache = home / ".cache"
    config = home / ".config"
    tmp = root / "tmp"
    for path in (home, cache, config, tmp):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": str(tmp),
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
    }


def _listener_inodes(port: int = ENGINE_PORT) -> set[str]:
    wanted_port = f"{port:04X}"
    inodes: set[str] = set()
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = path.read_text(encoding="ascii", errors="strict").splitlines()[1:]
        except (OSError, UnicodeError):
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or ":" not in fields[1]:
                continue
            _, local_port = fields[1].rsplit(":", 1)
            if fields[3] == "0A" and local_port.upper() == wanted_port:
                inodes.add(fields[9])
    return inodes


def _process_socket_inodes(pid: int) -> set[str]:
    result: set[str] = set()
    try:
        entries = list(Path(f"/proc/{pid}/fd").iterdir())
    except OSError:
        return result
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        match = _SOCKET_RE.fullmatch(target)
        if match:
            result.add(match.group("inode"))
    return result


def _terminate_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    except ProcessLookupError:
        pass


def _read_tail(path: Path, limit: int = MAX_DIAGNOSTIC_BYTES) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > limit:
                handle.seek(size - limit)
            data = handle.read(limit)
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def _wait_for_owned_engine(process: subprocess.Popen[bytes], log_path: Path) -> None:
    deadline = time.monotonic() + _ENGINE_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        returncode = process.poll()
        if returncode is not None:
            diagnostic = _read_tail(log_path).strip()
            raise AmassRuntimeError(
                f"owned Amass engine exited before readiness (exit={returncode}): {diagnostic[:2000]}"
            )
        listeners = _listener_inodes()
        if listeners:
            if listeners & _process_socket_inodes(process.pid):
                return
            raise AmassRuntimeError("Amass engine port 4000 is owned by another process or container")
        time.sleep(0.05)
    raise AmassRuntimeError("owned Amass engine did not bind port 4000 before the startup deadline")


def _run_to_files(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
) -> int:
    with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
        process = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=stdout_handle,
            stderr=stderr_handle,
            cwd=str(cwd),
            env=env,
            shell=False,
            check=False,
        )
    return int(process.returncode)


def _read_capture(path: Path, *, label: str) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AmassRuntimeError(f"missing {label} output") from exc
    if size > MAX_CAPTURE_BYTES:
        raise AmassRuntimeError(f"{label} output exceeded the 2 MiB runtime limit")
    return path.read_text(encoding="utf-8", errors="replace")


def run_managed_amass(
    *,
    target: str,
    timeout_minutes: int,
    amass_binary: str = AMASS_BINARY,
    root_dir: str | None = None,
) -> tuple[int, str, str]:
    canonical_target = _canonical_domain(target)
    timeout = _bounded_timeout_minutes(timeout_minutes)
    binary = str(amass_binary)
    if not os.path.isabs(binary):
        raise AmassRuntimeError("Amass binary path must be absolute")
    if not Path(binary).is_file() or not os.access(binary, os.X_OK):
        raise AmassRuntimeError(f"Amass binary is unavailable or not executable: {binary}")
    if _listener_inodes():
        raise AmassRuntimeError("Amass engine port 4000 is already occupied before execution")

    managed_root = Path(
        tempfile.mkdtemp(prefix="aegis-amass-", dir=root_dir or os.environ.get("TMPDIR") or "/tmp")
    )
    os.chmod(managed_root, 0o700)
    output_dir = managed_root / "output"
    output_dir.mkdir(mode=0o700)
    env = _minimal_environment(managed_root)
    engine_log = managed_root / "engine.log"
    enum_stdout = managed_root / "enum.stdout"
    enum_stderr = managed_root / "enum.stderr"
    subs_stdout = managed_root / "subs.stdout"
    subs_stderr = managed_root / "subs.stderr"
    engine: subprocess.Popen[bytes] | None = None

    try:
        with engine_log.open("wb") as engine_handle:
            engine = subprocess.Popen(
                [binary, "engine"],
                stdin=subprocess.DEVNULL,
                stdout=engine_handle,
                stderr=subprocess.STDOUT,
                cwd=str(managed_root),
                env=env,
                shell=False,
            )
            _wait_for_owned_engine(engine, engine_log)

            enum_code = _run_to_files(
                [
                    binary, "enum", "-passive", "-d", canonical_target,
                    "-timeout", str(timeout), "-dir", str(output_dir),
                    "-engine", ENGINE_URL, "-nocolor", "-silent",
                ],
                cwd=managed_root,
                env=env,
                stdout_path=enum_stdout,
                stderr_path=enum_stderr,
            )
            if enum_code != 0:
                diagnostic = "\n".join(
                    part.strip()
                    for part in (_read_tail(enum_stderr), _read_tail(engine_log))
                    if part.strip()
                )
                return enum_code, "", diagnostic[:MAX_DIAGNOSTIC_BYTES]

            subs_code = _run_to_files(
                [
                    binary, "subs", "-dir", str(output_dir), "-d",
                    canonical_target, "-names", "-nocolor",
                ],
                cwd=managed_root,
                env=env,
                stdout_path=subs_stdout,
                stderr_path=subs_stderr,
            )
            stdout = _read_capture(subs_stdout, label="Amass discovered-name")
            stderr = _read_capture(subs_stderr, label="Amass discovered-name diagnostic")
            return subs_code, stdout, stderr[:MAX_DIAGNOSTIC_BYTES]
    finally:
        _terminate_process(engine)
        remaining = _listener_inodes()
        shutil.rmtree(managed_root, ignore_errors=True)
        if remaining and sys.exc_info()[0] is None:
            raise AmassRuntimeError("Amass engine listener remained after managed execution teardown")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--target", required=True)
    parser.add_argument("--timeout-minutes", required=True, type=int)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        code, stdout, stderr = run_managed_amass(
            target=args.target,
            timeout_minutes=args.timeout_minutes,
        )
    except AmassRuntimeError as exc:
        print(f"AEGIS_AMASS_RUNTIME_ERROR: {exc}", file=sys.stderr)
        return 70
    if stdout:
        sys.stdout.write(stdout)
        if not stdout.endswith("\n"):
            sys.stdout.write("\n")
    if stderr:
        sys.stderr.write(stderr)
        if not stderr.endswith("\n"):
            sys.stderr.write("\n")
    return int(code)


if __name__ == "__main__":
    raise SystemExit(main())

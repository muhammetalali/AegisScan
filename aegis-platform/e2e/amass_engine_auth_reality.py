#!/usr/bin/env python3
from __future__ import annotations

import os
import socket
import subprocess
import time
import urllib.error
import urllib.request

ENGINE_URL = "http://127.0.0.1:4000/api/v1/health"
HEADER = "X-Aegis-Amass-Token"
TOKEN = "a" * 64
WRONG = "b" * 64


def _status(token: str | None) -> int:
    headers = {HEADER: token} if token is not None else {}
    request = urllib.request.Request(ENGINE_URL, headers=headers, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=2) as response:
            response.read(4096)
            return int(response.status)
    except urllib.error.HTTPError as exc:
        exc.read(4096)
        return int(exc.code)


def _port_open() -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        return sock.connect_ex(("127.0.0.1", 4000)) == 0
    finally:
        sock.close()


def main() -> int:
    env = {
        "AEGIS_AMASS_ENGINE_TOKEN": TOKEN,
        "HOME": "/tmp/amass-auth-home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": "/tmp/amass-auth-home/.cache",
        "XDG_CONFIG_HOME": "/tmp/amass-auth-home/.config",
    }
    os.makedirs(env["XDG_CACHE_HOME"], mode=0o700, exist_ok=True)
    os.makedirs(env["XDG_CONFIG_HOME"], mode=0o700, exist_ok=True)
    process = subprocess.Popen(
        ["/usr/local/bin/amass", "engine", "-silent"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        cwd="/tmp",
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"Amass engine exited before auth probe: {process.returncode}")
            if _port_open():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Amass engine did not bind TCP/4000")

        observed = {
            "no_token": _status(None),
            "wrong_token": _status(WRONG),
            "correct_token": _status(TOKEN),
        }
        if observed != {"no_token": 401, "wrong_token": 401, "correct_token": 200}:
            raise RuntimeError(f"unexpected Amass engine auth boundary: {observed}")
        print("AEGIS_AMASS_ENGINE_AUTH_BOUNDARY_PROVEN")
        return 0
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _port_open():
            time.sleep(0.1)
        if _port_open():
            raise RuntimeError("Amass engine listener survived auth probe teardown")


if __name__ == "__main__":
    raise SystemExit(main())

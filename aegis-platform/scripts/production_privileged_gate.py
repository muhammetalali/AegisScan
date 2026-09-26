#!/usr/bin/env python3
"""Root-owned privileged boundary for AegisScan internal production deployment."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path("/opt/aegisscan/AegisScan")
ENV_FILE = Path("/etc/aegisscan/production.env")
ENTERPRISE_CA = Path("/etc/aegisscan/enterprise-ca.pem")
INSTALLED_GATE = Path("/usr/local/sbin/aegisscan-production-gate")
EXPECTED_REMOTE = "https://github.com/muhammetalali/AegisScan.git"
EXPECTED_SUDO_USER = "aegisdeploy"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
IPV6_ULA = ipaddress.ip_network("fc00::/7")
SECURE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class PrivilegedGateError(RuntimeError):
    pass


def _release_sha(value: str) -> str:
    release = value.strip()
    if not SHA_RE.fullmatch(release):
        raise PrivilegedGateError("release SHA must be exactly 40 lowercase hexadecimal characters")
    return release


def _is_private(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return any(address in network for network in RFC1918_NETWORKS)
    return address in IPV6_ULA


def _origin(value: str) -> str:
    parsed = urlparse(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise PrivilegedGateError("origin must be an explicit HTTPS origin")
    host = parsed.hostname.strip().lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.fullmatch(host) or host.startswith(".") or host.endswith(".") or ".." in host:
            raise PrivilegedGateError("origin hostname is invalid")
        url_host = host
    else:
        if not _is_private(address):
            raise PrivilegedGateError("origin literal must be inside the RFC1918/IPv6-ULA enterprise perimeter")
        url_host = f"[{host}]" if isinstance(address, ipaddress.IPv6Address) else host
    try:
        port = parsed.port
    except ValueError as exc:
        raise PrivilegedGateError("origin port is invalid") from exc
    port_part = f":{port}" if port and port != 443 else ""
    return f"https://{url_host}{port_part}"


def _metadata_ok(path: Path, *, require_root: bool = True, allow_public_read: bool = True) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise PrivilegedGateError(f"required production path is missing: {path}") from exc
    if require_root and info.st_uid != 0:
        raise PrivilegedGateError(f"production path must be owned by root: {path}")
    if path.is_symlink():
        return
    forbidden = stat.S_IWGRP | stat.S_IWOTH
    if info.st_mode & forbidden:
        raise PrivilegedGateError(f"production path must not be writable by group/others: {path}")
    if not allow_public_read and info.st_mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IXGRP | stat.S_IXOTH):
        raise PrivilegedGateError(f"private production path has excessive permissions: {path}")


def _assert_secure_tree() -> None:
    for parent in (Path("/opt"), Path("/opt/aegisscan"), REPO_ROOT):
        _metadata_ok(parent)
    _metadata_ok(REPO_ROOT / ".git")
    for root, dirs, files in os.walk(REPO_ROOT, followlinks=False):
        root_path = Path(root)
        _metadata_ok(root_path)
        for name in dirs:
            _metadata_ok(root_path / name)
        for name in files:
            _metadata_ok(root_path / name)


def _assert_private_material() -> None:
    _metadata_ok(Path("/etc/aegisscan"), allow_public_read=False)
    _metadata_ok(ENV_FILE, allow_public_read=False)
    if ENV_FILE.stat().st_size <= 0:
        raise PrivilegedGateError("production environment file is empty")
    _metadata_ok(ENTERPRISE_CA)
    if ENTERPRISE_CA.stat().st_size <= 0:
        raise PrivilegedGateError("enterprise CA bundle is empty")


def _assert_installed_gate() -> None:
    if Path(__file__).resolve() != INSTALLED_GATE:
        raise PrivilegedGateError(
            f"privileged gate must execute from the root-owned installed path: {INSTALLED_GATE}"
        )
    _metadata_ok(INSTALLED_GATE)


def _assert_invocation_identity() -> None:
    if os.geteuid() != 0:
        raise PrivilegedGateError("privileged gate must run as root")
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user and sudo_user != EXPECTED_SUDO_USER:
        raise PrivilegedGateError(f"privileged gate rejected sudo caller: {sudo_user}")
    if not sudo_user and os.getuid() != 0:
        raise PrivilegedGateError("privileged gate caller identity is unavailable")


def _environment() -> dict[str, str]:
    return {
        "PATH": SECURE_PATH,
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "AEGIS_ENTERPRISE_CA_BUNDLE": str(ENTERPRISE_CA),
        "REQUESTS_CA_BUNDLE": str(ENTERPRISE_CA),
        "SSL_CERT_FILE": str(ENTERPRISE_CA),
    }


def _run(
    argv: list[str],
    *,
    cwd: Path = REPO_ROOT,
    capture: bool = True,
    timeout: int = 3600,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            env=_environment(),
            text=True,
            capture_output=capture,
            check=True,
            timeout=timeout,
            input=input_text,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()[-4000:]
        suffix = f": {detail}" if detail else ""
        raise PrivilegedGateError(f"command failed with exit {exc.returncode}: {argv[0]}{suffix}") from exc
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise PrivilegedGateError(f"command failed: {argv[0]}: {exc}") from exc


def _git(*args: str, capture: bool = True, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "/usr/bin/git",
            "-c",
            f"safe.directory={REPO_ROOT}",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=never",
            *args,
        ],
        capture=capture,
        timeout=timeout,
    )


def _assert_expected_remote() -> None:
    remote = _git("remote", "get-url", "origin").stdout.strip()
    if remote != EXPECTED_REMOTE:
        raise PrivilegedGateError(f"production repository origin mismatch: {remote!r}")


def _prepare_release(release_sha: str) -> None:
    _assert_secure_tree()
    _assert_expected_remote()
    status = _git("status", "--porcelain", "--untracked-files=no").stdout.strip()
    if status:
        raise PrivilegedGateError("production checkout has tracked local modifications")
    _git("fetch", "--no-tags", "--prune", "origin", "main", capture=False)
    _git("cat-file", "-e", f"{release_sha}^{{commit}}")
    ancestor = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            f"safe.directory={REPO_ROOT}",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=never",
            "merge-base",
            "--is-ancestor",
            release_sha,
            "origin/main",
        ],
        cwd=REPO_ROOT,
        env=_environment(),
        text=True,
        capture_output=True,
        timeout=60,
    )
    if ancestor.returncode != 0:
        raise PrivilegedGateError("release SHA is not contained in origin/main")
    _assert_secure_tree()


def _python(script: str, *args: str, timeout: int) -> None:
    path = REPO_ROOT / "aegis-platform" / "scripts" / script
    _metadata_ok(path)
    _run(["/usr/bin/python3", str(path), *args], capture=False, timeout=timeout)


def _release_deployer(release_sha: str, origin: str) -> None:
    """Use the verified candidate orchestrator while backup still sees the old checkout."""
    relative = "aegis-platform/scripts/production_host_deploy.py"
    source = _git("show", f"{release_sha}:{relative}").stdout
    if not source.strip():
        raise PrivilegedGateError("candidate deployment orchestrator is empty")
    launcher = (
        "import sys; path=sys.argv.pop(1); source=sys.stdin.read(); sys.argv[0]=path; "
        "exec(compile(source,path,'exec'), {'__name__':'__main__','__file__':path})"
    )
    _run(
        ["/usr/bin/python3", "-c", launcher, str(REPO_ROOT / relative),
         "--release-sha", release_sha, "--env-file", str(ENV_FILE), "--origin", origin],
        input_text=source, capture=False, timeout=21600,
    )


def deploy(release_sha: str, origin: str) -> None:
    release_sha = _release_sha(release_sha)
    origin = _origin(origin)
    _assert_private_material()
    _prepare_release(release_sha)
    _python("production_host_reality.py", "--env-file", str(ENV_FILE), timeout=900)
    _release_deployer(release_sha, origin)
    _assert_secure_tree()


def accept(release_sha: str) -> None:
    release_sha = _release_sha(release_sha)
    _assert_private_material()
    _assert_secure_tree()
    current = _git("rev-parse", "HEAD").stdout.strip()
    if current != release_sha:
        raise PrivilegedGateError("production host checkout does not match the accepted release SHA")
    _python(
        "production_operational_acceptance.py",
        "--env-file",
        str(ENV_FILE),
        "--release-sha",
        release_sha,
        timeout=7200,
    )
    _assert_secure_tree()


def cleanup_e2e_scope(release_sha: str) -> None:
    release_sha = _release_sha(release_sha)
    _assert_private_material()
    _assert_secure_tree()
    current = _git("rev-parse", "HEAD").stdout.strip()
    if current != release_sha:
        raise PrivilegedGateError("production host checkout does not match the cleanup release SHA")
    _python(
        "production_operational_acceptance.py",
        "--env-file",
        str(ENV_FILE),
        "--release-sha",
        release_sha,
        "--cleanup-e2e-scope",
        timeout=1800,
    )
    _assert_secure_tree()


def resilience(release_sha: str, action: str, origin: str = "") -> None:
    release_sha = _release_sha(release_sha)
    if action not in {"backup", "recover-services"}:
        raise PrivilegedGateError("unsupported resilience action")
    _assert_private_material()
    _assert_secure_tree()
    _assert_expected_remote()
    if _git("status", "--porcelain", "--untracked-files=no").stdout.strip():
        raise PrivilegedGateError("production checkout has tracked local modifications")
    if _git("rev-parse", "HEAD").stdout.strip() != release_sha:
        raise PrivilegedGateError("production host checkout does not match the resilience release SHA")
    args = ["--release-sha", release_sha, "--env-file", str(ENV_FILE), "--action", action]
    if action == "recover-services":
        args += ["--origin", _origin(origin)]
    _python("production_host_resilience.py", *args, timeout=14400)
    _assert_secure_tree()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    deploy_parser = subparsers.add_parser("deploy")
    deploy_parser.add_argument("--release-sha", required=True)
    deploy_parser.add_argument("--origin", required=True)
    cleanup_parser = subparsers.add_parser("cleanup-e2e-scope")
    cleanup_parser.add_argument("--release-sha", required=True)

    accept_parser = subparsers.add_parser("accept")
    accept_parser.add_argument("--release-sha", required=True)
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("--release-sha", required=True)
    recovery_parser = subparsers.add_parser("recover-services")
    recovery_parser.add_argument("--release-sha", required=True)
    recovery_parser.add_argument("--origin", required=True)

    args = parser.parse_args()
    try:
        _assert_invocation_identity()
        _assert_installed_gate()
        if args.action == "deploy":
            deploy(args.release_sha, args.origin)
        elif args.action == "accept":
            accept(args.release_sha)
        elif args.action == "cleanup-e2e-scope":
            cleanup_e2e_scope(args.release_sha)
        elif args.action in {"backup", "recover-services"}:
            resilience(args.release_sha, args.action, getattr(args, "origin", ""))
        else:
            raise PrivilegedGateError(f"unsupported privileged action: {args.action}")
    except PrivilegedGateError as exc:
        print(
            json.dumps(
                {
                    "schema": "aegisscan.production-privileged-gate.v1",
                    "status": "failed",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {
                "schema": "aegisscan.production-privileged-gate.v1",
                "status": "success",
                "action": args.action,
                "release_sha": args.release_sha,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

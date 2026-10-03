#!/usr/bin/env python3
"""Run the isolated Web Labs P6 measured acceptance on an exact candidate SHA.

Host-only operator tool. It never talks to production services and refuses an
unsealed/dirty source checkout, mutable scanner image revision, or non-P6 DB.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

FIXTURE_IMAGE_ID = "sha256:51fc25f0244f9fb28ec13602d2902ea53b526414b89f3362aaf9f62c5f7541c7"
FIXTURE_REVISION = "b051e47ecb3b77c97a2b89b12cc7d98c0557ce9b330f63d301c2d70a81f21bc9"
SUPPORT_NETWORK = "aegis-burp-p2-packaging"
EGRESS = "aegis-burp-p2-egress"
POSTGRES = "aegis-burp-p3-postgres"
REDIS = "aegis-burp-p3-redis"
CONTROL = "aegis-burp-p6-control"
P6_DB = "burp_p6"
P6_REDIS_DB = "2"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class AcceptanceError(RuntimeError):
    pass


def run(args, *, check=True, input_text=None, stdout=None, stderr=None, timeout=180):
    result = subprocess.run(
        [str(x) for x in args],
        input=input_text,
        text=True,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=stderr if stderr is not None else subprocess.PIPE,
        timeout=timeout,
    )
    if check and result.returncode:
        detail = result.stderr or result.stdout or ""
        raise AcceptanceError(
            f"command failed ({result.returncode}): {' '.join(map(str, args))}: "
            f"{detail[-1600:]}"
        )
    return result


def output(args, *, timeout=180) -> str:
    return run(args, timeout=timeout).stdout.strip()


def docker_inspect(name: str) -> dict:
    value = json.loads(output(["docker", "inspect", name]))
    if not isinstance(value, list) or len(value) != 1:
        raise AcceptanceError(f"unexpected docker inspect result for {name}")
    return value[0]


def image_inspect(ref: str) -> dict:
    value = json.loads(output(["docker", "image", "inspect", ref]))
    if not isinstance(value, list) or len(value) != 1:
        raise AcceptanceError(f"unexpected image inspect result for {ref}")
    return value[0]


def remove_container(name: str) -> None:
    run(["docker", "rm", "-f", name], check=False)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def container_cgroup(name: str) -> Path:
    pid = int(docker_inspect(name)["State"]["Pid"])
    if pid <= 0:
        raise AcceptanceError(f"container {name} has no running PID")
    for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3 and fields[0] == "0":
            path = Path("/sys/fs/cgroup") / fields[2].lstrip("/")
            if path.is_dir():
                return path
    raise AcceptanceError(f"cannot resolve cgroup v2 path for {name}")


def cpu_usage_usec(cgroup: Path) -> int:
    for line in (cgroup / "cpu.stat").read_text().splitlines():
        key, value = line.split()
        if key == "usage_usec":
            return int(value)
    raise AcceptanceError(f"cpu usage missing in {cgroup}")


class ResourceMonitor:
    def __init__(self, containers: list[str]):
        self.cgroups = [container_cgroup(name) for name in containers]
        self.cpu_start = sum(cpu_usage_usec(path) for path in self.cgroups)
        self.peak = 0
        self.started = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self):
        while not self._stop.is_set():
            total = 0
            for path in self.cgroups:
                try:
                    total += int((path / "memory.current").read_text().strip())
                except (FileNotFoundError, ValueError):
                    pass
            self.peak = max(self.peak, total)
            self._stop.wait(0.1)

    def start(self):
        self._thread.start()

    def stop(self) -> dict:
        self._stop.set()
        self._thread.join(timeout=2)
        cpu_end = 0
        for path in self.cgroups:
            try:
                cpu_end += cpu_usage_usec(path)
            except FileNotFoundError:
                pass
        return {
            "duration_ms": round((time.monotonic() - self.started) * 1000, 3),
            "cpu_seconds": round(max(0, cpu_end - self.cpu_start) / 1_000_000, 6),
            "peak_memory_bytes": int(self.peak),
        }


def ensure_connected(container: str) -> None:
    record = docker_inspect(container)
    if SUPPORT_NETWORK not in record["NetworkSettings"]["Networks"]:
        run(["docker", "network", "connect", SUPPORT_NETWORK, container])


def ensure_egress_rule(container: str, port: int, label: str) -> None:
    rules = output(["docker", "exec", EGRESS, "nft", "-a", "list", "ruleset"])
    if label in rules:
        return
    record = docker_inspect(container)
    address = record["NetworkSettings"]["Networks"][SUPPORT_NETWORK]["IPAddress"]
    run(
        [
            "docker",
            "exec",
            EGRESS,
            "nft",
            "insert",
            "rule",
            "netdev",
            "aegis_egress",
            "egress",
            "ip",
            "daddr",
            address,
            "tcp",
            "dport",
            str(port),
            "counter",
            "accept",
            "comment",
            f'"{label}"',
        ]
    )


def load_env(path: Path, source_commit: str) -> dict[str, str]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise AcceptanceError("env template must be a JSON object")
    env = {str(k): str(v) for k, v in raw.items()}
    env.pop("AEGIS_ISOLATED_BURP_LAB_VERIFICATION_PROOF", None)
    env.update(
        DATABASE_URL=f"postgresql://preview:preview-test-only@{POSTGRES}:5432/{P6_DB}",
        REDIS_URL=f"redis://{REDIS}:6379/{P6_REDIS_DB}",
        CELERY_BROKER_URL=f"redis://{REDIS}:6379/{P6_REDIS_DB}",
        CELERY_RESULT_BACKEND=f"redis://{REDIS}:6379/{P6_REDIS_DB}",
        PYTHONPATH="/app",
        DJANGO_SETTINGS_MODULE="django_project.settings",
        AUTHORIZED_SCAN_TARGETS="127.0.0.1",
        AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF="1",
        AEGIS_PROOF_SOURCE_COMMIT=source_commit,
    )
    return env


def secure_base(env: dict[str, str], image: str) -> list[str]:
    args = [
        "docker",
        "run",
        "--network",
        f"container:{EGRESS}",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "1500m",
        "--cpus",
        "2",
        "--pids-limit",
        "256",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        "--user",
        "10001:10001",
        "-w",
        "/app",
    ]
    for key, value in env.items():
        args.extend(["-e", f"{key}={value}"])
    return args + [image]


def run_ephemeral(
    env: dict[str, str],
    image: str,
    *,
    name: str,
    entrypoint: str,
    command: list[str],
    mounts: list[tuple[Path, str, str]] = [],
    log: Path | None = None,
) -> None:
    args = secure_base(env, image)
    args[2:2] = ["--rm", "--name", name]
    insertion = len(args) - 1
    mount_args: list[str] = []
    for host, target, mode in mounts:
        mount_args.extend(["-v", f"{host}:{target}:{mode}"])
    args[insertion:insertion] = mount_args + ["--entrypoint", entrypoint]
    if log:
        with log.open("w") as handle:
            result = run(args + command, check=False, stdout=handle, stderr=subprocess.STDOUT)
        if result.returncode:
            raise AcceptanceError(f"{name} failed; inspect {log}")
    else:
        run(args + command)


def prepare_backends(env: dict[str, str], image: str, checkpoint: Path) -> None:
    for name in (POSTGRES, REDIS, EGRESS):
        record = docker_inspect(name)
        if not record["State"]["Running"]:
            raise AcceptanceError(f"required isolated support container is not running: {name}")
    ensure_connected(POSTGRES)
    ensure_connected(REDIS)
    ensure_egress_rule(POSTGRES, 5432, "isolated-p6-postgres")
    ensure_egress_rule(REDIS, 6379, "isolated-p6-redis")

    run(
        [
            "docker",
            "exec",
            POSTGRES,
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "preview",
            "-d",
            "postgres",
            "-c",
            f'DROP DATABASE IF EXISTS "{P6_DB}" WITH (FORCE);',
        ]
    )
    run(
        [
            "docker",
            "exec",
            POSTGRES,
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "preview",
            "-d",
            "postgres",
            "-c",
            f'CREATE DATABASE "{P6_DB}";',
        ]
    )
    run(["docker", "exec", REDIS, "redis-cli", "-n", P6_REDIS_DB, "FLUSHDB"])
    if output(
        ["docker", "exec", REDIS, "redis-cli", "-n", P6_REDIS_DB, "LLEN", "scanners"]
    ) != "0":
        raise AcceptanceError("P6 scanner queue is not empty after isolated reset")

    run_ephemeral(
        env,
        image,
        name="aegis-burp-p6-migrate",
        entrypoint="python",
        command=["manage.py", "migrate", "--noinput"],
        log=checkpoint / "migrate.log",
    )


def start_control(env: dict[str, str], image: str) -> None:
    remove_container(CONTROL)
    args = secure_base(env, image)
    args[2:2] = ["-d", "--name", CONTROL, "--label", "aegis.phase=web-labs-p6"]
    args.insert(len(args) - 1, "--entrypoint")
    args.insert(len(args) - 1, "sh")
    run(args + ["-lc", "exec sleep infinity"])


def start_worker(env: dict[str, str], image: str, name: str) -> None:
    remove_container(name)
    args = secure_base(env, image)
    args[2:2] = ["-d", "--name", name, "--label", "aegis.phase=web-labs-p6"]
    args.insert(len(args) - 1, "--entrypoint")
    args.insert(len(args) - 1, "celery")
    run(
        args
        + [
            "-A",
            "fastapi_app.celery_app",
            "worker",
            "--pool",
            "solo",
            "--concurrency",
            "1",
            "--queues",
            "scanners",
            "--hostname",
            "p6-live@%h",
            "--loglevel",
            "WARNING",
            "--without-gossip",
            "--without-mingle",
            "--without-heartbeat",
        ]
    )
    time.sleep(1.5)
    if not docker_inspect(name)["State"]["Running"]:
        raise AcceptanceError(f"P6 worker did not remain running: {name}")


def start_burp(
    *,
    name: str,
    image: str,
    profile: Path,
    xauthority: Path,
) -> str:
    remove_container(name)
    image_record = image_inspect(image)
    args = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--label",
        "aegis.phase=web-labs-p6",
        "--network",
        f"container:{EGRESS}",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "1536m",
        "--cpus",
        "1",
        "--pids-limit",
        "256",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        "--user",
        "1000:1000",
        "-e",
        "DISPLAY=:0",
        "-e",
        "XAUTHORITY=/run/burp-xauthority",
        "-v",
        f"{profile}:/var/lib/aegis-burp/profile",
        "-v",
        "/tmp/.X11-unix:/tmp/.X11-unix:ro",
        "-v",
        f"{xauthority}:/run/burp-xauthority:ro",
        image,
    ]
    run(args)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        probe = run(
            ["docker", "exec", EGRESS, "nc", "-z", "-w", "1", "127.0.0.1", "9876"],
            check=False,
        )
        if probe.returncode == 0:
            return image_record["Id"]
        if not docker_inspect(name)["State"]["Running"]:
            logs = output(["docker", "logs", name], timeout=30)
            raise AcceptanceError(f"Burp runtime exited before MCP readiness: {logs[-1600:]}")
        time.sleep(1)
    raise AcceptanceError("Burp MCP SSE port 9876 did not become ready")


def harness(
    *,
    env: dict[str, str],
    image: str,
    source_root: Path,
    case_dir: Path,
    action: str,
    variant: str | None = None,
    inspection: Path | None = None,
) -> None:
    args = secure_base(env, image)
    name = "aegis-burp-p6-harness-" + action.replace("-", "") + "-" + uuid.uuid4().hex[:6]
    args[2:2] = ["--rm", "--name", name]
    insertion = len(args) - 1
    args[insertion:insertion] = [
        "-v",
        f"{source_root / 'aegis-platform/e2e/live_web_lab_measurement.py'}:/acceptance.py:ro",
        "-v",
        f"{case_dir}:/results",
        "--entrypoint",
        "python",
    ]
    command = ["/acceptance.py", action, "--state", "/results/context.json"]
    if variant:
        command += ["--variant", variant]
    if inspection:
        command += ["--inspection", "/results/inspection.json"]
    log = case_dir / f"{action}.log"
    with log.open("w") as handle:
        result = run(args + command, check=False, stdout=handle, stderr=subprocess.STDOUT)
    (case_dir / f"{action}.exit").write_text(str(result.returncode))
    if result.returncode:
        raise AcceptanceError(f"P6 harness {action} failed; inspect {log}")


def lifecycle(
    source_root: Path,
    actor: str,
    action: str,
    arguments: list[str],
    output_path: Path,
) -> dict:
    cmd = [
        "python3",
        str(source_root / "aegis-platform/scripts/web_lab_host_lifecycle.py"),
        "--control-container",
        CONTROL,
        "--control-workdir",
        "/app",
        "--actor-id",
        actor,
        action,
        *arguments,
    ]
    result = run(cmd)
    output_path.write_text(result.stdout)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    payload = json.loads(lines[-1])
    if not isinstance(payload, dict):
        raise AcceptanceError("lifecycle command returned unexpected payload")
    return payload


def inspect_runtime(
    source_root: Path, container: str, case_dir: Path
) -> dict:
    output_path = case_dir / "inspection.json"
    run(
        [
            "python3",
            str(source_root / "aegis-platform/scripts/inspect_web_lab_runtime.py"),
            "--container",
            container,
            "--expected-image-id",
            FIXTURE_IMAGE_ID,
            "--fixture-source",
            str(source_root / "aegis-platform/e2e/fixtures/bac-target/app.py"),
            "--output",
            str(output_path),
        ]
    )
    return json.loads(output_path.read_text())


def wait_scan(scan_ref: str, timeout: float = 180) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = output(
            [
                "docker",
                "exec",
                POSTGRES,
                "psql",
                "-U",
                "preview",
                "-d",
                P6_DB,
                "-At",
                "-c",
                f"SELECT status FROM scans_scan WHERE id='{scan_ref}'",
            ]
        )
        if status in {"completed", "failed", "cancelled"}:
            return status
        time.sleep(2)
    raise AcceptanceError(f"scan did not reach a terminal state: {scan_ref}")


def derive_case(
    *,
    source_root: Path,
    case_ref: str,
    case_dir: Path,
    source_commit: str,
    fixture_image_id: str,
    scanner_image_id: str,
    proof: Path,
    metrics: dict,
) -> Path:
    metrics_path = case_dir / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2))
    output_path = case_dir / "measurement-case.json"
    run(
        [
            "python3",
            str(source_root / "aegis-platform/scripts/web_lab_measurement_case.py"),
            "--plan",
            str(source_root / "docs/web-labs/p6-measurement-plan-v1.json"),
            "--case-ref",
            case_ref,
            "--proof",
            str(proof),
            "--metrics",
            str(metrics_path),
            "--source-commit",
            source_commit,
            "--fixture-image-id",
            fixture_image_id,
            "--scanner-image-id",
            scanner_image_id,
            "--output",
            str(output_path),
        ]
    )
    return output_path


def lifecycle_target_names() -> list[str]:
    return [
        name.strip()
        for name in output(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                "label=aegis.web-lab.lifecycle=v1",
                "--format",
                "{{.Names}}",
            ]
        ).splitlines()
        if name.strip()
    ]


def cleanup_p6_runtime() -> None:
    names = output(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            "label=aegis.phase=web-labs-p6",
            "--format",
            "{{.Names}}",
        ]
    ).splitlines()
    for name in names:
        if name.strip():
            remove_container(name.strip())
    remove_container(CONTROL)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--scanner-image", required=True)
    parser.add_argument("--burp-image", default="aegis-burp-p2:2026.9")
    parser.add_argument("--env-template", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--xauthority", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    args = parser.parse_args()

    source_root = args.source_root.resolve()
    checkpoint = args.checkpoint.resolve()
    if not SHA40.fullmatch(args.source_commit):
        raise AcceptanceError("source commit must be an exact 40-hex SHA")
    if output(["git", "-C", source_root, "rev-parse", "HEAD"]) != args.source_commit:
        raise AcceptanceError("source checkout HEAD differs from sealed P6 SHA")
    if output(["git", "-C", source_root, "status", "--porcelain"]):
        raise AcceptanceError("P6 acceptance requires a clean sealed source checkout")
    allowed_root = Path("/home/aegisadmin/aegis-web-labs-checkpoints").resolve()
    if checkpoint.parent != allowed_root:
        raise AcceptanceError("P6 checkpoint must be a direct child of the checkpoint root")
    if checkpoint.exists():
        raise AcceptanceError("P6 checkpoint already exists; never overwrite evidence")
    checkpoint.mkdir(mode=0o700)

    scanner_record = image_inspect(args.scanner_image)
    scanner_id = scanner_record["Id"]
    if scanner_record.get("Config", {}).get("Labels", {}).get(
        "org.opencontainers.image.revision"
    ) != args.source_commit:
        raise AcceptanceError("scanner image revision label differs from sealed P6 SHA")
    if image_inspect(FIXTURE_IMAGE_ID)["Id"] != FIXTURE_IMAGE_ID:
        raise AcceptanceError("fixture image identity changed")
    burp_id = image_inspect(args.burp_image)["Id"]
    if not args.env_template.is_file() or not args.profile.is_dir() or not args.xauthority.is_file():
        raise AcceptanceError("required host-only env/profile/Xauthority input is unavailable")

    env = load_env(args.env_template, args.source_commit)
    backend_root = source_root / "aegis-platform/backend"
    sys.path.insert(0, str(backend_root))
    from fastapi_app.services.web_lab_measurement import validate_plan

    plan = validate_plan(
        json.loads(
            (source_root / "docs/web-labs/p6-measurement-plan-v1.json").read_text()
        )
    )
    cases = plan["cases"]

    preexisting_labs = lifecycle_target_names()
    if preexisting_labs:
        raise AcceptanceError(
            "P6 requires an exclusive Web Lab lifecycle window; existing targets: "
            + ",".join(preexisting_labs)
        )
    cleanup_p6_runtime()
    case_outputs: list[Path] = []
    lifecycle_instances: dict[str, tuple[str, str]] = {}
    try:
        prepare_backends(env, scanner_id, checkpoint)
        start_control(env, scanner_id)

        for index, spec in enumerate(cases, 1):
            case_ref = spec["case_ref"]
            case_dir = checkpoint / case_ref
            case_dir.mkdir(mode=0o770)
            run(["setfacl", "-m", "u:10001:rwx", str(case_dir)])
            harness(
                env=env,
                image=scanner_id,
                source_root=source_root,
                case_dir=case_dir,
                action="prepare",
                variant=spec["variant"],
            )
            state = json.loads((case_dir / "context.json").read_text())

            lifecycle_result = lifecycle(
                source_root,
                state["actor_ref"],
                "provision",
                [
                    "--asset-id",
                    state["asset_ref"],
                    "--lab-definition-id",
                    "bac-orders-v1",
                    "--variant",
                    spec["variant"],
                    "--ttl-seconds",
                    "1800",
                    "--image-id",
                    FIXTURE_IMAGE_ID,
                    "--fixture-source",
                    str(source_root / "aegis-platform/e2e/fixtures/bac-target/app.py"),
                    "--network-container",
                    EGRESS,
                    "--idempotency-key",
                    f"p6-{index}-{case_ref}-{uuid.uuid4().hex[:8]}",
                ],
                case_dir / "lifecycle-provision.json",
            )
            instance = lifecycle_result["instance"]
            lifecycle_instances[instance["lifecycle_ref"]] = (
                state["actor_ref"],
                instance["container_name"],
            )
            inspection = inspect_runtime(source_root, instance["container_name"], case_dir)
            if inspection["fixture_revision"] != FIXTURE_REVISION:
                raise AcceptanceError("fixture revision changed during P6 inspection")

            runtime_name = "aegis-burp-p6-runtime-" + str(index)
            worker_name = "aegis-burp-p6-worker-" + str(index)
            is_disconnect = spec["scenario"] == "disconnect"
            if is_disconnect:
                probe = run(
                    ["docker", "exec", EGRESS, "nc", "-z", "-w", "1", "127.0.0.1", "9876"],
                    check=False,
                )
                if probe.returncode == 0:
                    raise AcceptanceError("disconnect case began with MCP port unexpectedly open")
            else:
                observed_burp_id = start_burp(
                    name=runtime_name,
                    image=burp_id,
                    profile=args.profile.resolve(),
                    xauthority=args.xauthority.resolve(),
                )
                if observed_burp_id != burp_id:
                    raise AcceptanceError("Burp runtime image identity changed")

            start_worker(env, scanner_id, worker_name)
            resource_names = [worker_name, instance["container_name"]]
            if not is_disconnect:
                resource_names.append(runtime_name)
            monitor = ResourceMonitor(resource_names)
            monitor.start()
            try:
                harness(
                    env=env,
                    image=scanner_id,
                    source_root=source_root,
                    case_dir=case_dir,
                    action="schedule",
                    inspection=case_dir / "inspection.json",
                )
                state = json.loads((case_dir / "context.json").read_text())
                status = wait_scan(state["scan_ref"])
                if is_disconnect and status != "failed":
                    raise AcceptanceError(
                        f"disconnect case must fail closed, observed status={status}"
                    )
                if not is_disconnect and status != "completed":
                    raise AcceptanceError(
                        f"nominal case must complete, observed status={status}"
                    )
            finally:
                measured = monitor.stop()

            if is_disconnect:
                harness(
                    env=env,
                    image=scanner_id,
                    source_root=source_root,
                    case_dir=case_dir,
                    action="collect-disconnect",
                )
                proof = case_dir / "disconnect-proof.json"
                proof_value = json.loads(proof.read_text())
                external_requests = int(proof_value["invocation_claim_count"])
            else:
                harness(
                    env=env,
                    image=scanner_id,
                    source_root=source_root,
                    case_dir=case_dir,
                    action="collect",
                )
                proof = case_dir / "live-verification-proof.json"
                proof_value = json.loads(proof.read_text())
                external_requests = int(proof_value["qualified_evidence_count"])

            measured.update(
                external_requests=external_requests,
                human_interventions=0,
            )
            case_outputs.append(
                derive_case(
                    source_root=source_root,
                    case_ref=case_ref,
                    case_dir=case_dir,
                    source_commit=args.source_commit,
                    fixture_image_id=FIXTURE_IMAGE_ID,
                    scanner_image_id=scanner_id,
                    proof=proof,
                    metrics=measured,
                )
            )

            remove_container(worker_name)
            remove_container(runtime_name)
            cleanup_result = lifecycle(
                source_root,
                state["actor_ref"],
                "cleanup",
                [
                    "--instance-id",
                    instance["lifecycle_ref"],
                    "--idempotency-key",
                    f"p6-clean-{index}-{uuid.uuid4().hex[:8]}",
                ],
                case_dir / "lifecycle-cleanup.json",
            )
            if cleanup_result.get("cleaned", {}).get("status") != "cleaned":
                raise AcceptanceError("P5 lifecycle did not close P6 target as cleaned")
            lifecycle_instances.pop(instance["lifecycle_ref"], None)

        report_path = checkpoint / "measurement-report.json"
        command = [
            "python3",
            str(source_root / "aegis-platform/scripts/web_lab_measurement_report.py"),
            "--plan",
            str(source_root / "docs/web-labs/p6-measurement-plan-v1.json"),
            "--source-commit",
            args.source_commit,
            "--output",
            str(report_path),
        ]
        for case_path in case_outputs:
            command += ["--case", str(case_path)]
        run(command)
        report = json.loads(report_path.read_text())
        if report["status"] != "pass" or report["outcomes"]["mismatches"] != 0:
            raise AcceptanceError("P6 measurement report did not pass")

        orphan_names = lifecycle_target_names()
        if orphan_names:
            raise AcceptanceError(
                "Web Lab lifecycle targets remain after P6: " + ",".join(orphan_names)
            )

        artifacts = {}
        for path in sorted(checkpoint.rglob("*")):
            if path.is_file():
                artifacts[str(path.relative_to(checkpoint))] = sha256_file(path)
        closeout = {
            "schema": "aegis.web-labs-p6-closeout.v1",
            "status": "pass",
            "source_commit": args.source_commit,
            "scanner_image_id": scanner_id,
            "fixture_image_id": FIXTURE_IMAGE_ID,
            "fixture_revision": FIXTURE_REVISION,
            "burp_runtime_image_id": burp_id,
            "measurement_sha256": report["measurement_sha256"],
            "case_count": report["case_count"],
            "mismatches": report["outcomes"]["mismatches"],
            "indeterminate_cases": report["outcomes"]["indeterminate_cases"],
            "human_interventions_total": (
                report["resources"]["baseline"]["human_interventions_total"]
                + report["resources"]["held_out"]["human_interventions_total"]
            ),
            "production_touched": False,
            "orphan_web_lab_containers": [],
            "artifacts": artifacts,
        }
        closeout_path = checkpoint / "closeout.json"
        closeout_path.write_text(json.dumps(closeout, indent=2, sort_keys=True))
        print(
            json.dumps(
                {
                    "P6_LIVE_ACCEPTANCE": "PASS",
                    "source_commit": args.source_commit,
                    "measurement_sha256": report["measurement_sha256"],
                    "closeout_sha256": sha256_file(closeout_path),
                }
            )
        )
        return 0
    finally:
        for instance_id, (actor_ref, container_name) in list(lifecycle_instances.items()):
            try:
                lifecycle(
                    source_root,
                    actor_ref,
                    "cleanup",
                    [
                        "--instance-id",
                        instance_id,
                        "--idempotency-key",
                        "p6-finally-" + uuid.uuid4().hex[:12],
                    ],
                    checkpoint / ("finally-cleanup-" + instance_id + ".json"),
                )
            except Exception as exc:
                with (checkpoint / "cleanup-errors.log").open("a") as handle:
                    handle.write(f"{instance_id} {container_name}: {exc}\n")
                remove_container(container_name)
        cleanup_p6_runtime()


if __name__ == "__main__":
    raise SystemExit(main())

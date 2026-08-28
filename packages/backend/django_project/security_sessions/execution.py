from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from django.db import transaction
from django.utils import timezone

from .models import SecurityTestSession
from .services import (
    SessionAccessError,
    SessionPolicyError,
    _append_evidence_locked,
    authenticate_execution_identity,
    redact,
)


@dataclass(frozen=True)
class ExecutionResult:
    execution_id: str
    session_id: str
    kind: str
    command: str
    target: str
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    evidence_ref: str


def _target_in_scope(session: SecurityTestSession, target: str) -> bool:
    requested = target.strip()
    targets = {str(x).strip().lower() for x in (session.scope or {}).get("targets", [])}
    if requested.lower() in targets:
        return True
    return requested.lower() in {"local", "localhost", "runner"} and bool(
        (session.scope or {}).get("allow_local_runner")
    )


def _truncate(value: str, limit: int = 12000) -> str:
    return value if len(value) <= limit else value[:limit] + "\n[TRUNCATED]"


def execute_with_identity(
    *,
    token: str,
    expected_session_id: UUID | str,
    command: str,
    target: str = "local",
    kind: str = "command",
    approval_id: str | None = None,
    timeout_seconds: int = 60,
    cwd: str | None = None,
) -> dict[str, Any]:
    command = command.strip()
    if not command:
        raise SessionPolicyError("command is required")
    if kind not in {"command", "interactive", "privileged_validation"}:
        raise SessionPolicyError("unsupported execution kind")
    if timeout_seconds < 1 or timeout_seconds > 900:
        raise SessionPolicyError("timeout_seconds must be between 1 and 900")

    identity, session = authenticate_execution_identity(token)
    if str(session.id) != str(expected_session_id):
        raise SessionAccessError("execution identity is not bound to this security test session")
    if not _target_in_scope(session, target):
        raise SessionPolicyError("target is outside the session scope")

    required_capability = {
        "command": "active_validate",
        "interactive": "interactive_session",
        "privileged_validation": "privileged_validation",
    }[kind]
    if required_capability not in set(session.capabilities):
        raise SessionAccessError(f"session lacks capability: {required_capability}")
    if kind in {"interactive", "privileged_validation"}:
        if not approval_id:
            raise SessionPolicyError("high-risk execution requires approval_id")
        if approval_id != str(session.authorization_id) and approval_id != str(
            (session.metadata or {}).get("approval_id", "")
        ):
            raise SessionAccessError("approval_id does not match the session authorization context")

    execution_id = f"exec-{identity.id}-{int(time.time() * 1000)}"
    started = time.perf_counter()
    stdout = ""
    stderr = ""
    exit_code: int | None = None
    status = "success"

    with transaction.atomic():
        locked_session = SecurityTestSession.objects.select_for_update().get(pk=session.id)
        _append_evidence_locked(
            locked_session,
            event_type="execution.started",
            capability=required_capability,
            target=target,
            action="shell.exec",
            status="started",
            data={
                "execution_id": execution_id,
                "kind": kind,
                "command": command,
                "cwd": cwd,
                "adapter": "authorized_local_shell",
            },
        )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=True,
            cwd=cwd or None,
        )
        exit_code = completed.returncode
        stdout = _truncate(completed.stdout)
        stderr = _truncate(completed.stderr)
        status = "success" if exit_code == 0 else "failed"
    except subprocess.TimeoutExpired as exc:
        status = "timeout"
        stdout = _truncate(exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = _truncate(exc.stderr or "execution timed out") if isinstance(exc.stderr, str) else "execution timed out"
    except (OSError, ValueError) as exc:
        status = "failed"
        stderr = _truncate(str(exc))
    finally:
        duration_ms = int((time.perf_counter() - started) * 1000)

    with transaction.atomic():
        locked_session = SecurityTestSession.objects.select_for_update().get(pk=session.id)
        record = _append_evidence_locked(
            locked_session,
            event_type="execution.completed",
            capability=required_capability,
            target=target,
            action="shell.exec",
            status=status,
            data=redact(
                {
                    "execution_id": execution_id,
                    "kind": kind,
                    "command": command,
                    "cwd": cwd,
                    "adapter": "authorized_local_shell",
                    "exit_code": exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                    "duration_ms": duration_ms,
                    "approval_id": approval_id,
                    "observed_at": timezone.now().isoformat(),
                }
            ),
        )

    return ExecutionResult(
        execution_id=execution_id,
        session_id=str(session.id),
        kind=kind,
        command=command,
        target=target,
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        evidence_ref=str(record.id),
    ).__dict__

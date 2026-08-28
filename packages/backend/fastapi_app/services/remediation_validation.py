from __future__ import annotations

import asyncio
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    checks: tuple[dict[str, Any], ...]
    blocked: bool = False


@dataclass(frozen=True)
class ToolResult:
    tool: str
    available: bool
    passed: bool
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int


class RemediationValidationSuite:
    """Approval-gated validation with real local security-tool execution.

    The suite never writes to a target. It validates a supplied workspace/tree and
    fails closed when approval, scope, workspace, or required tooling is missing.
    """

    def validate(self, candidate: dict[str, Any], checks: dict[str, Callable[[dict[str, Any]], bool]]) -> dict[str, Any]:
        if not candidate.get("approval_id"):
            return ValidationResult(False, (), True).__dict__
        results = []
        for name, check in checks.items():
            try:
                passed = bool(check(candidate))
                results.append({"check": name, "passed": passed})
            except Exception as exc:
                results.append({"check": name, "passed": False, "error": type(exc).__name__})
        return ValidationResult(all(x["passed"] for x in results), tuple(results), False).__dict__

    @staticmethod
    def _workspace(candidate: dict[str, Any]) -> Path:
        if not candidate.get("approval_id"):
            raise PermissionError("approval_id is required")
        if not candidate.get("authorized"):
            raise PermissionError("authorized scope is required")
        raw = str(candidate.get("workspace") or "").strip()
        if not raw:
            raise ValueError("workspace is required for real remediation validation")
        path = Path(raw).resolve()
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"validation workspace does not exist: {path}")
        allowed_root = str(os.getenv("AEGIS_VALIDATION_WORKSPACE_ROOT", "")).strip()
        if allowed_root:
            root = Path(allowed_root).resolve()
            try:
                path.relative_to(root)
            except ValueError as exc:
                raise PermissionError("workspace is outside configured validation root") from exc
        return path

    async def _run_tool(self, tool: str, args: list[str], workspace: Path, timeout: int = 180) -> ToolResult:
        executable = shutil.which(tool)
        if executable is None:
            return ToolResult(tool, False, False, None, "", f"{tool} is not installed or not on PATH", 0)
        command = [executable, *args]
        started = asyncio.get_running_loop().time()
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(workspace),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=os.environ.copy(),
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            elapsed = int((asyncio.get_running_loop().time() - started) * 1000)
            return ToolResult(tool, True, False, -1, "", "tool execution timed out", elapsed)
        elapsed = int((asyncio.get_running_loop().time() - started) * 1000)
        out = stdout.decode(errors="replace")[-20000:]
        err = stderr.decode(errors="replace")[-10000:]
        # Security tools commonly return non-zero when they discover findings.
        # For remediation validation, zero is required for a clean validation pass.
        return ToolResult(tool, True, process.returncode == 0, process.returncode, out, err, elapsed)

    async def validate_workspace(
        self,
        candidate: dict[str, Any],
        *,
        tools: list[str] | None = None,
        timeout: int = 180,
    ) -> dict[str, Any]:
        workspace = self._workspace(candidate)
        requested = tools or ["semgrep"]
        supported = {"semgrep", "nuclei", "trivy", "grype", "gitleaks"}
        unknown = sorted(set(requested) - supported)
        if unknown:
            raise ValueError(f"unsupported validation tools: {', '.join(unknown)}")

        results: list[ToolResult] = []
        for tool in requested:
            if tool == "semgrep":
                result = await self._run_tool("semgrep", ["scan", "--config", "auto", "--json", "--error", "."], workspace, timeout)
            elif tool == "nuclei":
                target = str(candidate.get("validation_target") or "").strip()
                if not target:
                    result = ToolResult(tool, False, False, None, "", "validation_target is required for nuclei", 0)
                else:
                    result = await self._run_tool("nuclei", ["-u", target, "-jsonl", "-silent"], workspace, timeout)
                    # Nuclei's exit code alone is insufficient; any emitted result is a finding.
                    result = ToolResult(result.tool, result.available, result.passed and not result.stdout.strip(), result.exit_code, result.stdout, result.stderr, result.duration_ms)
            elif tool == "trivy":
                result = await self._run_tool("trivy", ["fs", "--scanners", "vuln,secret", "--exit-code", "1", "."], workspace, timeout)
            elif tool == "grype":
                result = await self._run_tool("grype", ["dir:."], workspace, timeout)
            else:
                result = await self._run_tool("gitleaks", ["detect", "--no-banner", "--redact"], workspace, timeout)
            results.append(result)

        available = [item for item in results if item.available]
        passed = bool(results) and all(item.passed for item in available) and len(available) == len(results)
        payload = {
            "passed": passed,
            "blocked": False,
            "workspace": str(workspace),
            "tools": [
                {
                    "tool": item.tool,
                    "available": item.available,
                    "passed": item.passed,
                    "exit_code": item.exit_code,
                    "stdout": item.stdout,
                    "stderr": item.stderr,
                    "duration_ms": item.duration_ms,
                }
                for item in results
            ],
        }
        payload["summary"] = {
            "requested": len(results),
            "available": len(available),
            "failed": sum(1 for item in results if item.available and not item.passed),
            "missing": sum(1 for item in results if not item.available),
        }
        return payload

    @staticmethod
    def compare_scores(before: float, after: float) -> dict[str, Any]:
        before_value = max(0.0, min(100.0, float(before)))
        after_value = max(0.0, min(100.0, float(after)))
        delta = round(after_value - before_value, 2)
        return {
            "before": round(before_value, 2),
            "after": round(after_value, 2),
            "improvement": round(max(0.0, delta), 2),
            "delta": delta,
            "regressed": delta < 0,
        }

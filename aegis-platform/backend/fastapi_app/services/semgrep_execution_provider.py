from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi_app.services.kali_semgrep_provider import (
    KaliSemgrepProviderError,
    execute_kali_semgrep,
    semgrep_provider_decision,
)
from fastapi_app.services.scanner_adapters import run_semgrep, validate_code_target


_MAX_SNAPSHOT_FILES = 20_000
_MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class SemgrepExecutionResult:
    tool: str
    target: str
    exit_code: int
    stdout: str
    stderr: str
    routing: dict[str, Any]
    runtime: dict[str, Any]


def _workspace_root() -> Path:
    root = Path(os.getenv('AEGIS_SEMGREP_WORKSPACE_ROOT', '/var/lib/aegis-semgrep'))
    if not root.is_absolute():
        raise KaliSemgrepProviderError('AEGIS_SEMGREP_WORKSPACE_ROOT must be absolute')
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise KaliSemgrepProviderError('AEGIS_SEMGREP_WORKSPACE_ROOT must be a regular directory')
    return root


def _iter_source_files(source: Path) -> list[tuple[Path, Path]]:
    if source.is_symlink():
        raise KaliSemgrepProviderError('Semgrep canary source cannot be a symlink')
    if source.is_file():
        return [(source, Path(source.name))]
    if not source.is_dir():
        raise KaliSemgrepProviderError('Semgrep canary source must be a regular file or directory')

    files: list[tuple[Path, Path]] = []
    total_bytes = 0
    for item in sorted(source.rglob('*'), key=lambda path: path.relative_to(source).as_posix()):
        if item.is_symlink():
            raise KaliSemgrepProviderError(
                f'Semgrep canary source tree cannot contain symlinks: {item.relative_to(source).as_posix()}'
            )
        if item.is_dir():
            continue
        if not item.is_file():
            raise KaliSemgrepProviderError(
                f'Semgrep canary source tree contains unsupported file type: {item.relative_to(source).as_posix()}'
            )
        relative = item.relative_to(source)
        size = item.stat().st_size
        total_bytes += size
        if len(files) + 1 > _MAX_SNAPSHOT_FILES:
            raise KaliSemgrepProviderError(
                f'Semgrep canary source exceeds {_MAX_SNAPSHOT_FILES} files'
            )
        if total_bytes > _MAX_SNAPSHOT_BYTES:
            raise KaliSemgrepProviderError(
                f'Semgrep canary source exceeds {_MAX_SNAPSHOT_BYTES} bytes'
            )
        files.append((item, relative))
    if not files:
        raise KaliSemgrepProviderError('Semgrep canary source tree cannot be empty')
    return files


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(
        (path for path in root.rglob('*') if path.is_file() or path.is_symlink()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    if not files:
        raise KaliSemgrepProviderError('Semgrep canary snapshot cannot be empty')
    total_bytes = 0
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise KaliSemgrepProviderError('Semgrep canary snapshot contains an invalid file')
        relative = path.relative_to(root).as_posix().encode('utf-8')
        data = path.read_bytes()
        total_bytes += len(data)
        if len(files) > _MAX_SNAPSHOT_FILES or total_bytes > _MAX_SNAPSHOT_BYTES:
            raise KaliSemgrepProviderError('Semgrep canary snapshot exceeds the bounded workspace policy')
        digest.update(len(relative).to_bytes(4, 'big'))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, 'big'))
        digest.update(data)
    return digest.hexdigest()


@dataclass
class _Snapshot:
    snapshot_id: str
    root: Path
    source_sha256: str
    source_entry: str
    original_root: Path

    def cleanup(self) -> None:
        if self.root.exists() and not self.root.is_symlink():
            shutil.rmtree(self.root)


def _stage_source(source: str) -> _Snapshot:
    canonical = Path(validate_code_target(source)).resolve(strict=True)
    workspace = _workspace_root()
    snapshot_id = secrets.token_hex(32)
    destination = workspace / snapshot_id
    destination.mkdir(mode=0o700)
    try:
        files = _iter_source_files(canonical)
        if canonical.is_file():
            original_root = canonical.parent
            source_entry = canonical.name
        else:
            original_root = canonical
            source_entry = '.'

        for item, relative in files:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target, follow_symlinks=False)
        source_sha256 = _tree_sha256(destination)
        return _Snapshot(
            snapshot_id=snapshot_id,
            root=destination,
            source_sha256=source_sha256,
            source_entry=source_entry,
            original_root=original_root,
        )
    except BaseException:
        if destination.exists() and not destination.is_symlink():
            shutil.rmtree(destination)
        raise


def _rewrite_candidate_paths(raw_output: str, snapshot: _Snapshot) -> str:
    try:
        payload = json.loads(raw_output) if raw_output.strip() else {}
    except json.JSONDecodeError:
        return raw_output
    if not isinstance(payload, dict):
        return raw_output
    results = payload.get('results')
    if not isinstance(results, list):
        return raw_output

    snapshot_root = snapshot.root.resolve()
    for item in results:
        if not isinstance(item, dict):
            continue
        raw_path = item.get('path')
        if not isinstance(raw_path, str) or not raw_path:
            continue
        candidate = Path(raw_path)
        relative: Path | None = None
        if candidate.is_absolute():
            try:
                relative = candidate.resolve(strict=False).relative_to(snapshot_root)
            except ValueError:
                relative = None
        else:
            if '..' not in candidate.parts:
                parts = candidate.parts
                if parts and parts[0] == snapshot.snapshot_id:
                    relative = Path(*parts[1:])
                else:
                    relative = candidate
        if relative is None:
            raise KaliSemgrepProviderError(
                f'Kali Semgrep returned a path outside the bound snapshot: {raw_path}'
            )
        item['path'] = str((snapshot.original_root / relative).resolve(strict=False))

    return json.dumps(payload, sort_keys=True, separators=(',', ':'))


def run_semgrep_with_provider(
    *,
    source: str,
    timeout_seconds: int,
    routing_key: str,
    execution_ref: str,
    authorization_ref: str,
    scope_ref: str,
    state_getter: Callable[[], str] | None,
) -> SemgrepExecutionResult:
    """Execute Semgrep through the bounded M4 provider decision.

    M4 admits Legacy and Canary production modes only. Raw Kali remains a
    provider-library diagnostic mode and is rejected by this execution layer.
    Selected Kali executions stage a bounded immutable source snapshot in the
    shared workspace and fail closed on any provider/provenance/runtime error.
    """
    canonical_source = validate_code_target(source)
    decision = semgrep_provider_decision(routing_key=routing_key)
    if decision.mode not in {'legacy', 'canary'}:
        raise RuntimeError(
            f'Semgrep provider mode {decision.mode!r} is not admitted by the governed production execution layer'
        )
    routing = decision.as_dict()

    if decision.selected_provider == 'legacy':
        result = run_semgrep(
            canonical_source,
            timeout=timeout_seconds,
            state_getter=state_getter,
        )
        return SemgrepExecutionResult(
            tool=result.tool,
            target=result.target,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            routing=routing,
            runtime={
                'provider': 'legacy-native-worker',
                'provenance_authority': 'production-scanner-adapter',
            },
        )

    if decision.selected_provider != 'kali':
        raise RuntimeError(f'Unsupported Semgrep provider decision: {decision.selected_provider!r}')

    snapshot = _stage_source(canonical_source)
    try:
        result = execute_kali_semgrep(
            snapshot_id=snapshot.snapshot_id,
            source_sha256=snapshot.source_sha256,
            source_entry=snapshot.source_entry,
            timeout_seconds=timeout_seconds,
            execution_ref=execution_ref,
            authorization_ref=authorization_ref,
            scope_ref=scope_ref,
            state_getter=state_getter,
        )
        stdout = _rewrite_candidate_paths(str(result['stdout']), snapshot)
        runtime = dict(result['runtime'])
        runtime['source_sha256'] = snapshot.source_sha256
        runtime['snapshot_policy'] = {
            'max_files': _MAX_SNAPSHOT_FILES,
            'max_bytes': _MAX_SNAPSHOT_BYTES,
            'symlinks_allowed': False,
        }
        return SemgrepExecutionResult(
            tool='semgrep',
            target=canonical_source,
            exit_code=int(result['exit_code']),
            stdout=stdout,
            stderr=str(result['stderr']),
            routing=routing,
            runtime=runtime,
        )
    finally:
        snapshot.cleanup()

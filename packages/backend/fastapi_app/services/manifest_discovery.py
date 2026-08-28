from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

SUPPORTED_MANIFESTS = {
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "composer.lock",
    "Gemfile.lock",
}
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_FILES = 25


def _root(path: str) -> Path:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("workspace must be an existing directory")
    return root


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def discover_dependency_manifests(workspace: str, *, max_bytes: int = DEFAULT_MAX_BYTES, max_files: int = DEFAULT_MAX_FILES) -> list[dict[str, Any]]:
    root = _root(workspace)
    results: list[dict[str, Any]] = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        dirnames[:] = [name for name in dirnames if name not in {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}]
        for filename in filenames:
            if filename not in SUPPORTED_MANIFESTS:
                continue
            candidate = current / filename
            try:
                resolved = candidate.resolve(strict=True)
                if not _inside(root, resolved) or not resolved.is_file() or resolved.is_symlink():
                    continue
                size = resolved.stat().st_size
                if size <= 0 or size > max_bytes:
                    continue
                content = resolved.read_text(encoding="utf-8", errors="strict")
            except (OSError, UnicodeError):
                continue
            relative = resolved.relative_to(root).as_posix()
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            results.append({"filename": relative, "content": content, "bytes": size, "sha256": digest})
            if len(results) >= max_files:
                return results
    return results

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


UPSTREAM_REPOSITORY = 'https://github.com/0x4m4/hexstrike-ai.git'
UPSTREAM_REF = 'master'
UPSTREAM_COMMIT = 'd689933ff579d839c676c82b231f8e98326c5f04'


@dataclass(frozen=True)
class UpstreamCapability:
    kind: str
    name: str
    source_file: str
    line: int
    parameters: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    path: str | None = None

    def public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data['parameters'] = list(self.parameters)
        data['methods'] = list(self.methods)
        return data


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def upstream_root() -> Path:
    return _repo_root() / 'third_party' / 'hexstrike-ai'


def _source(path: str) -> tuple[Path, ast.Module]:
    source_path = upstream_root() / path
    if not source_path.is_file():
        raise RuntimeError(
            'Pinned HexStrike source is unavailable. Initialize the '
            'third_party/hexstrike-ai submodule before capability discovery.'
        )
    return source_path, ast.parse(source_path.read_text(encoding='utf-8'), filename=str(source_path))


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        prefix = _decorator_name(node.value)
        return f'{prefix}.{node.attr}' if prefix else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ''


def _function_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    names = [arg.arg for arg in args]
    if node.args.vararg:
        names.append(f'*{node.args.vararg.arg}')
    if node.args.kwarg:
        names.append(f'**{node.args.kwarg.arg}')
    return tuple(names)


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _route_methods(decorator: ast.Call) -> tuple[str, ...]:
    for keyword in decorator.keywords:
        if keyword.arg == 'methods' and isinstance(keyword.value, (ast.List, ast.Tuple)):
            methods = [_literal_string(item) for item in keyword.value.elts]
            return tuple(item.upper() for item in methods if item)
    name = _decorator_name(decorator.func).rsplit('.', 1)[-1].upper()
    if name in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}:
        return (name,)
    return ()


@lru_cache(maxsize=1)
def discover_hexstrike_capabilities() -> tuple[UpstreamCapability, ...]:
    discovered: list[UpstreamCapability] = []

    _, mcp_tree = _source('hexstrike_mcp.py')
    for node in ast.walk(mcp_tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(_decorator_name(item).endswith('mcp.tool') for item in node.decorator_list):
            discovered.append(
                UpstreamCapability(
                    kind='mcp-tool',
                    name=node.name,
                    source_file='hexstrike_mcp.py',
                    line=node.lineno,
                    parameters=_function_parameters(node),
                )
            )

    _, server_tree = _source('hexstrike_server.py')
    for node in ast.walk(server_tree):
        if isinstance(node, ast.ClassDef):
            if node.name.endswith(('Manager', 'Engine', 'System', 'Monitor', 'Detector', 'Optimizer', 'Correlator', 'Generator')):
                discovered.append(
                    UpstreamCapability(
                        kind='agent',
                        name=node.name,
                        source_file='hexstrike_server.py',
                        line=node.lineno,
                    )
                )
            continue
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            decorator_name = _decorator_name(decorator.func)
            if not decorator_name.endswith(('.route', '.get', '.post', '.put', '.patch', '.delete')):
                continue
            route_path = _literal_string(decorator.args[0]) if decorator.args else None
            if not route_path:
                continue
            discovered.append(
                UpstreamCapability(
                    kind='server-route',
                    name=node.name,
                    source_file='hexstrike_server.py',
                    line=node.lineno,
                    parameters=_function_parameters(node),
                    methods=_route_methods(decorator),
                    path=route_path,
                )
            )

    unique = {
        (item.kind, item.name, item.source_file, item.line, item.path): item
        for item in discovered
    }
    return tuple(sorted(unique.values(), key=lambda item: (item.kind, item.name, item.line)))


def hexstrike_catalog() -> dict[str, Any]:
    capabilities = discover_hexstrike_capabilities()
    counts: dict[str, int] = {}
    for item in capabilities:
        counts[item.kind] = counts.get(item.kind, 0) + 1
    return {
        'source': 'hexstrike-ai',
        'repository': UPSTREAM_REPOSITORY,
        'ref': UPSTREAM_REF,
        'commit': UPSTREAM_COMMIT,
        'execution_authority': 'aegisscan',
        'direct_upstream_execution_exposed': False,
        'counts': counts,
        'total': len(capabilities),
        'capabilities': [item.public_dict() for item in capabilities],
    }

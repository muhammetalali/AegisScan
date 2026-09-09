from __future__ import annotations

import subprocess

from fastapi_app.services.hexstrike_catalog import (
    UPSTREAM_COMMIT,
    discover_hexstrike_capabilities,
    hexstrike_catalog,
    upstream_root,
)


def test_hexstrike_submodule_is_exact_pinned_commit():
    root = upstream_root()
    assert (root / 'LICENSE').is_file()
    assert (root / 'hexstrike_mcp.py').is_file()
    assert (root / 'hexstrike_server.py').is_file()
    actual = subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', 'HEAD'],
        text=True,
    ).strip()
    assert actual == UPSTREAM_COMMIT


def test_complete_source_surface_is_discovered_without_importing_upstream():
    capabilities = discover_hexstrike_capabilities()
    assert capabilities
    kinds = {item.kind for item in capabilities}
    assert {'mcp-tool', 'server-route', 'agent'} <= kinds

    names = {item.name for item in capabilities}
    assert 'nuclei_scan' in names
    assert len([item for item in capabilities if item.kind == 'mcp-tool']) >= 50

    identities = {
        (item.kind, item.name, item.source_file, item.line, item.path)
        for item in capabilities
    }
    assert len(identities) == len(capabilities)


def test_upstream_catalog_never_claims_direct_execution_authority():
    catalog = hexstrike_catalog()
    assert catalog['commit'] == UPSTREAM_COMMIT
    assert catalog['execution_authority'] == 'aegisscan'
    assert catalog['direct_upstream_execution_exposed'] is False
    assert catalog['total'] == sum(catalog['counts'].values())

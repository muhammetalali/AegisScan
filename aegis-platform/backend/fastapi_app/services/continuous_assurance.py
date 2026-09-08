from __future__ import annotations

from django_project.assets.models import Asset


ASSURANCE_ENGINE_CONTRACT = {
    Asset.Type.WEBSITE: ('url', 'nuclei'),
    Asset.Type.API_ENDPOINT: ('url', 'nuclei'),
    Asset.Type.IP_ADDRESS: ('ip', 'nmap'),
    Asset.Type.DOMAIN: ('ip', 'nmap'),
    Asset.Type.NETWORK_RANGE: ('network', 'masscan'),
    Asset.Type.SOURCE_CODE: ('code', 'semgrep'),
    Asset.Type.REPOSITORY: ('code', 'semgrep'),
}


def validate_assurance_engine_contract(asset: Asset, scan_type: str, engine: str) -> str:
    expected = ASSURANCE_ENGINE_CONTRACT.get(asset.type)
    if expected is None:
        return f'Continuous assurance does not support asset type {asset.type}.'
    if (scan_type, engine) != expected:
        return f'Continuous assurance requires scan_type={expected[0]} and engine={expected[1]} for asset type {asset.type}.'
    return ''

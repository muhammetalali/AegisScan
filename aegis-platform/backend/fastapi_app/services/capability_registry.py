from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .native_tool_runtime import NATIVE_TOOL_SPECS, validate_native_options


@dataclass(frozen=True)
class Capability:
    id: str
    tool: str
    category: str
    description: str
    scan_type: str
    asset_types: tuple[str, ...]
    risk: str
    source: str = 'aegisscan-native'
    execution_mode: str = 'isolated-celery'
    evidence_required: bool = True
    authorization_required: bool = True
    allowed_options: tuple[str, ...] = ()
    adapter: str = 'specialized'

    def public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data['asset_types'] = list(self.asset_types)
        data['allowed_options'] = list(self.allowed_options)
        return data


CAPABILITIES: dict[str, Capability] = {
    'network.nmap': Capability(
        id='network.nmap', tool='nmap', category='network-reconnaissance',
        description='Authorized host and network service discovery using the native Nmap adapter.',
        scan_type='ip', asset_types=('ip_address', 'domain'), risk='active-low',
    ),
    'network.masscan': Capability(
        id='network.masscan', tool='masscan', category='network-reconnaissance',
        description='Authorized high-speed network port discovery using the native Masscan adapter.',
        scan_type='network', asset_types=('network_range',), risk='active-medium',
        allowed_options=('ports', 'rate'),
    ),
    'web.nuclei': Capability(
        id='web.nuclei', tool='nuclei', category='web-vulnerability-assessment',
        description='Authorized template-driven web and API vulnerability assessment using the native Nuclei adapter.',
        scan_type='url', asset_types=('website', 'api_endpoint'), risk='active-medium',
    ),
    'code.semgrep': Capability(
        id='code.semgrep', tool='semgrep', category='source-code-analysis',
        description='Authorized static source-code analysis using the native Semgrep adapter.',
        scan_type='code', asset_types=('source_code', 'repository'), risk='passive',
    ),
}

for _id, _spec in NATIVE_TOOL_SPECS.items():
    if _id in CAPABILITIES:
        raise RuntimeError(f'Duplicate native capability id: {_id}')
    CAPABILITIES[_id] = Capability(
        id=_id,
        tool=_spec.binary,
        category=_spec.category,
        description=_spec.description,
        scan_type=_spec.scan_type,
        asset_types=_spec.asset_types,
        risk=_spec.risk,
        allowed_options=tuple(_spec.option_map),
        adapter='native-cli',
    )


def list_capabilities() -> list[Capability]:
    return sorted(CAPABILITIES.values(), key=lambda item: item.id)


def get_capability(capability_id: str) -> Capability:
    try:
        return CAPABILITIES[capability_id]
    except KeyError as exc:
        raise ValueError(f'Unknown capability: {capability_id}') from exc


def validate_capability_options(capability: Capability, options: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(options) - set(capability.allowed_options))
    if unknown:
        raise ValueError(f'Unsupported options for {capability.id}: {unknown}')

    if capability.id in NATIVE_TOOL_SPECS:
        return validate_native_options(NATIVE_TOOL_SPECS[capability.id], options)

    normalized = dict(options)
    if capability.tool == 'masscan':
        ports = str(normalized.get('ports', '1-65535')).strip()
        if not ports or len(ports) > 128 or any(ch not in '0123456789,-' for ch in ports):
            raise ValueError('Masscan ports must be a numeric port/range expression')
        try:
            rate = int(normalized.get('rate', 1000))
        except (TypeError, ValueError) as exc:
            raise ValueError('Masscan rate must be an integer') from exc
        if rate < 1 or rate > 10000:
            raise ValueError('Masscan rate must be between 1 and 10000 packets/second')
        normalized = {'ports': ports, 'rate': rate}
    return normalized


def executable_engine_names() -> set[str]:
    return {item.tool for item in CAPABILITIES.values()}

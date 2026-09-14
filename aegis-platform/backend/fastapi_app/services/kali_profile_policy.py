from __future__ import annotations

from dataclasses import dataclass


KALI_BACKEND = 'aegis-kali'


@dataclass(frozen=True)
class KaliProfile:
    name: str
    production_allowed: bool
    description: str


PROFILES: dict[str, KaliProfile] = {
    'network': KaliProfile('network', True, 'Authorized network discovery and service validation.'),
    'recon': KaliProfile('recon', True, 'Passive and bounded DNS/subdomain reconnaissance.'),
    'web': KaliProfile('web', True, 'HTTP discovery, crawling, fingerprinting and bounded web validation.'),
    'api': KaliProfile('api', True, 'Aegis-native bounded API contract and runtime conformance.'),
    'browser': KaliProfile('browser', True, 'Headless browser and SPA security observation.'),
    'code': KaliProfile('code', True, 'Source, IaC, secret and container posture analysis.'),
    'cloud': KaliProfile('cloud', True, 'Read-only cloud and Kubernetes posture collection.'),
    'binary': KaliProfile('binary', True, 'Offline binary and file metadata analysis.'),
    'crypto': KaliProfile('crypto', True, 'Reserved for approved bounded cryptographic validators; no tool is implied.'),
    'full': KaliProfile('full', False, 'CI/lab/fallback aggregation only; never a production selection.'),
}

# This is execution placement metadata, not WSTG methodology authority. New
# capabilities must be deliberately assigned; prefix guessing is forbidden.
CAPABILITY_PROFILE_MAP: dict[str, str] = {
    'network.nmap': 'network',
    'network.masscan': 'network',
    'network.rustscan': 'network',
    'network.nbtscan-host': 'network',
    'network.nbtscan-range': 'network',
    'recon.amass': 'recon',
    'recon.subfinder': 'recon',
    'recon.dnsenum': 'recon',
    'recon.fierce': 'recon',
    'web.nuclei': 'web',
    'web.httpx': 'web',
    'web.katana': 'web',
    'web.security-headers': 'web',
    'web.http-method-policy': 'web',
    'web.duplicate-parameter-semantics': 'web',
    'web.ssrf-canary-validation': 'web',
    'tls.posture': 'web',
    'web.gobuster': 'web',
    'web.dirb': 'web',
    'web.feroxbuster': 'web',
    'web.ffuf': 'web',
    'web.nikto': 'web',
    'web.waf-detection': 'web',
    'browser.dom-snapshot': 'browser',
    'browser.spa-discovery': 'browser',
    'api.openapi-contract-security': 'api',
    'api.openapi-runtime-conformance': 'api',
    'code.semgrep': 'code',
    'code.checkov': 'code',
    'code.trivy-config': 'code',
    'code.trufflehog': 'code',
    'container.trivy-image': 'code',
    'cloud.read-only-posture': 'cloud',
    'kubernetes.read-only-posture': 'cloud',
    'binary.checksec': 'binary',
    'binary.strings': 'binary',
    'binary.objdump': 'binary',
    'binary.readelf': 'binary',
    'binary.xxd': 'binary',
    'binary.gdb-metadata': 'binary',
    'binary.binwalk': 'binary',
    'forensics.exiftool': 'binary',
}


def resolve_kali_profile(capability_id: str) -> str:
    try:
        profile = CAPABILITY_PROFILE_MAP[capability_id]
    except KeyError as exc:
        raise ValueError(f'No governed Kali profile assignment for capability: {capability_id}') from exc
    policy = PROFILES.get(profile)
    if policy is None or not policy.production_allowed:
        raise ValueError(f'Capability {capability_id} resolves to a non-production Kali profile: {profile}')
    return profile


def validate_profile_policy(capability_ids: set[str]) -> None:
    mapped = set(CAPABILITY_PROFILE_MAP)
    missing = sorted(capability_ids - mapped)
    stale = sorted(mapped - capability_ids)
    if missing or stale:
        raise RuntimeError(f'Kali profile policy drift: missing={missing}, stale={stale}')
    if any(name not in PROFILES for name in CAPABILITY_PROFILE_MAP.values()):
        raise RuntimeError('Kali profile policy references an unknown profile')
    if any(name == 'full' for name in CAPABILITY_PROFILE_MAP.values()):
        raise RuntimeError('full profile cannot be assigned to a production capability')

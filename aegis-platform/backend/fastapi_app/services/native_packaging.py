from __future__ import annotations

# Every entry is backed by a command -v assertion in Dockerfile.django.
# Registry presence alone never means that a capability is executable.
PACKAGED_NATIVE_CAPABILITIES = frozenset({
    'binary.checksec',
    'binary.strings',
    'binary.objdump',
    'binary.readelf',
    'binary.xxd',
    'binary.gdb-metadata',
    'binary.binwalk',
    'forensics.exiftool',
    'network.nbtscan-host',
    'network.nbtscan-range',
    'recon.dnsenum',
    'recon.fierce',
    'recon.subfinder',
    'web.gobuster',
    'web.dirb',
    'web.ffuf',
    'web.httpx',
    'web.katana',
    'web.security-headers',
    'web.waf-detection',
    'container.trivy-image',
    'code.checkov',
    'code.trufflehog',
})


def is_packaged_native_capability(capability_id: str) -> bool:
    return capability_id in PACKAGED_NATIVE_CAPABILITIES

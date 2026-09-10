from __future__ import annotations

from .api_runtime_capability import register_api_runtime_capability
from .api_schema_capability import register_api_schema_capability
from .cloud_capability import register_cloud_capability
from .kubernetes_capability import register_kubernetes_capability

# Package declarations and runtime registrations must stay synchronized even
# when this module is imported independently by CI/reality checks.
register_api_schema_capability()
register_api_runtime_capability()
register_kubernetes_capability()
register_cloud_capability()

# Every entry is backed by a command -v assertion in Dockerfile.django.
# Registry presence alone never means that a capability is executable.
PACKAGED_NATIVE_CAPABILITIES = frozenset({
    'api.openapi-contract-security',
    'api.openapi-runtime-conformance',
    'kubernetes.read-only-posture',
    'cloud.read-only-posture',
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
    'browser.dom-snapshot',
    'container.trivy-image',
    'code.checkov',
    'code.trufflehog',
})


def is_packaged_native_capability(capability_id: str) -> bool:
    return capability_id in PACKAGED_NATIVE_CAPABILITIES

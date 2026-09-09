from __future__ import annotations

# This manifest is deliberately small and explicit. Every entry is backed by a
# command -v assertion in Dockerfile.django. Registry presence alone never
# means that a capability is executable in the scanner image.
PACKAGED_NATIVE_CAPABILITIES = frozenset({
    'binary.checksec',
    'binary.strings',
    'binary.objdump',
    'binary.readelf',
    'binary.binwalk',
    'forensics.exiftool',
})


def is_packaged_native_capability(capability_id: str) -> bool:
    return capability_id in PACKAGED_NATIVE_CAPABILITIES

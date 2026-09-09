#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <image@sha256:digest> <certificate-identity-regexp> <certificate-oidc-issuer>" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
image="$1"
identity="$2"
issuer="$3"

case "$image" in
  *@sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "image must be immutable and digest-qualified: $image" >&2; exit 65 ;;
esac

command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 69; }

verify_common="--certificate-identity-regexp=$identity --certificate-oidc-issuer=$issuer"

# shellcheck disable=SC2086
cosign verify $verify_common "$image" >/dev/null
# shellcheck disable=SC2086
cosign verify-attestation $verify_common --type cyclonedx "$image" >/dev/null
# shellcheck disable=SC2086
cosign verify-attestation $verify_common --type slsaprovenance "$image" >/dev/null

echo "verified signature, CycloneDX SBOM, and SLSA provenance: $image"

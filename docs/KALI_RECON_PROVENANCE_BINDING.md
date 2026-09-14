# Kali Recon Runtime Provenance Binding

This change hardens the existing authenticated Kali Recon provider boundary without changing capability, WSTG, Finding, Risk, Governance, or authorization authority.

When `AEGIS_RECON_PROVIDER=kali`, the Control Plane now fails closed before transport unless the complete deployment trust anchor is configured. The required anchor binds runner version, build commit, base image digest, tool manifest digest, execution image digest, and runtime manifest digest.

The authenticated provider result must then match the trusted runner/build/base/tool-manifest/runtime-manifest identities and the expected Recon profile/capability tool. The provider computes `runtime_manifest_digest` from the immutable runtime manifest it actually loaded. The execution `image_digest` is not accepted from provider self-reporting; it is projected into durable runtime provenance from the Control Plane deployment trust anchor after the provider result passes validation.

The six trust values are wired into the scanner worker Compose environment so the same contract exists in development and the merged production Compose graph. Legacy mode remains the default and does not require Kali trust pins.

`Kali Recon Provenance Binding Reality` proves both the static/negative contract and a real Control Plane-to-provider path: it builds the exact Recon image, derives exact trusted identities, starts the isolated provider, invokes production `execute_kali_recon`, verifies the trusted provenance envelope, then changes a structurally valid trusted build pin and proves fail-closed rejection.

No secret values are added to provenance or logs. This hardening does not change the default provider, dispatch additional capabilities, or expand execution scope.

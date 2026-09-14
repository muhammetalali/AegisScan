# Kali Recon Runtime Provenance Binding

This change hardens the existing authenticated Kali Recon provider boundary without changing capability, WSTG, Finding, Risk, Governance, or authorization authority.

The Control Plane now fails closed unless the authenticated provider result is internally bound to the expected Recon profile and capability tool, with structurally valid runner version, build commit, base image digest, tool manifest digest, tool version, and tool source.

Optional deployment pins may additionally bind expected runner version, build commit, base image digest, and tool manifest digest through environment configuration. No secret values are introduced or logged.

This is defense-in-depth for the existing Recon provider; it does not change the default provider, dispatch additional capabilities, or expand execution scope.

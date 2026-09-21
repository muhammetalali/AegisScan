# AegisScan Internal Production Mode

AegisScan production is an internal-only enterprise service. A production release is not required or expected to expose the application to the public Internet.

## Trust boundary

The production application origin and production SSH management endpoint must resolve exclusively to:

- RFC1918 IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or
- IPv6 Unique Local Address space (`fc00::/7`).

Mixed private/public DNS answers fail closed. Loopback, link-local, multicast, unspecified, CGNAT and globally routable addresses are not admitted as the production service or management perimeter.

## Runner boundary

Live deployment and final governance run only on a dedicated GitHub self-hosted runner carrying all of these labels:

- `self-hosted`
- `linux`
- `x64`
- `aegisscan-production`

The runner must be located inside the authorized enterprise network, resolve the private production DNS zone, reach the private SSH management endpoint and production HTTPS origin, and retain only the outbound GitHub connectivity required to operate the runner and download approved evidence/actions.

The `production` GitHub Environment remains the approval/secret boundary. A GitHub-hosted runner is not an accepted substitute for live production or final production governance.

### Runner bootstrap and liveness

The repository provides `aegis-platform/scripts/production_runner_bootstrap.sh` to provision the dedicated runner on an authorized internal Linux host. The bootstrap is fail-closed: it requires the official `actions/runner` Linux x64 archive URL, an operator-supplied SHA-256 digest, a short-lived GitHub runner registration token, and an explicit GitHub repository/organization URL. It installs the runner under a dedicated `aegisrunner` service account, registers the required `aegisscan-production` custom label, installs the runner as a systemd service, and verifies that the service is enabled and active.

The bootstrap also provisions the execution prerequisites used by the live release chain: Git, GitHub CLI, OpenSSH client tooling, and the verified runner archive's official dependency installer. The deploy workflow pins Python 3.12 with `actions/setup-python@v6` and creates an isolated venv, so acceptance does not depend on an arbitrary system Python version. Automatic runner self-update is disabled so the verified archive digest remains the installed runner provenance; runner upgrades must be performed deliberately with a newly reviewed archive digest before GitHub's supported-version window expires.

A queued `Internal Production Deploy and Acceptance` job is not production acceptance. If no online runner matches `[self-hosted, linux, x64, aegisscan-production]`, the deployment remains queued and must not be represented as deployed. Activation requests are exact-main and time bounded; if `main` advances while a deployment is queued, a fresh activation request bound to the new main SHA is required.

## Enterprise CA

The production TLS certificate must chain to the enterprise CA bundle supplied to the protected workflow as `AEGIS_PRODUCTION_ENTERPRISE_CA_BUNDLE`.

The runner materializes that bundle only in a private temporary directory and exports:

- `AEGIS_ENTERPRISE_CA_BUNDLE`
- `REQUESTS_CA_BUNDLE`
- `SSL_CERT_FILE`

The production host must be pre-provisioned with the same approved trust bundle at:

`/etc/aegisscan/enterprise-ca.pem`

Host Reality rejects a missing, empty, oversized or unparsable CA bundle before deployment. Acceptance records the CA SHA-256 and rejects a trust bundle that changes during one acceptance run. Final governance requires the CA digest used at go-live to match the digest used at final revalidation.

## Evidence contract

A successful internal go-live artifact uses `aegisscan.go-live-evidence.v3` and binds:

- exact release SHA;
- `deployment_mode=internal`;
- `network_scope=rfc1918-or-ipv6-ula`;
- the internal HTTPS origin;
- enterprise CA SHA-256;
- private SSH/origin resolution evidence;
- verified TLS and security headers;
- real black-box E2E evidence from the internal production runner;
- installed CLI evidence;
- per-file SHA-256 digests;
- Alertmanager readiness;
- remote backup health and backup identifier.

Final governance uses `aegisscan.production-governance-decision.v2` and refuses legacy public-origin evidence as an approval basis.

## Phase boundary

This contract makes the repository ready for internal production execution. It does **not** claim that a live enterprise hostname, DNS record, TLS certificate, self-hosted runner, production host/cluster, backup target, Alertmanager receiver, RPO/RTO exercise or final governance approval has already been provisioned or executed. Those require separate live acceptance evidence.

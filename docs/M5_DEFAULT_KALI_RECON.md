# M5 Governed Default Kali Recon

## Objective

M5 promotes the governed Kali Recon execution fabric from bounded canary traffic to the
production default only for capabilities with approved semantic-parity evidence.

M5 does not equate "default Kali" with unconditional routing of every Recon capability.
The trust boundary remains evidence-driven:

- **recon.fierce** is parity-approved and routes to Kali by default.
- **recon.dnsenum** is parity-approved after independent fresh-main dual-run evidence and
  routes to Kali by default.
- **recon.subfinder** is parity-approved after independent fresh-main dual-run evidence and
  routes to Kali by default.
- **recon.amass** is parity-approved after managed-engine dual-run evidence on exact PR head
  and fresh main, and now routes to Kali by default.
- non-Recon capabilities remain on their existing execution paths.

This prevents M5 from silently widening execution trust beyond evidence that has passed
exact-head PR validation and fresh-main Reality.

## Routing contract

The authoritative decision remains
**fastapi_app.services.kali_recon_provider.recon_provider_decision()**.

Modes:

- **legacy**: explicit emergency rollback; every Recon capability uses the legacy worker.
- **canary**: M4 deterministic percentage routing remains available for controlled rollout.
- **default-kali**: M5 production default. Parity-approved Recon capabilities use Kali at
  100%; unapproved Recon capabilities remain legacy-routed.
- **kali**: engineering/reality override that routes all supported Recon capabilities to
  Kali. Production preflight and production policy reject this mode.

The approved M5 set is deliberately explicit: **recon.amass**, **recon.fierce**, **recon.dnsenum**, and **recon.subfinder**.

The approved set must never be expanded solely because a tool is packaged in the Kali
profile. Admission requires independent semantic-parity evidence, a reviewed promotion
change, and fresh-main proof.

## Production default

docker-compose.prod.yml resolves the scanner worker to
AEGIS_RECON_PROVIDER=default-kali unless an operator explicitly selects a safer supported
production mode.

production_host_deploy.py also treats default-kali as its production default and activates
the kali-recon Compose profile automatically.

Development/base Compose remains legacy-default so local environments do not implicitly
require production trust pins or a Kali provider.

## Trust and provenance

Active M5 Kali execution retains all M4 trust controls:

- provider endpoint must be explicit loopback HTTP on a high port;
- provider authentication token must be a 64-character lowercase hexadecimal value;
- runner version, build commit, base image, tool manifest, execution image, and runtime
  manifest pins are mandatory;
- the selected production image must be immutable and match the expected image digest;
- the Control Plane authenticates GET /v1/runtime and validates runtime attestation before
  any scanner binary launches;
- deployment/Control Plane pins remain authoritative for image identity.

No selected Kali failure silently falls back to legacy.

## Deployment readiness

For default-kali, production execution-plane acceptance must prove from inside the real
scanner_worker that:

1. recon.fierce resolves to Kali with reason default-kali-parity-approved;
2. recon.dnsenum resolves to Kali with reason default-kali-parity-approved;
3. recon.subfinder resolves to Kali with reason default-kali-parity-approved;
4. recon.amass resolves to Kali with reason default-kali-parity-approved;
5. no governed Recon capability remains on a default-Kali legacy holdback;
6. the kali_recon service is running;
7. the provider passes authenticated runtime attestation against deployment trust pins.

Public HTTPS acceptance remains a separate application availability proof and is not used
as evidence of scanner execution-plane readiness.

## Rollback after M6

M5 originally retained explicit legacy and zero-BPS canary rollback modes. M6 retires
those routes from the current production release. Recovery now checks out a prior,
main-contained release and redeploys its compatible legacy configuration only when the
migration-safety gate permits rollback. See `M6_LEGACY_RECON_RETIREMENT.md`.

## Reality proof

M5 Default Kali Reality must prove on the exact PR/main SHA:

1. default-Kali routing and task integration contracts;
2. only parity-approved Recon capabilities can enter Kali under M5 default routing;
3. raw kali mode is rejected by production preflight/policy;
4. production Compose resolves to default-kali with an immutable bound Kali image;
5. exact legacy and exact governed Kali Recon images build successfully;
6. deterministic authorized DNS fixture execution;
7. real recon.fierce execution through the production Kali provider client;
8. real recon.dnsenum execution through default-kali is proven by Recon DNSenum Parity Reality;
9. real recon.subfinder execution through default-kali is proven by Recon Subfinder Parity Reality;
10. real recon.amass execution and managed-engine parity are proven by Recon Amass Parity Reality;
11. real legacy rollback execution remains available as an explicit emergency mode;
12. non-empty normalized observations from compared execution paths;
13. semantic equivalence remains green for every admitted capability;
14. runtime provenance is bound to the exact immutable image and deployment trust anchor;
15. zero remaining default-Kali Recon holdbacks and explicit legacy rollback are captured in evidence.

## Non-goals

M5 does not:

- retire the legacy native worker;
- bypass parity evidence when admitting future Recon capabilities;
- allow raw kali override in production;
- silently fall back after a selected Kali execution failure;
- begin M6 Legacy Retirement.

## Exit gate

M5 is complete only after:

- routing, task, production preflight, policy, deployment, and Compose contracts are green;
- real default-Kali and real legacy rollback executions are proven;
- semantic parity remains green for every default-Kali admitted capability;
- every approved capability promotion is independently proven on exact PR head and fresh main;
- exact PR head is terminal green and behind=0;
- the PR is merged using the verified expected-head SHA;
- fresh exact-main M5 Default Kali Reality and all mandatory release workflows are
  terminal green;
- exact-main M5 artifacts are inspected and bound to the current main SHA.

All current Recon capabilities are parity-admitted to default-Kali. M6 adds the separately
proven production retirement lock and stripped scanner image.

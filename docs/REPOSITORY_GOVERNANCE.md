# AegisScan Repository Governance

## Scope

This contract governs release integration into `main`. It does not own scanner, Kali, parity, canary, WSTG native execution, or security-engine runtime implementation.

## Main integration policy

`main` is the release integration line and must be protected by an active repository ruleset. The normative machine-readable target configuration is `.github/governance/main-ruleset-spec.json`.

Mandatory invariants:

- integration into `main` occurs through a pull request;
- force pushes are prohibited;
- deletion of `main` is prohibited;
- unresolved review threads block integration;
- the branch must be current before the required CI gate can pass;
- the required status context is `Aegis Required CI Governance`;
- the ruleset has no bypass actors;
- ruleset drift is a release-governance failure.

The approval count is intentionally `0` in the initial ruleset because the repository currently has a single administrative owner and a mandatory independent approval would create an integration deadlock. The pull-request requirement and review-thread-resolution requirement still apply. When a second trusted maintainer is available, governance should be revised in a dedicated PR to require at least one independent approval.

Signed-commit enforcement is intentionally not enabled in this first ruleset. Release provenance and supply-chain signing remain mandatory, but repository commit-signature enforcement should only be activated after every automated commit actor used by the project has been proven compatible; enabling it speculatively could deadlock release integration.

## Administrative activation

Repository rulesets require GitHub repository-administration write permission. AegisScan keeps the desired state in source control and provides an idempotent applicator at `scripts/admin/repository_ruleset_admin.py`.

The applicator never accepts a token value as a command-line argument and never persists credentials. Supply an administrator-scoped token through the `AEGIS_GITHUB_ADMIN_TOKEN` environment variable and run:

```bash
AEGIS_GITHUB_ADMIN_TOKEN='<admin-token>' \
python3 scripts/admin/repository_ruleset_admin.py \
  .github/governance/main-ruleset-spec.json \
  --repo muhammetalali/AegisScan \
  --mode apply
```

The operation is idempotent: it creates the named ruleset if absent, updates that exact named ruleset if present, refuses duplicate rulesets with the same name, and immediately verifies both the stored ruleset and the effective rules on `main`. A read-only verification can be performed with `--mode verify`. The token must never be committed, echoed into CI logs, or stored in repository fixtures.

The normal GitHub Actions `GITHUB_TOKEN` is intentionally not granted repository-administration permission. GitHub may therefore omit administrator-only fields such as `bypass_actors` from ruleset-detail responses inside CI. The Reality workflow still validates branch protection, the exact active named ruleset, its target, mandatory rule types, pull-request parameters, strict required checks, and effective rules. When `bypass_actors` is visible it must be an empty list; when GitHub redacts it, the workflow records `bypass_actor_visibility=permission_limited` instead of manufacturing a false proof. A-01 closure and any administrative ruleset change additionally require an administrator-scope live verification through the applicator or equivalent GitHub administration evidence. The admin applicator remains fail-closed and requires `bypass_actors=[]`.

## Required CI policy

AegisScan does not mark every workflow as an unconditional GitHub required check. Several Reality workflows are path-filtered, so doing that would leave unrelated pull requests permanently waiting for checks that GitHub never schedules.

Instead, `.github/workflows/required-ci-governance.yml` emits one unique status check, `Aegis Required CI Governance`. Its verifier:

1. binds to the exact pull-request or `main` SHA;
2. requires the always-on core Reality workflows;
3. derives path-sensitive mandatory workflows from `.github/governance/required-ci-policy.json`;
4. observes every other pull-request/push workflow that GitHub actually schedules for that exact SHA;
5. fails immediately if any observed workflow completes with a non-success conclusion;
6. waits for all mandatory workflows to appear and finish;
7. requires a quiescence window before publishing success, reducing late-scheduling races.

The core pull-request set currently includes:

- Domain Contract Reality;
- Security Reality Check;
- Canonical Source Tree Reality;
- Native Capability Reality;
- Risk Correlation Acceptance;
- Risk Decision Lineage Reality;
- Remediation Verification Lineage Reality.

Critical path-sensitive gates include External Black-Box E2E, Production Runtime Reality, Supply Chain Release, and Scanner Crash Recovery Reality. Scanner/engine-specific Reality workflows introduced by the execution-fabric owner are also fail-closed when they are triggered because all scheduled workflows are observed by the governance gate.

## Reality proof

`.github/workflows/repository-governance-reality.yml` has two modes:

- Pull requests validate the proposed ruleset contract, permission-regression behavior, and dry-run the administrative payload without pretending the currently protected branch's administrator-only fields are visible to Actions.
- Every push to `main`, plus manual dispatch, queries GitHub for the live branch and applicable repository rules and fails closed unless protection, PR-only integration, force-push protection, deletion protection, strict status checks, and the required governance context are active.

A repository-governance phase is not closed merely because these files exist. Closure requires a live active ruleset, administrator-scope proof that no bypass actors exist, and a green `Repository Governance Reality` run against the exact protected `main` SHA.

## Change ownership and collision control

Repository governance is owned by Chat A. Execution-fabric work owned by Chat B must not be modified from governance PRs. Before changing shared workflow or root configuration files, the current open PRs and changed-file sets must be inspected. A shared file already modified by the other workstream is locked until that work is merged or the governance change is redesigned to avoid the collision.

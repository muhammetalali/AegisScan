# G5–G6 controlled execution — 2026-11-07

**State:** prepared read-only evidence collection; **NOT** G5 acceptance.
**Protected baseline:** `bd75f136892e241bfafe805165e1e8563e8481a0`.
**Issue reuse:** [G5 #470](https://github.com/muhammetalali/AegisScan/issues/470), [G4 #440](https://github.com/muhammetalali/AegisScan/issues/440), [G6 #471](https://github.com/muhammetalali/AegisScan/issues/471).

## Established production facts (read-only host checks)
- Existing `aegis-remote-backup` runs `remote_backup_service.py schedule` without restarting; `AEGIS_BACKUP_INTERVAL_SECONDS=86400` (sleeps for 24h **after success completion**).
- Current schedule instance at observation: `1e920814f874ee0a3bddf3064ff19ec4e9eda097150bd94898e0ac17724eb3f5`; started 2026-11-06 13:08:41 UTC.
- First actual schedule-container backup: `20261106T130851Z-6fc685c45c92f908`, completed 2026-11-06 13:09:05 UTC. **Distinct** from workflow-triggered backup `20261106T222502Z-67636e4a6a30312a`.
- The second scheduled event was **not observed** when this change was prepared. Anticipated opportunity is around 2026-11-07 13:09 UTC if this process survives. Existing daily G5 monitoring at 17:30 Europe/Istanbul should be reused, not duplicated.
- 23 running containers, 0 unhealthy, 56 volumes retained; no prune. Corrected volume inventory says 9 attached.
- Existing evidence evaluator `scripts/ci/g5_g6_evidence_acceptance.py` stays authoritative and fail-closed. G5 PARTIAL, G6 BLOCKED_SOURCE, `project_complete=false`.

## P0 — original Docker scheduler evidence (this PR)

After an approved protected merge and deployment, run the collector on the **matching** exact-release host. It only reads selected Git/Docker metadata and Docker scheduler stdout; it does **not** trigger backups, create a scheduler, restart a service, remove volumes, access credentials or scan external targets.

```bash
python3 scripts/ci/g5_schedule_runtime_receipt.py \
  --expected-release-sha 'REPLACE_WITH_EXACT_DEPLOYED_40_CHAR_SHA' \
  --output /home/aegisadmin/aegis-acceptance-evidence-20261010/g5-schedule-UNIQUE-UTC.json
```

The output is exclusive-create and mode 0600, with a SHA-256 printed to stdout. `PARTIAL_NEEDS_TWO_CYCLES` is an expected exit 2 if only one real event exists. `CANDIDATE_TWO_CYCLES` (exit 0) is **candidate evidence only**, never a substitute for independent rechecking the matching container daemon log and object versions.

The collector fails closed for wrong release, dirty checkout, wrong Docker command, container restart, wrong interval, replayed backup ID, or insufficient distinct manifest/object versions. It records failures as a count, not raw potentially sensitive log lines. It refuses to relabel a manual `once` backup as `schedule`.

## P1 — restore latest scheduled backup

Use the existing version-aware PostgreSQL restore mechanisms, not a second restore service. Independent approval and disposable isolation are prerequisites. Verify latest scheduled backup ID, version IDs, source digest, restored tables and no production mutation. The already-proved workflow-triggered PostgreSQL restore does **not** satisfy the latest-scheduled recovery gate.

## P2 — independent full-platform disaster recovery

**Still OPEN:** provision or identify a separate approved isolation boundary, pinned images/release, resource capacity, restricted credentials/egress, functional verification and cleanup rollback. Recover **postgres, redis, django, fastapi, scanner, frontend**. An existing isolated PostgreSQL restore plus a production FastAPI restart are not complete six-service recovery.

## P3 — numerical RPO/RTO and human approval

**Still OPEN:** the accountable human owner must approve and sign numeric bounds; engineering must capture independently verified actual data-loss and complete-service-recovery times. Never infer owner-approved numbers from the 24h backup schedule.

## P4–P7 dependency queue

- **P4 G4:** keep verified deployed DDNS source/runtime sync. Only perform controlled NIC/DHCP transition with independent rollback; prove revoked-but-unexpired TLS rejection, Firefox UAT and portable successor CA escrow restore.
- **P5 G2:** real owner, second manager, employee and viewer authorized sessions, viewer mutation denial, cross-tenant isolation and actor-attributed audit evidence.
- **P6 G3:** authorized local fixture full Scan → Finding → Evidence → Remediation → Verification → Report flow. Real Burp/Academy interaction requires independent permission and compliance with provider terms; no implicit external-scanning authorization.
- **P7 G6:** obtain owner-authenticated **literal original 107 requirements** with provenance and separate preserved **100 decisions**, independently map both against exact-release production proof, then obtain human sign-off. Do not fabricate requirements.

## Change control

Submit draft PR → targeted tests and CI → review → protected merge → protected deploy → exact-host verification → independent operational UAT. Do not patch current production directly or close any issue based on code/CI alone. Retain all existing backups, Docker volumes, rollback images, CA material and production datasets.

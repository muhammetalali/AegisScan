# Public CA revocation and issuer artifacts (G4)

This directory is mounted **read-only** into the existing Nginx container.
No signing keys, passphrases, CA issuance database, or private TLS keys belong here.

The only intentionally exposed URLs are:

- `http://aegis-prod.aegis.internal/pki/aegisscan-root-ca.crl`:
  **DER-encoded**, authentic root-CA-signed complete CRL, when approved.
- `http://aegis-prod.aegis.internal/pki/aegisscan-root-ca.cer`:
  **DER-encoded** public issuer certificate, when approved.

Until these files exist, the exact endpoints return **404**, not a false
empty or unsigned revocation document. The rest of plain HTTP redirects to
HTTPS as before.

## Admission before publishing

1. Reconcile authoritative CA issuance and revocation history; do **not**
   initialize a fake empty index or assert an unrecorded serial is unrevoked.
2. Produce and verify the root-signed CRL only on the protected CA host,
   with valid `thisUpdate`, `nextUpdate`, and verified issuer signature.
   Publish DER bytes only after verifying its issuer and freshness; schedule
   renewal with monitoring and fail-closed expiry alerts.
3. Confirm the publicly served DER root certificate matches the already
   trusted original CA fingerprint; never substitute a new unapproved root.
4. Reissue the leaf with a CDP pointing at the exact CRL HTTP URI and
   appropriate CA Issuers AIA pointing at the exact DER issuer URI.
5. Accept unmodified Windows Schannel/Firefox HTTPS and controlled network
   failover before closing G4. No `-k`, revocation disablement or static IP.

## Fail-closed cryptographic admission before publication

After an authorized CA history/revocation audit **and before** copying any
signed public DER artifacts to the production mount, stage the two DER files in
a separate non-production directory (for example a root-controlled staging
path), then run:

```bash
python3 aegis-platform/scripts/production_internal_pki_verify.py \
  --root-cert /usr/local/share/ca-certificates/aegisscan-enterprise.crt \
  --public-dir /path/to/staged/public-der
```

The verifier is **read-only** and must return `G4_PUBLIC_PKI_CRYPTO=PASS`
before any controlled publication. It checks the original **pinned** public
root fingerprint, byte-for-byte DER issuer identity, the CRL signature,
`thisUpdate`/`nextUpdate` freshness, path and permissions, and rejects
symlinks, unexpected artifacts, and absent/malformed/replaced files. It
**never opens the CA signing key**, builds the CA index, creates or renews a
CRL, changes the trust store, or changes Nginx.

**Even a cryptographically valid CRL does not prove the lost original
CA issuance/revocation history.** The tool always reports
`HISTORICAL_CA_ISSUANCE_AND_REVOCATION_LEDGER=NOT_VERIFIED`
and `PRODUCTION_PKI_ACCEPTANCE=NOT_IMPLIED`.
If the authoritative historical register cannot be reconstructed with
evidence, do **not** treat `PASS` as permission to claim that old serials
are unrevoked. Follow a separately approved CA/trust rollover instead.
The actual production directory remains unchanged/HTTP 404 until that
independent historical governance gate has passed.

## Public artifact filesystem access

Only this **public artifact directory** must be traversable by the Nginx
worker (typically host directory `0755`, with approved DER files `0644`);
a directory mode such as `0700` returns HTTP 403 even for correctly mapped
files. Keep the volume read-only in Compose. The **issuer signing key remains
in its separate root-only `0600` store** and must never be copied here.

The signed public CRL and issuer certificate are intentionally ignored by
Git and are not tracked as source. Publishing or rotating them is a separate
root-controlled operational change with retention, rollback and audit proof.

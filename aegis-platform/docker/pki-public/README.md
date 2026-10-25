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

The signed public CRL and issuer certificate are intentionally ignored by
Git and are not tracked as source. Publishing or rotating them is a separate
root-controlled operational change with retention, rollback and audit proof.

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

## G4 approved-path preparation: historical CA recovery or bounded trust rollover

The prior production CA's issuance/revocation ledger remains **NOT_VERIFIED**.
Existing authenticated object-locked backups are **PostgreSQL** dumps, not
evidence that the original CA issuance ledger can be reconstructed. Do not
declare the old root's unknown certificate serials safe, create an empty
`index.txt` for it, or generate a clean CRL against guessed history.

A new CA rollover must be treated as a **distinct, documented trust identity**,
not as a silent overwrite of the pinned original issuer. Keep old trust
and current production TLS working until live cutover is accepted.

### Preparation and acceptance order (no automatic production changes)

1. **Provenance and scope:** record independently approved CA replacement,
   enumerate every known old-root-signed server/client certificate and relying
   client (Windows Schannel, Firefox/NSS, Ubuntu and internal workers), the
   canonical DNS name, and offline recovery media. Identify any undiscovered
   relying parties as an explicit blocker; do not assert a complete ledger from
   the existing `.srl` alone.
2. **Root-of-trust custody:** create new key material only in a separately
   approved restricted CA environment with an independently recoverable
   encrypted backup, restricted operator access, protected audit trail, fresh
   serial/index/revocation ledger, CRL numbering, renewal/expiry alerting and
   documented key-rotation/revocation policy. Do not place CA keys, the index,
   passphrases or issuance scripts in Git, Nginx's public mount or Windows
   client machines. Do not reuse the old root's distinguished name or trust
   fingerprint when that could disguise the rollover.
3. **Stage new public identity separately:** plan **versioned, distinct**
   issuer and CRL HTTP paths for the new CA. The current exact-path Nginx
   routes and the `ORIGINAL_ROOT_FINGERPRINT` guard are exclusively for the
   old root and MUST NOT be pointed to substituted new-root bytes. Before a
   live change, review a minimal, fail-closed extension of the **existing**
   Nginx allowlist and artifact verifier; do not introduce another reverse
   proxy, trust-bypass service or parallel authorization mechanism.
4. **Offline PKI evidence:** produce an actual signed new-CA CRL from the
   complete new ledger; preserve `thisUpdate/nextUpdate`, CRL number,
   issuer identity, DER SHA-256 and verification output. Issue the new leaf
   with only the stable DNS SAN, correct serverAuth/keyUsage, and new-version
   HTTP CDP and CA Issuers AIA endpoints. Validate the leaf's chain and a
   **positive non-revoked** as well as a **negative revoked** certificate
   against the *same* signed CRL. See
   `tests/test_internal_pki_publication.py` for test-only synthetic
   revocation rehearsal; a test pass is **not production issuance**.
5. **Dual trust before switch:** validate the exact new public CA fingerprint
   independently, then provision scoped Windows/Firefox/Ubuntu trust without
   deleting the original trusted CA. Only after the public DER endpoints
   return authentic parseable artifacts (no HTML-SPA 200 fallback, no
   `-k`, no disabled CRL checks), stage the leaf swap through the existing
   protected deploy/rollback path with prior encrypted recovery evidence.
6. **Live acceptance:** native Windows `Resolve-DnsName`, unmodified Schannel
   `curl.exe https://aegis-prod.aegis.internal/readyz` HTTP 200 with
   revocation enabled, authorized Firefox owner login, verification that a
   revoked test leaf is rejected by the intended client, backend readiness,
   backups and end-to-end scans on the unchanged authorized scope. Conduct
   real bounded DHCP/NIC/Wi-Fi/Ethernet/VMware route transitions with
   measured recovery and explicit fail-closed behavior. Record exact
   production SHA, tests and rollback proof.
7. **Retire old trust only after evidence:** account for all known old-root
   clients/certificates and obtain explicit owner final acceptance. If
   certificate/status validation or connectivity fails, restore the previous
   exact cert/config and keep the still-valid old root while investigating.

**G4 stays PARTIAL** until all live criteria succeed. An offline synthetic
test cannot validate Windows Schannel, browser state, historical CA
completeness, DHCP roaming or production availability.

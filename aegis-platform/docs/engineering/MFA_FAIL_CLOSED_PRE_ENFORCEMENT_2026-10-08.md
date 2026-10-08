# AegisScan MFA state — 2026-10-08

## Scope: defensive mitigation only

- The currently exposed Django login endpoint issues cookie JWTs through
  `TokenObtainPairSerializer`, and `users.User` already stores
  `two_factor_enabled` and `two_factor_secret`.
- There is no proven TOTP/WebAuthn challenge, enrollment and recovery contract,
  anti-replay ledger, or login second-factor verification route.
- Therefore: **a password alone must not issue JWTs for accounts marked MFA
  enabled**. A targeted pre-token validation now refuses login for such
  accounts, preserving ordinary password login for accounts not so marked.
- A wrong password remains HTTP 401 with no MFA disclosure; a correct
  password on a flagged account returns HTTP 403 with no JWT cookies. The
  authentication audit records the refused login.
- This policy deliberately protects a previously silent flag. It **does not
  constitute completed or usable MFA**. Do not enable the flag until a real
  second-factor flow exists.
- Production count of active enabled-MFA users was 0 at the read-only
  2026-10-08 inspection; this is not a license to assume zero forever.

## Required before closing issue #345

1. Strong TOTP or WebAuthn enrollment and verifier with encrypted secrets;
   protected enrollment confirmations and reliable offboarding.
2. Short-lived pre-auth challenge bound to user, expiry, browser/client and
   rate limits; JWT access/refresh cookies only after passing MFA.
3. One-time recovery codes, anti-replay counters, lockout audit, revocation,
   session/JWT invalidation and supportable administrator recovery.
4. Password-only denial, replay/expired/drift, brute force, CSRF, login,
   refresh/logout and multi-role integration tests.
5. Exact-SHA full CI, explicit reviewed production rollout and real-browser
   second-factor acceptance. Keep issue #345 open until these are proven.

This document is a gated security note, not a final implementation claim.

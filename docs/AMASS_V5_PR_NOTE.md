# Amass v5 parity PR verification note

Base at branch creation: `main@95a176d2dfe8188df6b32c6f0c37c8373c10ee0d`.

This branch intentionally repairs Amass v5 evidence semantics and its local Engine authorization boundary before any production routing promotion. `recon.amass` must remain on the Legacy path under `default-kali` until exact-head and fresh-main real dual-run evidence both pass.

The release gate is:

1. exact-source patched Amass v5.1.1 builds in both Legacy and Kali images;
2. unit/contract gates pass;
3. unauthenticated/wrong-token Engine access is rejected and authenticated health succeeds;
4. Docker-internal HackerTarget fixture is proven deterministic;
5. real Legacy and explicit engineering-Kali executions produce non-empty expected observations;
6. semantic parity reports no mismatch;
7. all exact-head mandatory CI is terminal green;
8. branch is not behind main;
9. merge uses the exact reviewed head;
10. fresh-main repeats Contract and Real Reality successfully before a separate promotion PR is allowed.

# G3 — Burp BApp supplier integrity preflight (not approval)

This stage **does not launch Burp, send HTTP traffic, create approval records, or deploy Ubuntu**. Its purpose is to make structural artifact evidence reproducible and prevent a ZIP hash, signature blob, or untrusted source checkout from being treated as supplier authorization.

## Exact observed candidate — PortSwigger MCP Server 1.4.0, serial 12

- Official BApp Store identifier: 9952290f04ed4f628e624d0aa9dccebc.
- BApp SHA-256: fe7b40d5b5ed13ab6e40907bddef5df4f4a0685de13cff13f416acac8e4c045d.
- BappSignature.sig SHA-256: 926bf1686b88ef5ba9ae784e8d18f797e18aa08f5e325d127ad25accf4e8cf63.
- Source tree: PortSwigger/mcp-server commit 291034081160bc944b6df3eccd60c6fc99b477e1; its BApp manifest was byte-equal to the downloaded archive.
- JAR manifest version: 1.4.0. The embedded Gradle Built-Date is variable; reproducible source builds have not been proven.

Invoke the offline checker against the locally obtained candidate and reviewed source manifest with:

    python3 scripts/ci/bapp_supplier_preflight.py \
      --archive "$BAPP_ARCHIVE" \
      --expected-archive-sha256 fe7b40d5b5ed13ab6e40907bddef5df4f4a0685de13cff13f416acac8e4c045d \
      --expected-signature-sha256 926bf1686b88ef5ba9ae784e8d18f797e18aa08f5e325d127ad25accf4e8cf63 \
      --source-manifest "$PINNED_SOURCE_MANIFEST" \
      --expected-uuid 9952290f04ed4f628e624d0aa9dccebc \
      --expected-version 1.4.0 --expected-serial 12 \
      --output "$PRIVATE_NEW_OUTPUT_PATH"

Use a new output path for each receipt, never overwrite previous evidence. No archive is extracted or executed. CI exercises altered hashes, missing signatures, altered source, duplicate ZIP entries, symlinks, unsafe paths, suspicious compression ratios and inconsistent versions.

## Uncrossed independent acceptance gates

1. **Signature authenticity:** obtain and authenticate the PortSwigger publisher verification key or authoritative documented verification method; verify the real BApp signature cryptographically against its exact covered bytes.
2. **Dependency/provenance evidence:** require authenticated artifact-bound supplier SBOM, build provenance and a credible critical-vulnerability review.
3. **Reproducibility:** independently rebuild and evaluate normalized binary equivalence. Gradle's volatile Built-Date prevents assuming byte-identical builds.
4. **Owner and enterprise authorization:** only after objective evidence passes may authorized owners issue current tenant/capability/version-scoped approved/trusted decisions. Existing provider_approval.py stores applicant-supplied signature_verified, SBOM and provenance flags; those booleans are not independently validated as publisher facts.
5. **Governed local execution:** use the existing Scan -> Celery -> Burp MCP -> Evidence -> Independent Verification -> Remediation -> Report workflow on an owned resettable vulnerable/patched fixture. Do not claim new solved Academy/Cyberpedia labs without genuine verified results and required external permissions.

Even with archive integrity verified, the preflight's governance.admission is **BLOCKED**. Merge source prep under protected GitHub CI, then request **one** protected Ubuntu deployment only after all remaining implementation/acceptance obligations for G3 are ready. Never reuse expired or mismatched deploy requests.

## Additional G3.2 preliminary dependency evidence (not a vendor SBOM)

The offline checker also enumerates embedded JAR Maven metadata using only the
bounded META-INF/maven/<group>/<artifact>/pom.properties entries. It requires
consistent group/artifact paths, safe coordinate strings, unique components,
strict property structure, and deterministic sorting. Records include Maven
package URLs and exact properties hashes, anchored in the pinned BApp archive
digest. **This inventory is incomplete by design:** shaded libraries, missing
pom.properties, custom native dependencies and internal modules may be absent.
It is not an authenticated vendor SBOM, not a vulnerability clearance, and
cannot promote approved/trusted. A complete independently reviewed supplier
SBOM/provenance and authenticated vendor signature remain required.

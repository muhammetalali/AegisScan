# WSTG v4.2 canonical catalog

PR-1 introduces read-only methodology metadata under the canonical backend.
JSON is used for the proposed methodology pack so the loader can reject duplicate
keys and validate records without a new YAML parsing dependency.

The pack has exactly 97 official tests across 12 categories. The approved matrix's
per-test classifications remain 25 AUTO_EXISTING, 45 ASSISTED_EXISTING,
21 MANUAL_GOVERNED, 5 GAP_NATIVE_SMALL and 1 CONDITIONAL_NA. These are design
classifications, never execution results or claims that an asset passed a test.
Eight extensions have an AEGIS-EXT namespace and are excluded from official totals.

The upstream v4.2 commit is pinned. Every record includes its document path and
SHA256. INPV-13 refers to Format String Injection. The upstream Buffer Overflow
file contains only a removal notice with the same ID and is excluded. SQL and
code-injection subchapters do not become additional official test IDs.

## Consumer contract

```python
from fastapi_app.services.wstg_catalog import WSTGCatalog

catalog = WSTGCatalog()
test = catalog.resolve('WSTG-v42-INFO-02')
assert test == catalog.resolve('WSTG-INFO-02', version='4.2')
```

Unversioned legacy identifiers require an explicit version. Unknown versions,
unknown identifiers, extension IDs in official lookups, invalid checksums and
unexpected record fields fail closed. Records are frozen Pydantic contracts.

## Existing components and ownership

The existing capability_registry remains authoritative for execution capabilities.
The compliance importer remains authoritative for compliance framework persistence;
WSTG metadata does not introduce a second database or claim to be a compliance
assessment. Existing Evidence, ScanEngineExecution and Governed Action Executor
remain the integration targets. PR #105 was verified merged into the initial
base b098aa44c09af8d80effd1b8954b67e4c3bf1c5f; finding.confirm and finding.close
already delegate to the existing governed services.

The user's current ownership/order supersedes numbering in the design report:
PR-1 catalog, PR-3 capability mapping, PR-7 applicability/planner, PR-9 projection,
PR-10 UI/reporting/E2E. Account B owns Kali execution and PR-8 native validators;
the main account owns contracts and integration. No Account B capability is
accepted by this catalog change.

## Validation and limits

Run from repository root:

```bash
PYTHONPATH=aegis-platform/backend python -m unittest fastapi_app.services.test_wstg_catalog -v
python aegis-platform/backend/scripts/wstg_catalog_reality.py --upstream /path/to/pinned/wstg
```

WSTG Catalog Reality runs at the exact PR head and compares every record with a
clean checkout of the pinned OWASP release. It captures pack fingerprints and the
tested Aegis commit. Negative tests exercise duplicate/missing records, ambiguous
legacy IDs, corrupted metadata and attempted execution fields. A separate digest
locks the 97 approved ID/classification pairs against swaps that preserve totals.

This PR changes no REST API, database schema, scan dispatch, authorization,
finding lifecycle or runtime backend. Capability mappings, applicability decisions,
observation/evidence projection and coverage UI belong to subsequent PRs. Catalog
validation does not constitute security execution, Kali parity or production E2E
proof. The complete integration remains unclosed until those stages pass.

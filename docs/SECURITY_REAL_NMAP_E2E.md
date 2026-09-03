# Real Nmap E2E Security Gate

This stage proves the supported network-scan execution chain against a controlled loopback target.

## Contract

The regression must establish all of the following in one real execution:

`persisted authorized asset -> network Scan -> real Celery task invocation -> real nmap binary -> XML parsing -> persisted Evidence -> persisted ScanEngineExecution -> completed Scan`

The CI target is `127.0.0.1`, which is explicitly allow-listed through `AUTHORIZED_SCAN_TARGETS` for the test job. This is a controlled local target and does not depend on an external host.

The test rejects synthetic success by asserting real Nmap output is present, the parser discovers at least one host, the execution records completion, and the Evidence SHA-256 matches the persisted raw output.

## Security boundary

The real task still requires an explicitly authorized asset and server-side target scope before tool execution. Unsupported or unauthorized targets must fail rather than produce fabricated findings.

## Scope limitation

This proves the real Nmap execution path and evidence persistence on the controlled loopback target. It does not claim production-wide scanner/provider completeness, remote infrastructure coverage, Masscan support, or end-to-end frontend rendering.

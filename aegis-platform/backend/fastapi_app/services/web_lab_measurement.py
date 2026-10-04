from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from typing import Any

CASE_SCHEMA = "aegis.web-lab-measurement-case.v1"
REPORT_SCHEMA = "aegis.web-lab-measurement-report.v1"
PLAN_SCHEMA = "aegis.web-labs-p6-plan.v1"
RECIPE_REVISION = "aegis.web-labs-p6-recipes.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")


class MeasurementError(ValueError):
    pass


def _text(value: Any, field: str) -> str:
    value = str(value or "").strip()
    if not value:
        raise MeasurementError(f"{field} is required")
    return value


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MeasurementError(f"{field} must be a finite non-negative number")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise MeasurementError(f"{field} must be a finite non-negative number")
    return number


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MeasurementError(f"{field} must be a non-negative integer")
    return value


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def validate_plan(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schema") != PLAN_SCHEMA:
        raise MeasurementError("unknown P6 plan schema")
    if raw.get("recipe_revision") != RECIPE_REVISION:
        raise MeasurementError("unexpected P6 recipe revision")
    definition_id = _text(raw.get("definition_id"), "definition_id")
    if definition_id != "bac-orders-v1":
        raise MeasurementError("P6 is sealed to definition_id bac-orders-v1")
    expected_metrics = [
        "duration_ms",
        "cpu_seconds",
        "peak_memory_bytes",
        "external_requests",
        "human_interventions",
    ]
    if raw.get("resource_metrics") != expected_metrics:
        raise MeasurementError("P6 resource_metrics must match the sealed contract")
    limits = raw.get("release_claim_limits")
    expected_limits = {
        "production_deployment": False,
        "provider_production_approval": False,
        "arbitrary_academy_solver": False,
        "additional_vulnerability_families": False,
    }
    if limits != expected_limits:
        raise MeasurementError("P6 release claim limits must remain fail-closed")
    rows = raw.get("cases")
    if not isinstance(rows, list) or not rows:
        raise MeasurementError("P6 plan requires cases")

    seen: set[str] = set()
    normalized = []
    for row in rows:
        if not isinstance(row, dict):
            raise MeasurementError("P6 plan case must be an object")
        case_ref = _text(row.get("case_ref"), "case_ref")
        if case_ref in seen:
            raise MeasurementError("duplicate P6 plan case_ref")
        seen.add(case_ref)
        split = row.get("split")
        scenario = row.get("scenario")
        variant = row.get("variant")
        expected = row.get("expected_verdict")
        if split not in {"baseline", "held_out"}:
            raise MeasurementError("invalid plan split")
        if scenario not in {"nominal", "disconnect"}:
            raise MeasurementError("invalid plan scenario")
        if variant not in {"vulnerable", "patched"}:
            raise MeasurementError("invalid plan variant")
        if expected not in {"vulnerable", "not_vulnerable", "indeterminate"}:
            raise MeasurementError("invalid expected verdict")
        if scenario == "disconnect" and expected != "indeterminate":
            raise MeasurementError("disconnect plan case must expect indeterminate")
        normalized.append(
            {
                "case_ref": case_ref,
                "split": split,
                "scenario": scenario,
                "variant": variant,
                "expected_verdict": expected,
            }
        )

    required = {
        ("baseline", "nominal", "vulnerable", "vulnerable"),
        ("baseline", "nominal", "patched", "not_vulnerable"),
        ("held_out", "nominal", "vulnerable", "vulnerable"),
        ("held_out", "nominal", "patched", "not_vulnerable"),
        ("held_out", "disconnect", "vulnerable", "indeterminate"),
    }
    actual = {
        (x["split"], x["scenario"], x["variant"], x["expected_verdict"])
        for x in normalized
    }
    if not required <= actual:
        raise MeasurementError("P6 plan is missing a required measurement class")
    if actual != required or len(normalized) != len(required):
        raise MeasurementError("P6 plan must contain exactly the five sealed measurement classes")
    return {**raw, "definition_id": definition_id, "cases": normalized}


def case_from_proof(
    *,
    plan_case: dict[str, Any],
    proof: dict[str, Any],
    proof_sha256: str,
    source_commit: str,
    fixture_image_id: str,
    scanner_image_id: str,
    metrics: dict[str, Any],
    definition_id: str,
) -> dict[str, Any]:
    if not _SHA256.fullmatch(str(proof_sha256 or "")):
        raise MeasurementError("proof_sha256 must be sha256 hex")
    if proof.get("source_commit") != source_commit:
        raise MeasurementError("proof source SHA mismatch")
    scenario = plan_case.get("scenario")
    variant = plan_case.get("variant")
    if proof.get("variant") != variant:
        raise MeasurementError("proof variant does not match sealed case")

    if scenario == "nominal":
        if proof.get("schema") != "aegis.burp-live-lab-verification-proof.v1" or proof.get("status") != "pass":
            raise MeasurementError("nominal case requires a passing live verification proof")
        verdict = proof.get("verdict")
        if not isinstance(verdict, dict):
            raise MeasurementError("live verification proof is missing verdict")
        if verdict.get("definition_id") != definition_id:
            raise MeasurementError("proof definition does not match sealed plan")
        evidence_refs = proof.get("evidence_refs")
        row = {
            "observed_verdict": verdict.get("verdict"),
            "finding_present": bool(verdict.get("finding_present")),
            "lab_solved": bool(verdict.get("lab_solved")),
            "claim_state": "committed",
            "fixture_revision": verdict.get("fixture_revision"),
            "instance_ref": verdict.get("instance_ref"),
            "process_ref": verdict.get("process_ref"),
            "evidence_refs": evidence_refs,
        }
    else:
        if proof.get("schema") != "aegis.web-lab-disconnect-proof.v1" or proof.get("status") != "pass":
            raise MeasurementError("disconnect case requires a passing disconnect proof")
        if proof.get("definition_id") != definition_id:
            raise MeasurementError("disconnect proof definition does not match sealed plan")
        row = {
            "observed_verdict": proof.get("verdict"),
            "finding_present": bool(proof.get("finding_present")),
            "lab_solved": bool(proof.get("lab_solved")),
            "claim_state": proof.get("claim_state"),
            "fixture_revision": proof.get("fixture_revision"),
            "instance_ref": proof.get("instance_ref"),
            "process_ref": proof.get("process_ref"),
            "evidence_refs": proof.get("evidence_refs"),
        }

    candidate = {
        "schema": CASE_SCHEMA,
        "case_ref": plan_case.get("case_ref"),
        "split": plan_case.get("split"),
        "scenario": scenario,
        "recipe_revision": RECIPE_REVISION,
        "definition_id": definition_id,
        "variant": variant,
        "source_commit": source_commit,
        "fixture_revision": row["fixture_revision"],
        "fixture_image_id": fixture_image_id,
        "scanner_image_id": scanner_image_id,
        "instance_ref": row["instance_ref"],
        "process_ref": row["process_ref"],
        "expected_verdict": plan_case.get("expected_verdict"),
        "observed_verdict": row["observed_verdict"],
        "finding_present": row["finding_present"],
        "lab_solved": row["lab_solved"],
        "claim_state": row["claim_state"],
        "used_for_tuning": plan_case.get("split") == "baseline",
        "evidence_refs": row["evidence_refs"],
        "proof_sha256": proof_sha256,
        "metrics": metrics,
    }
    return validate_case(candidate)


def validate_case(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schema") != CASE_SCHEMA:
        raise MeasurementError("unknown measurement case schema")

    case_ref = _text(raw.get("case_ref"), "case_ref")
    split = raw.get("split")
    scenario = raw.get("scenario")
    variant = raw.get("variant")
    if split not in {"baseline", "held_out"}:
        raise MeasurementError("invalid split")
    if scenario not in {"nominal", "disconnect"}:
        raise MeasurementError("invalid scenario")
    if variant not in {"vulnerable", "patched"}:
        raise MeasurementError("invalid variant")
    if raw.get("recipe_revision") != RECIPE_REVISION:
        raise MeasurementError("measurement case recipe revision mismatch")

    source_commit = _text(raw.get("source_commit"), "source_commit")
    if not _COMMIT.fullmatch(source_commit):
        raise MeasurementError("source_commit must be an exact 40-hex SHA")

    fixture_revision = _text(raw.get("fixture_revision"), "fixture_revision")
    if not _SHA256.fullmatch(fixture_revision):
        raise MeasurementError("fixture_revision must be sha256 hex")

    fixture_image_id = _text(raw.get("fixture_image_id"), "fixture_image_id")
    scanner_image_id = _text(raw.get("scanner_image_id"), "scanner_image_id")
    if not _IMAGE.fullmatch(fixture_image_id) or not _IMAGE.fullmatch(scanner_image_id):
        raise MeasurementError("image ids must be immutable sha256 digests")

    expected = raw.get("expected_verdict")
    observed = raw.get("observed_verdict")
    allowed = {"vulnerable", "not_vulnerable", "indeterminate"}
    if expected not in allowed or observed not in allowed:
        raise MeasurementError("invalid verdict")

    evidence = raw.get("evidence_refs")
    if (
        not isinstance(evidence, list)
        or not evidence
        or any(not isinstance(x, str) or not x.strip() for x in evidence)
    ):
        raise MeasurementError("every measurement case requires non-empty string evidence_refs")
    if len(set(evidence)) != len(evidence):
        raise MeasurementError("measurement evidence_refs must be unique")

    proof_sha = _text(raw.get("proof_sha256"), "proof_sha256")
    if not _SHA256.fullmatch(proof_sha):
        raise MeasurementError("proof_sha256 must be sha256 hex")

    metrics = raw.get("metrics")
    if not isinstance(metrics, dict):
        raise MeasurementError("metrics object is required")
    normalized_metrics = {
        "duration_ms": _number(metrics.get("duration_ms"), "metrics.duration_ms"),
        "cpu_seconds": _number(metrics.get("cpu_seconds"), "metrics.cpu_seconds"),
        "peak_memory_bytes": _integer(
            metrics.get("peak_memory_bytes"), "metrics.peak_memory_bytes"
        ),
        "external_requests": _integer(
            metrics.get("external_requests"), "metrics.external_requests"
        ),
        "human_interventions": _integer(
            metrics.get("human_interventions"), "metrics.human_interventions"
        ),
    }

    finding_present = raw.get("finding_present")
    lab_solved = raw.get("lab_solved")
    used_for_tuning = raw.get("used_for_tuning")
    if (
        not isinstance(finding_present, bool)
        or not isinstance(lab_solved, bool)
        or not isinstance(used_for_tuning, bool)
    ):
        raise MeasurementError(
            "finding_present, lab_solved and used_for_tuning must be booleans"
        )

    claim_state = raw.get("claim_state")
    if claim_state not in {"committed", "indeterminate"}:
        raise MeasurementError("invalid claim_state")
    if split == "held_out" and used_for_tuning:
        raise MeasurementError("held_out cases must never be used for tuning")

    if scenario == "disconnect":
        if (
            expected != "indeterminate"
            or observed != "indeterminate"
            or claim_state != "indeterminate"
        ):
            raise MeasurementError("disconnect must remain indeterminate and fail closed")
        if finding_present or lab_solved:
            raise MeasurementError(
                "disconnect cannot create a finding or solved claim"
            )
    else:
        if claim_state != "committed":
            raise MeasurementError("nominal measurement must use committed claims")
        if variant == "vulnerable":
            if (
                expected != "vulnerable"
                or observed != "vulnerable"
                or not finding_present
                or not lab_solved
            ):
                raise MeasurementError("vulnerable nominal semantics changed")
        if variant == "patched":
            if (
                expected != "not_vulnerable"
                or observed != "not_vulnerable"
                or finding_present
                or lab_solved
            ):
                raise MeasurementError("patched nominal semantics changed")

    return {
        "schema": CASE_SCHEMA,
        "case_ref": case_ref,
        "split": split,
        "scenario": scenario,
        "recipe_revision": RECIPE_REVISION,
        "definition_id": _text(raw.get("definition_id"), "definition_id"),
        "variant": variant,
        "source_commit": source_commit,
        "fixture_revision": fixture_revision,
        "fixture_image_id": fixture_image_id,
        "scanner_image_id": scanner_image_id,
        "instance_ref": _text(raw.get("instance_ref"), "instance_ref"),
        "process_ref": _text(raw.get("process_ref"), "process_ref"),
        "expected_verdict": expected,
        "observed_verdict": observed,
        "finding_present": finding_present,
        "lab_solved": lab_solved,
        "claim_state": claim_state,
        "used_for_tuning": used_for_tuning,
        "evidence_refs": list(evidence),
        "proof_sha256": proof_sha,
        "metrics": normalized_metrics,
    }


def _stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def values(key: str) -> list[float]:
        return [float(x["metrics"][key]) for x in rows]

    return {
        "case_count": len(rows),
        "duration_ms_median": statistics.median(values("duration_ms")),
        "cpu_seconds_median": statistics.median(values("cpu_seconds")),
        "peak_memory_bytes_max": int(max(values("peak_memory_bytes"))),
        "external_requests_total": int(sum(values("external_requests"))),
        "human_interventions_total": int(sum(values("human_interventions"))),
    }


def build_report(
    cases: list[dict[str, Any]], *, plan: dict[str, Any], source_commit: str
) -> dict[str, Any]:
    plan = validate_plan(plan)
    if not _COMMIT.fullmatch(source_commit):
        raise MeasurementError("report source_commit must be exact SHA")

    rows = [validate_case(x) for x in cases]
    by_ref = {x["case_ref"]: x for x in rows}
    if len(by_ref) != len(rows):
        raise MeasurementError("duplicate measurement case_ref")

    plan_by_ref = {x["case_ref"]: x for x in plan["cases"]}
    if set(by_ref) != set(plan_by_ref):
        raise MeasurementError(
            "measurement cases must exactly match the sealed P6 plan"
        )
    for ref, expected in plan_by_ref.items():
        row = by_ref[ref]
        for field in ("split", "scenario", "variant", "expected_verdict"):
            if row[field] != expected[field]:
                raise MeasurementError(
                    f"case {ref} violates sealed plan field {field}"
                )

    if any(x["source_commit"] != source_commit for x in rows):
        raise MeasurementError("measurement case source SHA mismatch")
    if any(x["definition_id"] != plan["definition_id"] for x in rows):
        raise MeasurementError("measurement case definition does not match sealed plan")

    for field in (
        "fixture_revision",
        "fixture_image_id",
        "scanner_image_id",
        "recipe_revision",
        "definition_id",
    ):
        if len({x[field] for x in rows}) != 1:
            raise MeasurementError(f"measurement cases disagree on {field}")

    for field in ("instance_ref", "process_ref", "proof_sha256"):
        values = [x[field] for x in rows]
        if len(set(values)) != len(values):
            raise MeasurementError(
                f"measurement cases must use distinct {field}"
            )

    evidence = [e for row in rows for e in row["evidence_refs"]]
    if len(set(evidence)) != len(evidence):
        raise MeasurementError("measurement cases must not reuse evidence refs")

    baseline = [x for x in rows if x["split"] == "baseline"]
    held_out = [x for x in rows if x["split"] == "held_out"]
    matched = sum(
        x["expected_verdict"] == x["observed_verdict"] for x in rows
    )

    report = {
        "schema": REPORT_SCHEMA,
        "status": "pass",
        "source_commit": source_commit,
        "recipe_revision": rows[0]["recipe_revision"],
        "definition_id": rows[0]["definition_id"],
        "fixture_revision": rows[0]["fixture_revision"],
        "fixture_image_id": rows[0]["fixture_image_id"],
        "scanner_image_id": rows[0]["scanner_image_id"],
        "case_count": len(rows),
        "held_out_separation": {
            "fresh_instance_process_and_evidence": True,
            "used_for_tuning": False,
            "scope": (
                "fresh sealed instances of bac-orders-v1; "
                "not an unseen vulnerability-family claim"
            ),
        },
        "outcomes": {
            "expected_outcome_matches": matched,
            "mismatches": len(rows) - matched,
            "indeterminate_cases": sum(
                x["observed_verdict"] == "indeterminate" for x in rows
            ),
        },
        "resources": {
            "baseline": _stats(baseline),
            "held_out": _stats(held_out),
        },
        "cases": sorted(rows, key=lambda x: x["case_ref"]),
        "claims": {
            "production_deployment": False,
            "provider_production_approval": False,
            "arbitrary_academy_solver": False,
            "additional_vulnerability_families": False,
        },
    }
    report["measurement_sha256"] = canonical_sha256(report)
    return report

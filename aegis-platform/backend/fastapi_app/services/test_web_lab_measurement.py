from __future__ import annotations

import unittest

from fastapi_app.services.web_lab_measurement import (
    CASE_SCHEMA,
    PLAN_SCHEMA,
    RECIPE_REVISION,
    MeasurementError,
    build_report,
    case_from_proof,
    canonical_sha256,
    validate_case,
    validate_plan,
)

SHA = "1" * 40
FIXTURE = "2" * 64
FIXTURE_IMAGE = "sha256:" + "3" * 64
SCANNER_IMAGE = "sha256:" + "4" * 64


def plan():
    return {
        "schema": PLAN_SCHEMA,
        "recipe_revision": RECIPE_REVISION,
        "definition_id": "bac-orders-v1",
        "resource_metrics": [
            "duration_ms",
            "cpu_seconds",
            "peak_memory_bytes",
            "external_requests",
            "human_interventions",
        ],
        "release_claim_limits": {
            "production_deployment": False,
            "provider_production_approval": False,
            "arbitrary_academy_solver": False,
            "additional_vulnerability_families": False,
        },
        "cases": [
            {"case_ref": "baseline-vulnerable", "split": "baseline", "scenario": "nominal", "variant": "vulnerable", "expected_verdict": "vulnerable"},
            {"case_ref": "baseline-patched", "split": "baseline", "scenario": "nominal", "variant": "patched", "expected_verdict": "not_vulnerable"},
            {"case_ref": "heldout-vulnerable", "split": "held_out", "scenario": "nominal", "variant": "vulnerable", "expected_verdict": "vulnerable"},
            {"case_ref": "heldout-patched", "split": "held_out", "scenario": "nominal", "variant": "patched", "expected_verdict": "not_vulnerable"},
            {"case_ref": "heldout-disconnect", "split": "held_out", "scenario": "disconnect", "variant": "vulnerable", "expected_verdict": "indeterminate"},
        ],
    }


def case(ref, split, scenario, variant, verdict, n):
    vulnerable = scenario == "nominal" and variant == "vulnerable"
    disconnect = scenario == "disconnect"
    return {
        "schema": CASE_SCHEMA,
        "case_ref": ref,
        "split": split,
        "scenario": scenario,
        "recipe_revision": RECIPE_REVISION,
        "definition_id": "bac-orders-v1",
        "variant": variant,
        "source_commit": SHA,
        "fixture_revision": FIXTURE,
        "fixture_image_id": FIXTURE_IMAGE,
        "scanner_image_id": SCANNER_IMAGE,
        "instance_ref": f"instance-{n}",
        "process_ref": f"process-{n}",
        "expected_verdict": verdict,
        "observed_verdict": verdict,
        "finding_present": vulnerable,
        "lab_solved": vulnerable,
        "claim_state": "indeterminate" if disconnect else "committed",
        "used_for_tuning": split == "baseline",
        "evidence_refs": [f"evidence-{n}"],
        "proof_sha256": f"{n:x}" * 64,
        "metrics": {
            "duration_ms": 100 + n,
            "cpu_seconds": 1 + n / 10,
            "peak_memory_bytes": 1000 + n,
            "external_requests": 8 if not disconnect else 3,
            "human_interventions": 0,
        },
    }


def cases():
    return [
        case("baseline-vulnerable", "baseline", "nominal", "vulnerable", "vulnerable", 1),
        case("baseline-patched", "baseline", "nominal", "patched", "not_vulnerable", 2),
        case("heldout-vulnerable", "held_out", "nominal", "vulnerable", "vulnerable", 3),
        case("heldout-patched", "held_out", "nominal", "patched", "not_vulnerable", 4),
        case("heldout-disconnect", "held_out", "disconnect", "vulnerable", "indeterminate", 5),
    ]


class MeasurementTests(unittest.TestCase):
    def test_complete_sealed_suite_builds_deterministic_report(self):
        report = build_report(cases(), plan=plan(), source_commit=SHA)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(
            report["outcomes"],
            {"expected_outcome_matches": 5, "mismatches": 0, "indeterminate_cases": 1},
        )
        self.assertFalse(report["held_out_separation"]["used_for_tuning"])
        digest = report.pop("measurement_sha256")
        self.assertEqual(digest, canonical_sha256(report))

    def test_plan_requires_all_measurement_classes(self):
        broken = plan()
        broken["cases"].pop()
        with self.assertRaisesRegex(MeasurementError, "missing a required"):
            validate_plan(broken)

    def test_held_out_can_never_be_marked_as_tuning_data(self):
        row = cases()[2]
        row["used_for_tuning"] = True
        with self.assertRaisesRegex(MeasurementError, "never be used for tuning"):
            validate_case(row)

    def test_disconnect_fails_closed_as_indeterminate(self):
        row = cases()[-1]
        row["observed_verdict"] = "vulnerable"
        row["finding_present"] = True
        row["lab_solved"] = True
        with self.assertRaisesRegex(MeasurementError, "disconnect must remain indeterminate"):
            validate_case(row)

    def test_patched_case_cannot_create_finding(self):
        row = cases()[1]
        row["finding_present"] = True
        with self.assertRaisesRegex(MeasurementError, "patched nominal semantics changed"):
            validate_case(row)

    def test_vulnerable_case_cannot_be_false_negative(self):
        row = cases()[0]
        row["observed_verdict"] = "not_vulnerable"
        row["finding_present"] = False
        row["lab_solved"] = False
        with self.assertRaisesRegex(MeasurementError, "vulnerable nominal semantics changed"):
            validate_case(row)

    def test_source_sha_must_match_exact_release_candidate(self):
        rows = cases()
        rows[0]["source_commit"] = "9" * 40
        with self.assertRaisesRegex(MeasurementError, "source SHA mismatch"):
            build_report(rows, plan=plan(), source_commit=SHA)

    def test_runtime_images_and_fixture_must_be_identical_across_suite(self):
        rows = cases()
        rows[4]["scanner_image_id"] = "sha256:" + "9" * 64
        with self.assertRaisesRegex(MeasurementError, "scanner_image_id"):
            build_report(rows, plan=plan(), source_commit=SHA)

    def test_held_out_must_use_fresh_instance_process_and_proof(self):
        rows = cases()
        rows[3]["instance_ref"] = rows[0]["instance_ref"]
        with self.assertRaisesRegex(MeasurementError, "distinct instance_ref"):
            build_report(rows, plan=plan(), source_commit=SHA)

    def test_evidence_cannot_be_reused_between_cases(self):
        rows = cases()
        rows[4]["evidence_refs"] = rows[0]["evidence_refs"][:]
        with self.assertRaisesRegex(MeasurementError, "reuse evidence refs"):
            build_report(rows, plan=plan(), source_commit=SHA)

    def test_resource_metrics_are_measured_not_negative_or_boolean(self):
        row = cases()[0]
        row["metrics"]["duration_ms"] = -1
        with self.assertRaisesRegex(MeasurementError, "non-negative"):
            validate_case(row)

        row = cases()[0]
        row["metrics"]["human_interventions"] = True
        with self.assertRaisesRegex(MeasurementError, "non-negative integer"):
            validate_case(row)

    def test_case_set_must_exactly_match_sealed_plan(self):
        rows = cases()[:-1]
        with self.assertRaisesRegex(MeasurementError, "exactly match"):
            build_report(rows, plan=plan(), source_commit=SHA)

    def test_plan_is_sealed_to_bac_orders_definition(self):
        broken = plan()
        broken["definition_id"] = "other-family"
        with self.assertRaisesRegex(MeasurementError, "sealed to definition_id"):
            validate_plan(broken)

    def test_plan_rejects_extra_measurement_classes(self):
        broken = plan()
        broken["cases"].append(
            {
                "case_ref": "extra-baseline-vulnerable",
                "split": "baseline",
                "scenario": "nominal",
                "variant": "vulnerable",
                "expected_verdict": "vulnerable",
            }
        )
        with self.assertRaisesRegex(MeasurementError, "exactly the five"):
            validate_plan(broken)

    def test_plan_resource_metrics_are_sealed(self):
        broken = plan()
        broken["resource_metrics"] = broken["resource_metrics"][:-1]
        with self.assertRaisesRegex(MeasurementError, "resource_metrics"):
            validate_plan(broken)

    def test_metrics_reject_non_finite_values(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            row = cases()[0]
            row["metrics"]["duration_ms"] = value
            with self.assertRaisesRegex(MeasurementError, "finite non-negative"):
                validate_case(row)

    def test_evidence_refs_must_be_non_empty_strings(self):
        row = cases()[0]
        row["evidence_refs"] = [{"ref": "not-a-string"}]
        with self.assertRaisesRegex(MeasurementError, "non-empty string"):
            validate_case(row)

    def test_nominal_case_is_derived_from_live_proof(self):
        plan_case = plan()["cases"][0]
        proof = {
            "schema": "aegis.burp-live-lab-verification-proof.v1",
            "status": "pass",
            "source_commit": SHA,
            "variant": "vulnerable",
            "evidence_refs": ["ev-live-1"],
            "verdict": {
                "verdict": "vulnerable",
                "finding_present": True,
                "lab_solved": True,
                "definition_id": "bac-orders-v1",
                "fixture_revision": FIXTURE,
                "instance_ref": "live-instance-1",
                "process_ref": "live-process-1",
            },
        }
        row = case_from_proof(
            plan_case=plan_case, proof=proof, proof_sha256="a" * 64,
            source_commit=SHA, fixture_image_id=FIXTURE_IMAGE,
            scanner_image_id=SCANNER_IMAGE,
            metrics={"duration_ms": 10, "cpu_seconds": 1.0, "peak_memory_bytes": 10,
                     "external_requests": 8, "human_interventions": 0},
            definition_id="bac-orders-v1",
        )
        self.assertEqual(row["observed_verdict"], "vulnerable")
        self.assertEqual(row["evidence_refs"], ["ev-live-1"])

    def test_disconnect_case_is_derived_from_fail_closed_proof(self):
        plan_case = plan()["cases"][-1]
        proof = {
            "schema": "aegis.web-lab-disconnect-proof.v1",
            "status": "pass",
            "source_commit": SHA,
            "variant": "vulnerable",
            "definition_id": "bac-orders-v1",
            "fixture_revision": FIXTURE,
            "instance_ref": "disconnect-instance",
            "process_ref": "disconnect-process",
            "evidence_refs": ["claim:abc", "scan:def"],
            "verdict": "indeterminate",
            "finding_present": False,
            "lab_solved": False,
            "claim_state": "indeterminate",
        }
        row = case_from_proof(
            plan_case=plan_case, proof=proof, proof_sha256="b" * 64,
            source_commit=SHA, fixture_image_id=FIXTURE_IMAGE,
            scanner_image_id=SCANNER_IMAGE,
            metrics={"duration_ms": 10, "cpu_seconds": 1.0, "peak_memory_bytes": 10,
                     "external_requests": 1, "human_interventions": 0},
            definition_id="bac-orders-v1",
        )
        self.assertEqual(row["claim_state"], "indeterminate")
        self.assertFalse(row["finding_present"])

    def test_live_proof_source_sha_cannot_be_relabelled(self):
        plan_case = plan()["cases"][0]
        proof = {"schema": "aegis.burp-live-lab-verification-proof.v1", "status": "pass",
                 "source_commit": "9" * 40, "variant": "vulnerable"}
        with self.assertRaisesRegex(MeasurementError, "proof source SHA mismatch"):
            case_from_proof(
                plan_case=plan_case, proof=proof, proof_sha256="c" * 64,
                source_commit=SHA, fixture_image_id=FIXTURE_IMAGE,
                scanner_image_id=SCANNER_IMAGE, metrics={},
                definition_id="bac-orders-v1",
            )


if __name__ == "__main__":
    unittest.main()

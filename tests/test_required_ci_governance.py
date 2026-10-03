from __future__ import annotations

import importlib.util
import io
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "required_ci_governance.py"
SPEC = importlib.util.spec_from_file_location("aegis_required_ci_governance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class _Response:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class ApiRetryTests(unittest.TestCase):
    def test_timeout_is_retried_then_recovers(self) -> None:
        responses = [TimeoutError("read timed out"), _Response(b'{"ok": true}')]
        sleeps: list[float] = []
        with (
            mock.patch.object(MODULE.urllib.request, "urlopen", side_effect=responses),
            mock.patch.object(MODULE.time, "sleep", side_effect=sleeps.append),
        ):
            result = MODULE._api_json("/repos/acme/aegis/actions/runs", "token")
        self.assertEqual(result, {"ok": True})
        self.assertEqual(sleeps, [1.0])

    def test_timeout_exhaustion_fails_closed_after_bounded_retries(self) -> None:
        sleeps: list[float] = []
        with (
            mock.patch.object(MODULE.urllib.request, "urlopen", side_effect=TimeoutError("read timed out")),
            mock.patch.object(MODULE.time, "sleep", side_effect=sleeps.append),
        ):
            with self.assertRaisesRegex(MODULE.GovernanceError, "after 4 transient attempts"):
                MODULE._api_json("/repos/acme/aegis/actions/runs", "token")
        self.assertEqual(sleeps, [1.0, 2.0, 4.0])

    def test_nontransient_http_error_is_not_retried(self) -> None:
        error = MODULE.urllib.error.HTTPError(
            "https://api.github.com/test",
            403,
            "forbidden",
            {},
            io.BytesIO(b'{"message":"forbidden"}'),
        )
        calls = {"count": 0}

        def fail(*_args, **_kwargs):
            calls["count"] += 1
            raise error

        with (
            mock.patch.object(MODULE.urllib.request, "urlopen", side_effect=fail),
            mock.patch.object(MODULE.time, "sleep", side_effect=AssertionError("must not retry 403")),
        ):
            with self.assertRaisesRegex(MODULE.GovernanceError, "403"):
                MODULE._api_json("/repos/acme/aegis/actions/runs", "token")
        self.assertEqual(calls["count"], 1)


class WorkflowObservationTests(unittest.TestCase):
    def test_lifecycle_only_workflow_is_excluded_without_relaxing_other_failures(self) -> None:
        runs = {
            "Required CI Governance": {"status": "completed", "conclusion": "failure"},
            "Branch Hygiene Reality": {"status": "completed", "conclusion": "skipped"},
            "Domain Contract Reality": {"status": "completed", "conclusion": "success"},
            "Unexpected Triggered Reality": {"status": "completed", "conclusion": "skipped"},
        }
        filtered = MODULE._premerge_workflow_runs(
            runs,
            governance_workflow="Required CI Governance",
            lifecycle_only_workflows={"Branch Hygiene Reality"},
        )
        self.assertNotIn("Required CI Governance", filtered)
        self.assertNotIn("Branch Hygiene Reality", filtered)
        self.assertEqual(filtered["Domain Contract Reality"]["conclusion"], "success")
        self.assertEqual(filtered["Unexpected Triggered Reality"]["conclusion"], "skipped")
        self.assertNotIn(
            filtered["Unexpected Triggered Reality"]["conclusion"],
            {"success"},
        )


class LifecyclePolicyTests(unittest.TestCase):
    def test_live_operational_workflows_are_lifecycle_only_and_do_not_relax_code_reality(self) -> None:
        policy_path = Path(__file__).resolve().parents[1] / ".github" / "governance" / "required-ci-policy.json"
        policy = MODULE._load_policy(policy_path)
        lifecycle = set(policy["lifecycle_only_workflows"])
        self.assertTrue({
            "Branch Hygiene Reality",
            "Cloud Live Provider Reality",
            "External Identity Live Provider Reality",
            "Internal Production Deploy and Acceptance",
            "Production Resilience Acceptance",
            "Final Internal Production Governance",
        }.issubset(lifecycle))

        runs = {
            "Required CI Governance": {"status": "completed", "conclusion": "failure"},
            "Internal Production Deploy and Acceptance": {"status": "queued", "conclusion": None},
            "Production Resilience Acceptance": {"status": "queued", "conclusion": None},
            "Final Internal Production Governance": {"status": "queued", "conclusion": None},
            "Domain Contract Reality": {"status": "completed", "conclusion": "success"},
            "Unexpected Triggered Reality": {"status": "completed", "conclusion": "failure"},
        }
        filtered = MODULE._premerge_workflow_runs(
            runs,
            governance_workflow=policy["governance_workflow"],
            lifecycle_only_workflows=lifecycle,
        )
        self.assertNotIn("Internal Production Deploy and Acceptance", filtered)
        self.assertNotIn("Production Resilience Acceptance", filtered)
        self.assertNotIn("Final Internal Production Governance", filtered)
        self.assertEqual(filtered["Domain Contract Reality"]["conclusion"], "success")
        self.assertEqual(filtered["Unexpected Triggered Reality"]["conclusion"], "failure")

    def test_final_red_blue_sre_acceptance_is_always_required(self) -> None:
        policy_path = Path(__file__).resolve().parents[1] / ".github" / "governance" / "required-ci-policy.json"
        policy = MODULE._load_policy(policy_path)
        workflow = "Final Red Blue SRE Acceptance"
        self.assertIn(workflow, policy["always_required_workflows"]["pull_request"])
        self.assertIn(workflow, policy["always_required_workflows"]["push"])
        self.assertNotIn(workflow, policy["lifecycle_only_workflows"])


class LiveBaseDiffTests(unittest.TestCase):
    def test_pull_request_paths_come_from_live_base_compare(self) -> None:
        calls: list[str] = []

        def fake_api(path: str, token: str):
            self.assertEqual(token, "token")
            calls.append(path)
            if path == "/repos/acme/aegis/branches/main":
                return {"commit": {"sha": "live-main"}}
            if path == "/repos/acme/aegis/compare/live-main...head-sha":
                return {
                    "status": "ahead",
                    "merge_base_commit": {"sha": "live-main"},
                    "files": [
                        {"filename": "scripts/ci/required_ci_governance.py"},
                        {"filename": ".github/workflows/required-ci-governance.yml"},
                    ],
                }
            self.fail(f"unexpected API path: {path}")

        with mock.patch.object(MODULE, "_api_json", side_effect=fake_api):
            paths, live_base_sha = MODULE._pull_request_changed_paths(
                "acme/aegis", "main", "head-sha", "token"
            )

        self.assertEqual(live_base_sha, "live-main")
        self.assertEqual(
            paths,
            [
                ".github/workflows/required-ci-governance.yml",
                "scripts/ci/required_ci_governance.py",
            ],
        )
        self.assertEqual(
            calls,
            [
                "/repos/acme/aegis/branches/main",
                "/repos/acme/aegis/compare/live-main...head-sha",
            ],
        )

    def test_stale_head_is_rejected_instead_of_waiting_for_untriggered_workflows(self) -> None:
        def fake_api(path: str, token: str):
            if path.endswith("/branches/main"):
                return {"commit": {"sha": "new-main"}}
            if "/compare/" in path:
                return {
                    "status": "diverged",
                    "merge_base_commit": {"sha": "old-main"},
                    "files": [{"filename": "already-merged-file.py"}],
                }
            self.fail(f"unexpected API path: {path}")

        with mock.patch.object(MODULE, "_api_json", side_effect=fake_api):
            with self.assertRaisesRegex(MODULE.GovernanceError, "stale relative to live main@new-main"):
                MODULE._pull_request_changed_paths("acme/aegis", "main", "head-sha", "token")

    def test_compare_file_cap_fails_closed(self) -> None:
        def fake_api(path: str, token: str):
            if path.endswith("/branches/main"):
                return {"commit": {"sha": "live-main"}}
            if "/compare/" in path:
                return {
                    "status": "ahead",
                    "merge_base_commit": {"sha": "live-main"},
                    "files": [{"filename": f"file-{index}.txt"} for index in range(MODULE.COMPARE_FILE_CAP)],
                }
            self.fail(f"unexpected API path: {path}")

        with mock.patch.object(MODULE, "_api_json", side_effect=fake_api):
            with self.assertRaisesRegex(MODULE.GovernanceError, "300-file cap"):
                MODULE._pull_request_changed_paths("acme/aegis", "main", "head-sha", "token")


if __name__ == "__main__":
    unittest.main()

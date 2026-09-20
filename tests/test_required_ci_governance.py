from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "required_ci_governance.py"
SPEC = importlib.util.spec_from_file_location("aegis_required_ci_governance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


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

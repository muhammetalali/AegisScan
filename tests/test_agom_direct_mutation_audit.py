from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci/agom_direct_mutation_audit.py"
SPEC = importlib.util.spec_from_file_location("agom_direct_mutation_audit", SCRIPT)
audit = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(audit)

def minimal_policy() -> dict:
    return {
        "schema_version": 1,
        "production_roots": ["aegis-platform/backend"],
        "excluded_path_parts": ["migrations", "tests", "__pycache__"],
        "excluded_filename_prefixes": ["test_"],
        "protected_models": {
            "FindingDisposition": ["aegis-platform/backend/fastapi_app/services/finding_disposition.py"]
        },
        "protected_callables": {
            "govern_finding_disposition": [
                "aegis-platform/backend/fastapi_app/services/governed_action_executor.py"
            ],
            "publish_revision": [],
        },
        "protected_state_assignments": {
            "Vulnerability.Status.FIXED": [
                "aegis-platform/backend/fastapi_app/services/finding_closure.py"
            ]
        },
        "required_source_guards": [],
    }

class AgomDirectMutationAuditTests(unittest.TestCase):
    def _repo(self, files: dict[str, str]):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return temp, root

    def test_protected_model_write_outside_writer_fails_closed(self):
        temp, root = self._repo({
            "aegis-platform/backend/fastapi_app/routers/bypass.py":
                "from x import FindingDisposition\nFindingDisposition.objects.create(finding_id='x')\n"
        })
        self.addCleanup(temp.cleanup)
        violations = audit.audit_repository(root, minimal_policy())
        self.assertTrue(any(v.code == "PROTECTED_MODEL_WRITE" for v in violations))

    def test_protected_callable_outside_executor_fails_closed(self):
        temp, root = self._repo({
            "aegis-platform/backend/fastapi_app/routers/bypass.py":
                "from x import govern_finding_disposition as mutate\nmutate(finding_id='x')\n"
        })
        self.addCleanup(temp.cleanup)
        violations = audit.audit_repository(root, minimal_policy())
        self.assertTrue(any(v.code == "SENSITIVE_CALL_BYPASS" for v in violations))

    def test_direct_legacy_publication_call_is_forbidden_everywhere(self):
        temp, root = self._repo({
            "aegis-platform/backend/fastapi_app/routers/bypass.py":
                "from x import publish_revision\npublish_revision(revision_id='x')\n"
        })
        self.addCleanup(temp.cleanup)
        violations = audit.audit_repository(root, minimal_policy())
        self.assertTrue(any(v.code == "SENSITIVE_CALL_BYPASS" for v in violations))

    def test_terminal_state_assignment_outside_writer_fails_closed(self):
        temp, root = self._repo({
            "aegis-platform/backend/fastapi_app/routers/bypass.py":
                "from x import Vulnerability\nfinding.status = Vulnerability.Status.FIXED\n"
        })
        self.addCleanup(temp.cleanup)
        violations = audit.audit_repository(root, minimal_policy())
        self.assertTrue(any(v.code == "PROTECTED_STATE_WRITE" for v in violations))

    def test_authoritative_writer_and_executor_pass(self):
        temp, root = self._repo({
            "aegis-platform/backend/fastapi_app/services/finding_disposition.py":
                "from x import FindingDisposition\nFindingDisposition.objects.create(finding_id='x')\n",
            "aegis-platform/backend/fastapi_app/services/governed_action_executor.py":
                "from x import govern_finding_disposition\ngovern_finding_disposition(finding_id='x')\n",
        })
        self.addCleanup(temp.cleanup)
        self.assertEqual([], audit.audit_repository(root, minimal_policy()))

    def test_tests_and_migrations_are_not_production_authority_surfaces(self):
        temp, root = self._repo({
            "aegis-platform/backend/fastapi_app/services/test_fixture.py":
                "from x import FindingDisposition\nFindingDisposition.objects.create(finding_id='x')\n",
            "aegis-platform/backend/enterprise/migrations/9999_fixture.py":
                "from x import FindingDisposition\nFindingDisposition.objects.create(finding_id='x')\n",
        })
        self.addCleanup(temp.cleanup)
        self.assertEqual([], audit.audit_repository(root, minimal_policy()))

    def test_configuration_authorized_direct_assignment_is_rejected(self):
        temp, root = self._repo({
            "aegis-platform/backend/fastapi_app/routers/asset.py":
                "asset.configuration['authorized'] = True\n"
        })
        self.addCleanup(temp.cleanup)
        violations = audit.audit_repository(root, minimal_policy())
        self.assertTrue(any(v.code == "LEGACY_AUTHORIZATION_WRITE" for v in violations))

    def test_required_guard_is_fail_closed(self):
        policy = minimal_policy()
        policy["required_source_guards"] = [{
            "path": "aegis-platform/backend/fastapi_app/routers/vulnerabilities.py",
            "token": "_reject_direct_governed_status(update.status)",
            "min_count": 2,
        }]
        temp, root = self._repo({
            "aegis-platform/backend/fastapi_app/routers/vulnerabilities.py":
                "_reject_direct_governed_status(update.status)\n"
        })
        self.addCleanup(temp.cleanup)
        violations = audit.audit_repository(root, policy)
        self.assertTrue(any(v.code == "REQUIRED_GUARD_MISSING" for v in violations))

    def test_repository_matches_authoritative_policy(self):
        policy = audit.load_policy(ROOT / ".github/governance/agom-direct-mutation-policy.json")
        violations = audit.audit_repository(ROOT, policy)
        self.assertEqual([], violations, "\n".join(v.render() for v in violations))

if __name__ == "__main__":
    unittest.main()

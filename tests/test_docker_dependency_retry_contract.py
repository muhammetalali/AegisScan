from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
DJANGO = ROOT / "aegis-platform/backend/Dockerfile.django"
FASTAPI = ROOT / "aegis-platform/backend/Dockerfile.fastapi"


class DockerDependencyRetryContractTests(unittest.TestCase):
    def _assert_retry_contract(self, path: Path, final_dependency: str) -> None:
        text = path.read_text(encoding="utf-8")
        self.assertIn("pip_install_with_retry() {", text)
        self.assertIn(
            'python -m pip install --no-cache-dir --retries 5 --timeout 120 "$@"',
            text,
        )
        self.assertIn('if [ "$attempt" -ge 4 ]', text)
        self.assertIn('sleep_seconds=$((attempt * 10))', text)
        self.assertIn('pip_install_with_retry -r requirements.txt', text)
        self.assertIn(f"pip_install_with_retry {final_dependency}", text)
        self.assertNotIn("RUN pip install --no-cache-dir -r requirements.txt", text)

    def test_django_dependency_install_is_bounded_and_retryable(self) -> None:
        self._assert_retry_contract(DJANGO, "checkov==3.3.16")

    def test_fastapi_dependency_install_is_bounded_and_retryable(self) -> None:
        self._assert_retry_contract(FASTAPI, "semgrep")


if __name__ == "__main__":
    unittest.main()

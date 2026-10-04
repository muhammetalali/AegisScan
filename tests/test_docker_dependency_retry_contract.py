from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
DJANGO = ROOT / "aegis-platform/backend/Dockerfile.django"
FASTAPI = ROOT / "aegis-platform/backend/Dockerfile.fastapi"
FRONTEND = ROOT / "aegis-platform/frontend/Dockerfile"


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


    def test_frontend_dependency_install_is_lockfile_deterministic_and_retryable(self) -> None:
        text = FRONTEND.read_text(encoding="utf-8")
        self.assertIn("COPY package.json package-lock.json ./", text)
        self.assertIn("RUN --mount=type=cache,target=/root/.npm", text)
        self.assertIn("npm_ci_with_retry() {", text)
        self.assertIn("npm ci \\", text)
        self.assertIn("--fetch-retries=5", text)
        self.assertIn("--fetch-retry-factor=2", text)
        self.assertIn("--fetch-retry-mintimeout=10000", text)
        self.assertIn("--fetch-retry-maxtimeout=60000", text)
        self.assertIn("--fetch-timeout=120000", text)
        self.assertIn('if [ "$attempt" -ge 4 ]', text)
        self.assertIn('sleep_seconds=$((attempt * 10))', text)
        self.assertIn('rm -rf node_modules', text)
        self.assertNotIn("RUN npm install --no-audit --no-fund", text)


if __name__ == "__main__":
    unittest.main()

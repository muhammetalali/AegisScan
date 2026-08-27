import os
import time
import urllib.error
import urllib.request


DJANGO_URL = os.getenv("E2E_DJANGO_URL", "http://127.0.0.1:8000")
FASTAPI_URL = os.getenv("E2E_FASTAPI_URL", "http://127.0.0.1:8001")


def _get(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.status, response.read().decode("utf-8", errors="replace")


def _wait_for(url: str, attempts: int = 30) -> None:
    last_error = None
    for _ in range(attempts):
        try:
            status, _ = _get(url)
            if status == 200:
                return
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
        time.sleep(2)
    raise AssertionError(f"Service did not become healthy: {url}; last_error={last_error}")


def test_django_and_fastapi_health_contract():
    _wait_for(f"{DJANGO_URL}/health/")
    _wait_for(f"{FASTAPI_URL}/health")


def test_durable_resource_crud_is_not_exposed_by_fastapi():
    for resource in ("assets", "scans", "vulnerabilities", "reports", "compliance", "audit"):
        try:
            status, _ = _get(f"{FASTAPI_URL}/api/v1/{resource}/")
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert status == 404, f"FastAPI unexpectedly exposes durable CRUD: {resource}"

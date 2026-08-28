from pathlib import Path

import pytest

from fastapi_app.services import engine_adapters
from fastapi_app.services.manifest_discovery import discover_dependency_manifests


def test_manifest_discovery_ignores_dependency_and_generated_directories(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("httpx==0.27.0\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "requirements.txt").write_text("bad==9.9.9\n", encoding="utf-8")

    manifests = discover_dependency_manifests(str(tmp_path))

    assert [item["filename"] for item in manifests] == ["requirements.txt"]
    assert manifests[0]["sha256"]


def test_manifest_discovery_rejects_missing_workspace(tmp_path: Path):
    with pytest.raises(ValueError):
        discover_dependency_manifests(str(tmp_path / "does-not-exist"))


@pytest.mark.asyncio
async def test_dependency_risk_can_infer_code_workspace(tmp_path: Path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("httpx==0.27.0\n", encoding="utf-8")

    async def fake_manifest_analysis(content: str, filename: str):
        from fastapi_app.services.validation_executor import ExecutionResult
        return ExecutionResult(
            "completed",
            [],
            [{"id": "ev-test", "type": "dependency_manifest", "data": {"filename": filename}}],
            {"engine": "dependency_risk", "dependency_count": 1, "vulnerability_matches": 0},
        )

    monkeypatch.setattr(engine_adapters, "analyze_dependency_manifest", fake_manifest_analysis)
    result = await engine_adapters.execute_engine("dependency_risk", "code", str(tmp_path), {})

    assert result.status == "completed"
    assert result.metrics["workspace_discovery"] is True
    assert result.metrics["manifests_found"] == 1
    assert result.metrics["manifests"][0]["filename"] == "requirements.txt"

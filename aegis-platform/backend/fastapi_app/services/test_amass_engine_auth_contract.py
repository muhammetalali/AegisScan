from __future__ import annotations

from pathlib import Path

from fastapi_app.services import amass_managed_runtime as runtime

BACKEND_ROOT = Path(__file__).resolve().parents[2]
BUILDER = BACKEND_ROOT / "resources" / "build-amass-v5-aegis.sh"
PATCH = BACKEND_ROOT / "resources" / "patches" / "amass-v5.1.1-aegis-engine-auth.patch"
RUNTIME_SOURCE = Path(runtime.__file__).resolve()


def test_amass_source_build_is_exact_commit_and_patch_gated():
    builder = BUILDER.read_text(encoding="utf-8")
    assert 'AMASS_COMMIT="79299dce87b0085db0f2f4ef3e9c52cccb49f514"' in builder
    assert 'git -C "$SOURCE_ROOT" apply --unidiff-zero --check "$PATCH_PATH"' in builder
    assert 'go build -trimpath -buildvcs=false' in builder
    assert "grep -q 'AEGIS_AMASS_ENGINE_TOKEN'" in builder
    assert "grep -q 'X-Aegis-Amass-Token'" in builder
    assert '"$SOURCE_ROOT/engine/api/server/v1/handlers.go"' in builder
    assert '"$SOURCE_ROOT/engine/plugins/support/dispatch.go"' in builder


def test_amass_engine_patch_requires_authenticated_http_and_websocket_clients():
    patch = PATCH.read_text(encoding="utf-8")
    assert 'engineAuthHeader = "X-Aegis-Amass-Token"' in patch
    assert 'subtle.ConstantTimeCompare' in patch
    assert 'AEGIS_AMASS_ENGINE_TOKEN must be 64 lowercase hex characters' in patch
    assert 'clone.Header.Set(engineAuthHeader, t.token)' in patch
    assert 'headers.Set(engineAuthHeader, c.token)' in patch
    assert 'http.StatusUnauthorized' in patch
    assert 'sessionConfig := config.NewConfig()' in patch
    assert 'json.Unmarshal(raw, sessionConfig)' in patch
    assert 'v.mgr.NewSession(sessionConfig)' in patch
    assert 'strings.HasSuffix(fqdn.Name, "."+parent.Name)' in patch


def test_managed_runtime_generates_token_inside_execution_boundary(tmp_path):
    source = RUNTIME_SOURCE.read_text(encoding="utf-8")
    assert 'import secrets' in source
    assert 'env["AEGIS_AMASS_ENGINE_TOKEN"] = secrets.token_hex(32)' in source
    environment = runtime._minimal_environment(tmp_path / "runtime")
    assert "AEGIS_AMASS_ENGINE_TOKEN" not in environment

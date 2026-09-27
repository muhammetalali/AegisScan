from pathlib import Path

ROOT = Path(__file__).parents[1]
CLOUD = ROOT / ".github/workflows/cloud-live-provider-reality.yml"
IDENTITY = ROOT / ".github/workflows/external-identity-live-provider-reality.yml"


def _assert_cleanup_safe(path: Path, request_path: str, authorize_step: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert 'if [ "$GITHUB_EVENT_NAME" = "workflow_dispatch" ]; then' in text
    assert f"elif [ -f {request_path} ]; then" in text
    assert 'echo "execute=false" >> "$GITHUB_OUTPUT"' in text
    assert f"- name: {authorize_step}" in text
    assert "if: steps.request.outputs.execute == 'true'" in text


def test_cloud_live_request_deletion_is_cleanup_only_but_manual_dispatch_stays_enabled():
    _assert_cleanup_safe(
        CLOUD,
        ".github/live-acceptance-requests/cloud-providers.json",
        "Authorize exact-main live-provider acceptance",
    )
    text = CLOUD.read_text(encoding="utf-8")
    assert text.count("if: steps.request.outputs.execute == 'true'") >= 7
    assert "Require at least one complete live-provider binding" in text
    assert "Execute and validate configured live providers" in text


def test_external_identity_request_deletion_is_cleanup_only_but_manual_dispatch_stays_enabled():
    _assert_cleanup_safe(
        IDENTITY,
        ".github/live-acceptance-requests/external-identity.json",
        "Authorize exact-main external identity acceptance",
    )
    text = IDENTITY.read_text(encoding="utf-8")
    assert text.count("if: steps.request.outputs.execute == 'true'") >= 8
    assert "Require at least one complete external identity binding" in text
    assert "Execute real read-only external identity validation" in text


def test_cloud_binding_preflight_fails_fast_before_ci_wait_and_dependency_install():
    text = CLOUD.read_text(encoding="utf-8")
    authorize = text.index("- name: Authorize exact-main live-provider acceptance")
    binding = text.index("- name: Require at least one complete live-provider binding")
    wait = text.index("- name: Wait for exact-SHA Required CI Governance")
    install = text.index("- name: Install exact cloud runtime dependencies")
    execute = text.index("- name: Execute and validate configured live providers")
    assert authorize < binding < wait < install < execute

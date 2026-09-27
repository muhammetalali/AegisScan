from pathlib import Path
import yaml

ROOT = Path(__file__).parents[1]

CLOUD_REQUEST = ROOT / ".github/live-acceptance-requests/cloud-providers.json"
IDENTITY_REQUEST = ROOT / ".github/live-acceptance-requests/external-identity.json"
PERFORMANCE_REQUEST = ROOT / ".github/live-acceptance-requests/performance.json"

CLOUD_WORKFLOW = ROOT / ".github/workflows/cloud-live-provider-reality.yml"
IDENTITY_WORKFLOW = ROOT / ".github/workflows/external-identity-live-provider-reality.yml"
PERFORMANCE_WORKFLOW = ROOT / ".github/workflows/performance-load-soak-reality.yml"


def test_expired_external_acceptance_requests_are_not_retained_in_release_tree():
    assert not CLOUD_REQUEST.exists()
    assert not IDENTITY_REQUEST.exists()
    assert not PERFORMANCE_REQUEST.exists()


def test_cleanup_preserves_explicit_manual_live_acceptance_paths():
    cloud = yaml.safe_load(CLOUD_WORKFLOW.read_text(encoding="utf-8"))
    identity = yaml.safe_load(IDENTITY_WORKFLOW.read_text(encoding="utf-8"))
    performance = yaml.safe_load(PERFORMANCE_WORKFLOW.read_text(encoding="utf-8"))

    cloud_dispatch = cloud["on"]["workflow_dispatch"]
    identity_dispatch = identity["on"]["workflow_dispatch"]
    performance_dispatch = performance["on"]["workflow_dispatch"]

    assert cloud_dispatch["inputs"]["confirm"]["required"] is True
    assert identity_dispatch["inputs"]["confirm"]["required"] is True
    assert performance_dispatch["inputs"]["profile"]["options"] == ["ci", "release"]

    cloud_text = CLOUD_WORKFLOW.read_text(encoding="utf-8")
    identity_text = IDENTITY_WORKFLOW.read_text(encoding="utf-8")
    assert "--required-confirm VALIDATE" in cloud_text
    assert "--required-confirm VALIDATE" in identity_text
    assert 'if [ "$GITHUB_EVENT_NAME" = "workflow_dispatch" ]; then' in cloud_text
    assert 'if [ "$GITHUB_EVENT_NAME" = "workflow_dispatch" ]; then' in identity_text


def test_request_deletion_pushes_are_cleanup_only_for_live_provider_workflows():
    for path in (CLOUD_WORKFLOW, IDENTITY_WORKFLOW):
        text = path.read_text(encoding="utf-8")
        assert 'echo "execute=false" >> "$GITHUB_OUTPUT"' in text
        assert "cleanup-only push" in text
        assert "if: steps.request.outputs.execute == 'true'" in text

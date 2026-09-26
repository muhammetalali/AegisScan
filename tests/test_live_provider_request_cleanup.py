from pathlib import Path

ROOT = Path(__file__).parents[1]
CLOUD = ROOT / ".github/workflows/cloud-live-provider-reality.yml"
IDENTITY = ROOT / ".github/workflows/external-identity-live-provider-reality.yml"


def test_cloud_request_cleanup_is_safe_and_live_execution_stays_gated():
    text = CLOUD.read_text(encoding="utf-8")
    assert "Detect live-provider request" in text
    assert "[ -f .github/live-acceptance-requests/cloud-providers.json ]" in text
    assert text.count("if: steps.request.outputs.execute == 'true'") >= 7
    assert "Require at least one complete live-provider binding" in text
    assert "Execute and validate configured live providers" in text


def test_external_identity_request_cleanup_is_safe_and_live_execution_stays_gated():
    text = IDENTITY.read_text(encoding="utf-8")
    assert "Detect external-identity request" in text
    assert "[ -f .github/live-acceptance-requests/external-identity.json ]" in text
    assert text.count("if: steps.request.outputs.execute == 'true'") >= 8
    assert "Require at least one complete external identity binding" in text
    assert "Execute real read-only external identity validation" in text

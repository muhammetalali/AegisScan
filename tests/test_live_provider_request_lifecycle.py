from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLOUD = ROOT / ".github" / "workflows" / "cloud-live-provider-reality.yml"
IDENTITY = ROOT / ".github" / "workflows" / "external-identity-live-provider-reality.yml"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _assert_cleanup_safe(text: str, *, request_path: str, live_job: str) -> None:
    assert "request-routing:" in text
    assert "outputs:" in text
    assert "execute: ${{ steps.resolve.outputs.execute }}" in text
    assert f'[ ! -f {request_path} ]' in text
    assert 'if [ "$GITHUB_EVENT_NAME" = "push" ]' in text
    assert 'echo "execute=$execute" >> "$GITHUB_OUTPUT"' in text
    assert f"  {live_job}:\n    needs: request-routing\n    if: needs.request-routing.outputs.execute == 'true'" in text


def test_cloud_live_request_deletion_is_cleanup_only_before_production_job() -> None:
    text = _text(CLOUD)
    _assert_cleanup_safe(
        text,
        request_path=".github/live-acceptance-requests/cloud-providers.json",
        live_job="live-provider-reality",
    )
    live = text.split("  live-provider-reality:", 1)[1]
    assert "environment: production" in live
    assert "live_acceptance_request.py" in live
    assert "--scope cloud-providers" in live
    assert "--required-confirm VALIDATE" in live


def test_external_identity_request_deletion_is_cleanup_only_before_production_job() -> None:
    text = _text(IDENTITY)
    _assert_cleanup_safe(
        text,
        request_path=".github/live-acceptance-requests/external-identity.json",
        live_job="external-identity-live",
    )
    live = text.split("  external-identity-live:", 1)[1]
    assert "environment: production" in live
    assert "live_acceptance_request.py" in live
    assert "--scope external-identity" in live
    assert "--required-confirm VALIDATE" in live

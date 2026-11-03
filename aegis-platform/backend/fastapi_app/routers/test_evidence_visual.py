from __future__ import annotations

import base64
import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from fastapi_app.routers import evidence as evidence_router
from fastapi_app.services.browser_security_probe import _combine_runs, _run_browser
from fastapi_app.services.native_output_normalizer import normalize_native_output


# Small self-contained synthetic one-pixel image; no user or target data.
_PNG = base64.b64decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ'
    'AAAADUlEQVQIHWP4z8DwHwAFgAI/ScL/nwAAAABJRU5ErkJggg=='
)


def _record() -> SimpleNamespace:
    digest = hashlib.sha256(_PNG).hexdigest()
    body = {
        'schema': 'aegis.browser-security.v1',
        'target_url': 'https://example.invalid/',
        'observations': [{
            'kind': 'browser-render-verification',
            'browser_family': 'firefox',
            'rendered': True,
            'screenshot_retained': True,
            'screenshot_sha256': digest,
            'screenshot_bytes': len(_PNG),
        }],
        'visual_artifacts': [{
            'kind': 'browser-render-snapshot',
            'browser_family': 'firefox',
            'media_type': 'image/png',
            'sha256': digest,
            'size_bytes': len(_PNG),
            'png_base64': base64.b64encode(_PNG).decode('ascii'),
        }],
    }
    raw = json.dumps(body, sort_keys=True)
    return SimpleNamespace(source='aegis-browser-security', evidence_type='scanner_output',
                           raw_output=raw, sha256=hashlib.sha256(raw.encode()).hexdigest())


def test_visual_reader_requires_byte_integrity_and_render_provenance():
    row = _record()
    assert evidence_router._visual_png_from_evidence(row) == _PNG
    row.sha256 = '0' * 64
    assert evidence_router._visual_png_from_evidence(row) is None
    row = _record()
    data = json.loads(row.raw_output)
    data['visual_artifacts'][0]['png_base64'] = base64.b64encode(b'bad').decode()
    row.raw_output = json.dumps(data)
    row.sha256 = hashlib.sha256(row.raw_output.encode()).hexdigest()
    assert evidence_router._visual_png_from_evidence(row) is None
    row = _record()
    row.source = 'unrelated-scanner'
    assert evidence_router._visual_png_from_evidence(row) is None


def test_normalization_drops_binary_artifact_from_report_and_ai_inputs():
    row = _record()
    summary = normalize_native_output('browser.dom-snapshot', row.raw_output)
    assert summary['count'] == 1
    assert 'png_base64' not in str(summary)
    assert base64.b64encode(_PNG).decode() not in str(summary)


def test_browser_combination_keeps_binary_outside_public_observations(monkeypatch):
    digest = hashlib.sha256(_PNG).hexdigest()
    private = {
        'kind': 'browser-render-snapshot',
        'browser_family': 'firefox',
        'media_type': 'image/png',
        'sha256': digest,
        'size_bytes': len(_PNG),
        'png_base64': base64.b64encode(_PNG).decode(),
    }
    monkeypatch.setattr(
        'fastapi_app.services.browser_security_probe.capture_dom',
        lambda *a: ('<html></html>', False, '/bin/firefox', 'firefox',
                    'fixture', '', {
                        'rendered': True, 'screenshot_sha256': digest,
                        'screenshot_bytes': len(_PNG), 'screenshot_retained': True,
                        'visual_artifact': private,
                    })
    )
    result = _run_browser('https://example.invalid/', 1000, 65536, 'firefox')
    combined = _combine_runs('https://example.invalid/', [result])
    assert combined['visual_artifacts'][0] == private
    assert 'png_base64' not in str(combined['observations'])
    assert 'png_base64' not in str(combined['browser_runs'])


@pytest.mark.asyncio
async def test_visual_route_requires_existing_project_authorization(monkeypatch):
    row = _record()
    async def found(_id: str, _actor: str):
        return row
    monkeypatch.setattr(evidence_router, '_get_evidence', found)
    response = await evidence_router.get_visual_evidence('fake-id', user={'user_id': 'owner'})
    assert response.body == _PNG
    assert response.headers['cache-control'] == 'private, no-store'
    assert response.headers['content-type'] == 'image/png'

    async def denied(_id: str, _actor: str):
        return None
    monkeypatch.setattr(evidence_router, '_get_evidence', denied)
    with pytest.raises(HTTPException) as exc:
        await evidence_router.get_visual_evidence('fake-id', user={'user_id': 'outsider'})
    assert exc.value.status_code == 404

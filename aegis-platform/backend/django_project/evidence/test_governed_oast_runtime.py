from __future__ import annotations

import json
import os
import struct
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import GovernedOASTInteraction, GovernedOASTSession
from django_project.projects.models import Project
from django_project.users.models import User

from fastapi_app.services import wstg_native_capabilities as wstg
from fastapi_app.services.governed_oast import (
    OASTRuntimeError,
    create_oast_session,
    get_oast_session,
    ingest_dns_callback,
    ingest_http_callback,
)
from fastapi_app.services.oast_dns_collector import (
    DNSPacketError,
    nxdomain_response,
    parse_dns_question,
)


class GovernedOASTRuntimeTests(TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {
                'OAST_TOKEN_SIGNING_KEY': 'test-oast-signing-key-' + ('a' * 48),
                'OAST_PUBLIC_HTTP_BASE': 'http://127.0.0.1:8001/api/v1/oast/callback',
                'OAST_PUBLIC_DNS_DOMAIN': 'callbacks.oast.test',
                'OAST_ALLOW_INSECURE_LOCAL': 'true',
            },
            clear=False,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.user = User.objects.create_user(
            email='owner@example.test',
            password='unused',
            first_name='Owner',
            last_name='One',
        )
        self.other = User.objects.create_user(
            email='other@example.test',
            password='unused',
            first_name='Other',
            last_name='Tenant',
        )
        self.project = Project.objects.create(
            name='OAST Project',
            slug='oast-project',
            owner=self.user,
        )
        self.asset = Asset.objects.create(
            project=self.project,
            name='OAST Web Target',
            slug='oast-web-target',
            type=Asset.Type.WEBSITE,
            configuration={'url': 'https://target.example.test/'},
            owner=self.user,
        )
        self.authorization = AssetAuthorization.objects.create(
            asset=self.asset,
            actor=self.user,
            authorized=True,
            target_snapshot='https://target.example.test/',
            reason='governed OAST test',
            expires_at=timezone.now() + timedelta(hours=1),
        )

    def _session(self, *, key='oast-test-idempotency-0001', execution='exec-oast-1'):
        return create_oast_session(
            user_id=str(self.user.id),
            project_id=str(self.project.id),
            asset_id=str(self.asset.id),
            authorization_decision_id=str(self.authorization.id),
            execution_id=execution,
            idempotency_key=key,
            target='https://target.example.test/',
            ttl_seconds=300,
            max_interactions=8,
        )

    @staticmethod
    def _identity(payload):
        parsed = urlsplit(payload['callbacks']['http_url'])
        parts = parsed.path.rstrip('/').split('/')
        return parts[-2], parts[-1]

    def test_session_identity_is_server_generated_and_idempotent(self):
        first = self._session()
        second = self._session()
        self.assertEqual(first['id'], second['id'])
        self.assertEqual(first['callbacks'], second['callbacks'])
        self.assertEqual(GovernedOASTSession.objects.count(), 1)
        session_id, token = self._identity(first)
        session = GovernedOASTSession.objects.get(pk=session_id)
        self.assertNotEqual(session.token_sha256, token)
        self.assertTrue(first['callbacks']['dns_name'].endswith('.callbacks.oast.test'))

    def test_http_callback_is_deduplicated_redacted_and_projected(self):
        payload = self._session()
        session_id, token = self._identity(payload)
        first = ingest_http_callback(
            session_id=session_id,
            token=token,
            source_ip='198.51.100.9',
            method='POST',
            query_string='value=private-fixture',
            headers={
                'authorization': 'fixture-header-value',
                'cookie': 'fixture-cookie-value',
                'user-agent': 'oast-test-agent',
                'content-type': 'application/json',
            },
            body=b'{"fixture":"private-body"}',
        )
        duplicate = ingest_http_callback(
            session_id=session_id,
            token=token,
            source_ip='198.51.100.9',
            method='POST',
            query_string='value=private-fixture',
            headers={
                'authorization': 'fixture-header-value',
                'cookie': 'fixture-cookie-value',
                'user-agent': 'oast-test-agent',
                'content-type': 'application/json',
            },
            body=b'{"fixture":"private-body"}',
        )
        self.assertFalse(first['duplicate'])
        self.assertTrue(duplicate['duplicate'])
        self.assertEqual(first['interaction_id'], duplicate['interaction_id'])
        self.assertEqual(GovernedOASTInteraction.objects.count(), 1)
        interaction = GovernedOASTInteraction.objects.select_related('evidence').get()
        self.assertEqual(interaction.protocol, 'http')
        self.assertEqual(interaction.metadata['headers']['user-agent'], 'oast-test-agent')
        self.assertNotIn('authorization', interaction.metadata['headers'])
        self.assertNotIn('cookie', interaction.metadata['headers'])
        serialized = interaction.evidence.raw_output
        self.assertNotIn('private-fixture', serialized)
        self.assertNotIn('private-body', serialized)
        self.assertTrue(interaction.evidence.metadata['authoritative_oast_evidence'])
        self.assertEqual(len(interaction.evidence.sha256), 64)

    def test_dns_callback_correlates_to_same_session(self):
        payload = self._session()
        result = ingest_dns_callback(
            qname=payload['callbacks']['dns_name'].upper() + '.',
            source_ip='203.0.113.11',
            qtype=1,
        )
        self.assertTrue(result['accepted'])
        interaction = GovernedOASTInteraction.objects.get(pk=result['interaction_id'])
        self.assertEqual(interaction.protocol, 'dns')
        self.assertEqual(interaction.metadata['qtype'], 1)
        self.assertEqual(len(interaction.metadata['qname_sha256']), 64)
        self.assertNotIn(payload['callbacks']['dns_name'].split('.')[0], json.dumps(interaction.metadata))

    def test_authorization_supersession_blocks_callback(self):
        payload = self._session()
        session_id, token = self._identity(payload)
        AssetAuthorization.objects.create(
            asset=self.asset,
            actor=self.user,
            authorized=False,
            target_snapshot='https://target.example.test/',
            reason='superseded before callback',
            supersedes=self.authorization,
        )
        with self.assertRaises(OASTRuntimeError):
            ingest_http_callback(
                session_id=session_id,
                token=token,
                source_ip='198.51.100.9',
                method='GET',
            )
        self.assertEqual(GovernedOASTInteraction.objects.count(), 0)

    def test_expired_callback_is_rejected(self):
        payload = self._session()
        session_id, token = self._identity(payload)
        session = GovernedOASTSession.objects.get(pk=session_id)
        with patch(
            'fastapi_app.services.governed_oast.timezone.now',
            return_value=session.expires_at + timedelta(seconds=1),
        ):
            with self.assertRaises(OASTRuntimeError) as caught:
                ingest_http_callback(
                    session_id=session_id,
                    token=token,
                    source_ip='198.51.100.9',
                    method='GET',
                )
        self.assertEqual(caught.exception.code, 'callback_expired')

    def test_cross_tenant_session_read_is_denied(self):
        payload = self._session()
        with self.assertRaises(OASTRuntimeError) as caught:
            get_oast_session(session_id=payload['id'], user_id=str(self.other.id))
        self.assertEqual(caught.exception.code, 'session_not_found')

    def test_oast_ledger_is_immutable(self):
        payload = self._session()
        session = GovernedOASTSession.objects.get(pk=payload['id'])
        session.execution_id = 'changed'
        with self.assertRaises(ValidationError):
            session.save()
        with self.assertRaises(ValidationError):
            GovernedOASTSession.objects.filter(pk=session.pk).update(execution_id='changed')
        session_id, token = self._identity(payload)
        result = ingest_http_callback(
            session_id=session_id,
            token=token,
            source_ip='198.51.100.10',
            method='GET',
        )
        interaction = GovernedOASTInteraction.objects.select_related('evidence').get(
            pk=result['interaction_id']
        )
        interaction.request_method = 'POST'
        with self.assertRaises(ValidationError):
            interaction.save()
        with self.assertRaises(ValidationError):
            GovernedOASTInteraction.objects.filter(pk=interaction.pk).delete()

        evidence = interaction.evidence
        evidence.raw_output = '{"changed":true}'
        with self.assertRaises(ValidationError):
            evidence.save()
        with self.assertRaises(ValidationError):
            type(evidence).objects.filter(pk=evidence.pk).update(raw_output='changed')
        with self.assertRaises(ValidationError):
            type(evidence).objects.filter(pk=evidence.pk).delete()

    def test_wstg_confirmation_requires_signed_authoritative_proof(self):
        payload = self._session(execution='exec-wstg-oast-1')
        session_id, token = self._identity(payload)
        ingest_http_callback(
            session_id=session_id,
            token=token,
            source_ip='198.51.100.12',
            method='GET',
        )
        options = {
            'oast_session_id': session_id,
            'execution_id': 'exec-wstg-oast-1',
        }
        observation = wstg._ssrf_canary_validation(
            'https://target.example.test/',
            options,
        )
        self.assertTrue(observation['ssrf_confirmed'])
        self.assertTrue(observation['callback_observed'])
        self.assertTrue(observation['authoritative_oast_evidence'])
        self.assertFalse(observation['callback_attempted'])
        self.assertFalse(observation['final_decision'])
        normalized = wstg.normalize_wstg_internal_output(
            'web.ssrf-canary-validation',
            json.dumps({'observations': [observation]}),
        )
        self.assertTrue(normalized['observations'][0]['ssrf_confirmed'])
        forged = dict(observation)
        forged['proof_hmac'] = '0' * 64
        normalized_forged = wstg.normalize_wstg_internal_output(
            'web.ssrf-canary-validation',
            json.dumps({'observations': [forged]}),
        )
        self.assertFalse(normalized_forged['observations'][0]['ssrf_confirmed'])
        self.assertTrue(normalized_forged['observations'][0]['abstained'])

    def test_runtime_options_do_not_accept_callback_locations(self):
        with self.assertRaises(ValueError):
            wstg.validate_wstg_internal_options(
                'web.ssrf-canary-validation',
                {
                    'callback_url': 'https://example.test/callback',
                    'oast_session_id': '11111111-1111-1111-1111-111111111111',
                    'execution_id': 'exec-1',
                },
            )


class OASTDNSPacketTests(TestCase):
    def test_dns_question_parser_and_nxdomain_response_are_bounded(self):
        qname = 'abc.callbacks.oast.test'
        question = b''.join(
            bytes([len(label)]) + label.encode('ascii')
            for label in qname.split('.')
        ) + b'\x00' + struct.pack('!HH', 1, 1)
        packet = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + question
        parsed_name, qtype, parsed_question = parse_dns_question(packet)
        self.assertEqual(parsed_name, qname)
        self.assertEqual(qtype, 1)
        self.assertEqual(parsed_question, question)
        response = nxdomain_response(packet, parsed_question)
        response_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            '!HHHHHH', response[:12]
        )
        self.assertEqual(response_id, 0x1234)
        self.assertEqual(flags & 0x000F, 3)
        self.assertTrue(flags & 0x8000)
        self.assertEqual((qdcount, ancount, nscount, arcount), (1, 0, 0, 0))

    def test_dns_parser_rejects_compression_and_multi_question_packets(self):
        compressed = struct.pack('!HHHHHH', 1, 0x0100, 1, 0, 0, 0) + b'\xc0\x0c' + struct.pack('!HH', 1, 1)
        with self.assertRaises(DNSPacketError):
            parse_dns_question(compressed)
        multi = struct.pack('!HHHHHH', 1, 0x0100, 2, 0, 0, 0) + b'\x00' + struct.pack('!HH', 1, 1)
        with self.assertRaises(DNSPacketError):
            parse_dns_question(multi)

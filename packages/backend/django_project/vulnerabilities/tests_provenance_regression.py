import json

from django.test import TestCase

from projects.models import Project
from scans.models import Scan
from users.models import User
from .models import CanonicalFinding, Vulnerability, VulnerabilityEvidence


class ProvenanceAndCanonicalRegressionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            email="provenance-regression@example.local",
            password="test-password",
            role="admin",
        )
        cls.project = Project.objects.create(
            name="Provenance Regression",
            slug="provenance-regression",
            owner=cls.user,
        )
        cls.scan = Scan.objects.create(
            project=cls.project,
            initiated_by=cls.user,
            name="Provenance Regression Scan",
            scan_type=Scan.Type.URL,
            status=Scan.Status.COMPLETED,
            engines=["recon"],
            config={
                "target_type": "url",
                "target_value": "https://example.com",
            },
        )

    def _create_vulnerability(self, title, category="security_headers", raw=None, source_engine="recon"):
        return Vulnerability.objects.create(
            scan=self.scan,
            project=self.project,
            title=title,
            description=title,
            severity="medium",
            confidence="high",
            category=category,
            source_engine=source_engine,
            raw_data=raw or {
                "id": "source-finding",
                "asset": "example.com",
                "observed_at": "2026-08-31T00:00:00Z",
            },
        )

    def test_alias_titles_share_canonical_identity(self):
        first = self._create_vulnerability(
            "HTTPS response lacks Strict-Transport-Security",
            source_engine="vuln_intelligence",
        )
        second = self._create_vulnerability(
            "Missing Strict-Transport-Security",
            source_engine="control_validation",
            raw={"id": "source-finding-2", "asset": "example.com"},
        )

        first.refresh_from_db()
        second.refresh_from_db()
        self.assertIsNotNone(first.canonical_finding_id)
        self.assertEqual(first.canonical_finding_id, second.canonical_finding_id)

        canonical = CanonicalFinding.objects.get(pk=first.canonical_finding_id)
        self.assertEqual(canonical.observation_count, 2)
        self.assertCountEqual(canonical.source_engines, ["vuln_intelligence", "control_validation"])

    def test_reparenting_moves_observation_without_double_counting(self):
        finding = self._create_vulnerability(
            "Missing Content-Security-Policy",
            source_engine="control_validation",
            raw={"id": "source-csp", "asset": "example.com"},
        )
        finding.refresh_from_db()
        old_canonical = finding.canonical_finding
        self.assertEqual(old_canonical.observation_count, 1)

        finding.title = "Missing Strict-Transport-Security"
        finding.raw_data = {"id": "source-hsts", "asset": "example.com"}
        finding.save(update_fields=["title", "raw_data"])
        finding.refresh_from_db()

        new_canonical = finding.canonical_finding
        self.assertNotEqual(old_canonical.pk, new_canonical.pk)
        old_canonical.refresh_from_db()
        new_canonical.refresh_from_db()
        self.assertEqual(old_canonical.observation_count, 0)
        self.assertEqual(new_canonical.observation_count, 1)

    def test_evidence_persists_collector_engine_from_raw_payload(self):
        finding = self._create_vulnerability(
            "Observed security header issue",
            source_engine="control_validation",
            raw={"id": "source-header", "asset": "example.com"},
        )
        evidence = VulnerabilityEvidence.objects.create(
            vulnerability=finding,
            type="dynamic_analysis",
            source="recon",
            description="HTTP observation",
            confidence=0.96,
            raw_data=json.dumps({
                "id": "ev-1",
                "engine": "recon",
                "data": {"status_code": 403},
            }),
            metadata={"scan_id": str(self.scan.pk)},
        )

        evidence.refresh_from_db()
        self.assertEqual(evidence.collector_engine, "recon")
        self.assertEqual(evidence.source, "recon")

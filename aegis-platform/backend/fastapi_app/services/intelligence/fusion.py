from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from django.db import transaction

from django_project.intelligence.models import IntelligenceEnrichment

from .providers import CISAKEVProvider, EPSSProvider, NVDProvider, OSVProvider, IntelligenceProviderError


class IntelligenceFusionError(RuntimeError):
    pass


@dataclass(frozen=True)
class FusionResult:
    cve_id: str
    sources: dict[str, dict[str, Any]]
    source_urls: dict[str, str]
    provider_failures: list[str]
    confidence: float
    conflicts: list[str]
    recommendation: str
    explanation: str


class IntelligenceFusion:
    def __init__(self, *, nvd: Optional[NVDProvider] = None, osv: Optional[OSVProvider] = None, kev: Optional[CISAKEVProvider] = None, epss: Optional[EPSSProvider] = None):
        self.nvd = nvd or NVDProvider()
        self.osv = osv or OSVProvider()
        self.kev = kev or CISAKEVProvider()
        self.epss = epss or EPSSProvider()

    def enrich_cve(self, cve_id: str, *, nvd_api_key: Optional[str] = None) -> FusionResult:
        cve = cve_id.strip().upper()
        if not cve.startswith('CVE-'):
            raise IntelligenceFusionError('Only CVE identifiers can be enriched by the current fusion provider set')
        sources: dict[str, dict[str, Any]] = {}
        source_urls: dict[str, str] = {}
        failures: list[str] = []
        try:
            result = self.nvd.fetch_cve(cve, api_key=nvd_api_key)
            sources['nvd'] = result.data
            source_urls['nvd'] = result.url
        except IntelligenceProviderError as exc:
            failures.append(f'nvd:{exc}')
        try:
            result = self.osv.fetch_vulnerability(cve)
            sources['osv'] = result.data
            source_urls['osv'] = result.url
        except IntelligenceProviderError as exc:
            failures.append(f'osv:{exc}')
        try:
            kev_result = self.kev.catalog()
            source_urls['cisa_kev'] = kev_result.url
            present, item = self.kev.contains(cve)
            sources['cisa_kev'] = {'known_exploited': present, 'entry': item}
        except IntelligenceProviderError as exc:
            failures.append(f'cisa_kev:{exc}')
        try:
            result = self.epss.fetch(cve)
            sources['epss'] = result.data
            source_urls['epss'] = result.url
        except IntelligenceProviderError as exc:
            failures.append(f'epss:{exc}')

        if not sources:
            raise IntelligenceFusionError('No intelligence provider returned data: ' + '; '.join(failures))

        epss_value = None
        epss_rows = sources.get('epss', {}).get('data', [])
        if epss_rows and isinstance(epss_rows[0], dict):
            try:
                epss_value = float(epss_rows[0].get('epss'))
            except (TypeError, ValueError):
                epss_value = None
        kev_known = bool(sources.get('cisa_kev', {}).get('known_exploited'))

        confidence = 40.0
        if 'nvd' in sources:
            confidence += 15.0
        if 'osv' in sources:
            confidence += 15.0
        if kev_known:
            confidence += 20.0
        if epss_value is not None:
            confidence += 10.0

        conflicts: list[str] = []
        nvd_vulns = sources.get('nvd', {}).get('vulnerabilities', [])
        nvd_description = ''
        if nvd_vulns and isinstance(nvd_vulns[0], dict):
            descriptions = nvd_vulns[0].get('cve', {}).get('descriptions', [])
            nvd_description = next((d.get('value', '') for d in descriptions if isinstance(d, dict) and d.get('lang') == 'en'), '')
        osv_description = str(sources.get('osv', {}).get('summary') or '')
        if nvd_description and osv_description and nvd_description.strip().lower() != osv_description.strip().lower():
            conflicts.append('NVD and OSV summaries differ; review source-specific descriptions before making a final determination.')

        recommendation = 'Review the enriched intelligence before changing remediation priority.'
        if kev_known:
            recommendation = 'Prioritize remediation: CISA KEV identifies this CVE as known exploited.'
        elif epss_value is not None and epss_value >= 0.5:
            recommendation = 'Prioritize investigation: EPSS indicates elevated exploitation probability.'
        explanation = 'Sources successfully queried: ' + ', '.join(sorted(sources))
        if failures:
            explanation += '. Provider failures: ' + '; '.join(failures)
        if conflicts:
            explanation += ' Conflicts detected: ' + ' '.join(conflicts)
        return FusionResult(cve, sources, source_urls, failures, min(100.0, confidence), conflicts, recommendation, explanation)

    @staticmethod
    @transaction.atomic
    def persist(result: FusionResult, *, actor_id: str | None = None) -> IntelligenceEnrichment:
        return IntelligenceEnrichment.objects.create(
            cve_id=result.cve_id,
            sources=result.sources,
            source_urls=result.source_urls,
            provider_failures=result.provider_failures,
            confidence=result.confidence,
            conflicts=result.conflicts,
            recommendation=result.recommendation,
            explanation=result.explanation,
            observed_at=datetime.now(timezone.utc),
            observed_by_id=actor_id,
        )

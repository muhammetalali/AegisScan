from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .providers import CISAKEVProvider, EPSSProvider, NVDProvider, OSVProvider, IntelligenceProviderError


class IntelligenceFusionError(RuntimeError):
    pass


@dataclass(frozen=True)
class FusionResult:
    cve_id: str
    sources: dict[str, dict[str, Any]]
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
        failures: list[str] = []
        try:
            sources['nvd'] = self.nvd.fetch_cve(cve, api_key=nvd_api_key).data
        except IntelligenceProviderError as exc:
            failures.append(f'nvd:{exc}')
        try:
            present, item = self.kev.contains(cve)
            sources['cisa_kev'] = {'known_exploited': present, 'entry': item}
        except IntelligenceProviderError as exc:
            failures.append(f'cisa_kev:{exc}')
        try:
            sources['epss'] = self.epss.fetch(cve).data
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

        confidence = 50.0 + (30.0 if kev_known else 0.0) + (20.0 if epss_value is not None else 0.0)
        conflicts: list[str] = []
        recommendation = 'Review the enriched intelligence before changing remediation priority.'
        if kev_known:
            recommendation = 'Prioritize remediation: CISA KEV identifies this CVE as known exploited.'
        elif epss_value is not None and epss_value >= 0.5:
            recommendation = 'Prioritize investigation: EPSS indicates elevated exploitation probability.'
        explanation = 'Sources successfully queried: ' + ', '.join(sorted(sources))
        if failures:
            explanation += '. Provider failures: ' + '; '.join(failures)
        return FusionResult(cve, sources, min(100.0, confidence), conflicts, recommendation, explanation)

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import httpx


class IntelligenceProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    data: dict[str, Any]
    url: str


class _HttpProvider:
    timeout = httpx.Timeout(10.0, connect=5.0)

    def _get(self, url: str, *, headers: Optional[dict[str, str]] = None, params: Optional[dict[str, str]] = None) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(url, headers=headers, params=params)
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise IntelligenceProviderError(f'Provider request failed: {url}') from exc
        if not isinstance(payload, dict):
            raise IntelligenceProviderError(f'Provider returned non-object JSON: {url}')
        return payload


class NVDProvider(_HttpProvider):
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    def fetch_cve(self, cve_id: str, api_key: Optional[str] = None) -> ProviderResult:
        headers = {'apiKey': api_key} if api_key else None
        return ProviderResult('nvd', self._get(self.base_url, headers=headers, params={'cveId': cve_id}), self.base_url)


class OSVProvider(_HttpProvider):
    url = 'https://api.osv.dev/v1/vulns'

    def fetch_vulnerability(self, osv_id: str) -> ProviderResult:
        url = f'{self.url}/{osv_id}'
        return ProviderResult('osv', self._get(url), url)

    def query(self, package: str, ecosystem: str, version: str) -> ProviderResult:
        url = 'https://api.osv.dev/v1/query'
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.post(url, json={'package': {'name': package, 'ecosystem': ecosystem}, 'version': version})
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise IntelligenceProviderError(f'Provider request failed: {url}') from exc
        if not isinstance(payload, dict):
            raise IntelligenceProviderError(f'Provider returned non-object JSON: {url}')
        return ProviderResult('osv', payload, url)


class CISAKEVProvider(_HttpProvider):
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

    def catalog(self) -> ProviderResult:
        return ProviderResult('cisa_kev', self._get(self.url), self.url)

    def contains(self, cve_id: str) -> tuple[bool, Optional[dict[str, Any]]]:
        payload = self.catalog().data
        for item in payload.get('vulnerabilities', []):
            if isinstance(item, dict) and item.get('cveID') == cve_id:
                return True, item
        return False, None


class EPSSProvider(_HttpProvider):
    url = 'https://api.first.org/data/v1/epss'

    def fetch(self, cve_id: str) -> ProviderResult:
        return ProviderResult('epss', self._get(self.url, params={'cve': cve_id}), self.url)

"""Defensive, bounded threat-intelligence adapters used by background jobs."""

import re

import requests

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/vulns"
TIMEOUT = (3.05, 10)
USER_AGENT = "AegisScan-ThreatIntel/1.0"


def normalize_cve(value):
    value = str(value or "").strip().upper()
    return value if CVE_RE.fullmatch(value) else None


def _get(url, params=None):
    response = requests.get(
        url,
        params=params,
        timeout=TIMEOUT,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    return response.json()


def fetch_nvd(cve_id):
    data = _get(NVD_URL, {"cveId": cve_id})
    vulnerabilities = data.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve") or {}
    descriptions = cve.get("descriptions") or []
    english = next((x.get("value") for x in descriptions if x.get("lang") == "en"), None)
    return {
        "source": "NVD",
        "external_id": cve.get("id", cve_id),
        "description": english or "NVD record retrieved successfully.",
        "references": [x.get("url") for x in (cve.get("references") or []) if x.get("url")][:20],
        "raw": cve,
    }


def fetch_osv(cve_id):
    data = _get(f"{OSV_URL}/{cve_id}")
    if not data:
        return None
    return {
        "source": "OSV",
        "external_id": data.get("id", cve_id),
        "description": data.get("summary") or "OSV record retrieved successfully.",
        "references": [x.get("url") for x in (data.get("references") or []) if x.get("url")][:20],
        "raw": data,
    }


def enrich_cve(cve_id):
    cve_id = normalize_cve(cve_id)
    if not cve_id:
        return {"cve_id": cve_id, "sources": [], "errors": ["Invalid CVE identifier"]}

    sources = []
    errors = []
    for adapter in (fetch_nvd, fetch_osv):
        try:
            result = adapter(cve_id)
            if result:
                sources.append(result)
        except requests.RequestException as exc:
            errors.append(f"{adapter.__name__}: {exc.__class__.__name__}")
        except (ValueError, TypeError, KeyError):
            errors.append(f"{adapter.__name__}: invalid upstream response")
    return {"cve_id": cve_id, "sources": sources, "errors": errors}

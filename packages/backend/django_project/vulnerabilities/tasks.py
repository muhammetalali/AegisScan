from celery import shared_task
from django.db import transaction

from core.events import publish_dashboard_event
from .models import Vulnerability, VulnerabilityEvidence
from .threat_intel import enrich_cve


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_jitter=True, max_retries=3)
def enrich_vulnerability_threat_intel(self, vulnerability_id):
    vulnerability = Vulnerability.objects.select_related("project").get(pk=vulnerability_id)
    results = []

    for cve_id in vulnerability.cve_ids or []:
        result = enrich_cve(cve_id)
        results.append(result)
        for source in result["sources"]:
            external_id = source["external_id"]
            existing = VulnerabilityEvidence.objects.filter(vulnerability=vulnerability).filter(
                metadata__external_id=external_id,
                metadata__provider=source["source"],
            ).first()
            payload = {
                "type": VulnerabilityEvidence.Type.EXTERNAL_INTEL,
                "quality": VulnerabilityEvidence.Quality.MEDIUM,
                "source": source["source"],
                "description": source["description"],
                "raw_data": str(source["raw"]),
                "confidence": 0.85,
                "tags": ["threat-intelligence", source["source"].lower()],
                "metadata": {
                    "provider": source["source"],
                    "external_id": external_id,
                    "references": source["references"],
                },
            }
            if existing:
                for key, value in payload.items():
                    setattr(existing, key, value)
                existing.save(update_fields=list(payload.keys()))
            else:
                VulnerabilityEvidence.objects.create(vulnerability=vulnerability, **payload)

    with transaction.atomic():
        vulnerability.raw_data = {**(vulnerability.raw_data or {}), "threat_intelligence": results}
        vulnerability.evidence_count = vulnerability.evidences.count()
        vulnerability.save(update_fields=["raw_data", "evidence_count", "updated_at"])
        publish_dashboard_event(
            project_id=vulnerability.project_id,
            reason="vulnerability.threat_intel_enriched",
            entity="Vulnerability",
            entity_id=vulnerability.id,
        )

    return {
        "vulnerability_id": str(vulnerability.id),
        "sources": sum(len(item["sources"]) for item in results),
        "errors": [error for item in results for error in item["errors"]],
    }

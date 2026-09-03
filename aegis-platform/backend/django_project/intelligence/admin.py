from django.contrib import admin

from .models import IntelligenceEnrichment


@admin.register(IntelligenceEnrichment)
class IntelligenceEnrichmentAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'confidence', 'observed_at', 'observed_by', 'snapshot_sha256')
    search_fields = ('cve_id', 'snapshot_sha256')
    list_filter = ('provider_failures',)
    readonly_fields = ('snapshot_sha256', 'created_at', 'observed_at')

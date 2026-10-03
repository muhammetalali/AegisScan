from __future__ import annotations

from django.db import transaction
from enterprise.provider_approval_models import ProviderApprovalDecision

from .burp_http_probe import health_request_arguments
from .burp_mcp_gateway import (
    BURP_MCP_CAPABILITY_ID, BurpMCPProviderError, _current_provider_approval,
)


def resolve_probe_provider(*, project_id: str, decision_ref: str, target: str):
    """Use a project-scoped current decision, never a client-supplied endpoint."""
    health_request_arguments(target)
    with transaction.atomic():
        selected = ProviderApprovalDecision.objects.filter(
            pk=decision_ref, project_id=project_id, capability=BURP_MCP_CAPABILITY_ID,
        ).first()
        if selected is None:
            raise BurpMCPProviderError('قرار مزود Burp غير متاح في المشروع الحالي.')
        _record, current, mapping, _endpoint = _current_provider_approval(
            project_id=project_id, provider_name=selected.provider_name,
            provider_version=selected.provider_version,
        )
        if current.id != selected.id:
            raise BurpMCPProviderError('قرار المزود المختار استبدل بقرار أحدث؛ حدّث المرجع.')
        if (current.manifest.get('mcp_transport') != 'sse'
                or mapping.get('burp.http_request') != 'send_http1_request'):
            raise BurpMCPProviderError('المزود لا يعلن نقل SSE وأداة HTTP المتوافقة مع فحص المختبر.')
        return current

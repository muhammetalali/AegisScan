from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class TicketResult:
    provider: str
    status: str
    external_id: str | None
    url: str | None
    response: dict[str, Any]


class TicketProvider:
    name: str

    async def create(self, *, title: str, description: str, priority: str, evidence: list[dict[str, Any]], finding: dict[str, Any]) -> TicketResult:
        raise NotImplementedError


class JiraProvider(TicketProvider):
    name = "jira"

    async def create(self, *, title: str, description: str, priority: str, evidence: list[dict[str, Any]], finding: dict[str, Any]) -> TicketResult:
        base = os.getenv("JIRA_BASE_URL", "").rstrip("/")
        token = os.getenv("JIRA_API_TOKEN")
        email = os.getenv("JIRA_USER_EMAIL")
        project = os.getenv("JIRA_PROJECT_KEY")
        if not all((base, token, email, project)):
            return TicketResult(self.name, "not_configured", None, None, {"required": ["JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_USER_EMAIL", "JIRA_PROJECT_KEY"]})
        payload = {
            "fields": {
                "project": {"key": project},
                "summary": title[:255],
                "issuetype": {"name": os.getenv("JIRA_ISSUE_TYPE", "Task")},
                "description": description,
                "priority": {"name": priority.title()},
                "labels": ["aegisscan", "security-validation"],
            }
        }
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, auth=(email, token)) as client:
            response = await client.post(f"{base}/rest/api/3/issue", json=payload, headers={"Accept": "application/json"})
            response.raise_for_status()
            data = response.json()
        key = data.get("key")
        return TicketResult(self.name, "created", key, f"{base}/browse/{key}" if key else None, data)


class ServiceNowProvider(TicketProvider):
    name = "servicenow"

    async def create(self, *, title: str, description: str, priority: str, evidence: list[dict[str, Any]], finding: dict[str, Any]) -> TicketResult:
        base = os.getenv("SERVICENOW_BASE_URL", "").rstrip("/")
        token = os.getenv("SERVICENOW_API_TOKEN")
        if not base or not token:
            return TicketResult(self.name, "not_configured", None, None, {"required": ["SERVICENOW_BASE_URL", "SERVICENOW_API_TOKEN"]})
        urgency = {"critical": "1", "high": "1", "medium": "2", "low": "3"}.get(priority.lower(), "3")
        payload = {
            "short_description": title[:160],
            "description": description,
            "urgency": urgency,
            "impact": urgency,
            "category": "Security",
            "u_aegisscan_finding_id": str(finding.get("id") or finding.get("finding_id") or ""),
        }
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}) as client:
            response = await client.post(f"{base}/api/now/table/{os.getenv('SERVICENOW_TABLE', 'incident')}", json=payload)
            response.raise_for_status()
            data = response.json().get("result", response.json())
        number = data.get("number")
        sys_id = data.get("sys_id")
        return TicketResult(self.name, "created", number or sys_id, f"{base}/nav_to.do?uri=incident.do?sys_id={sys_id}" if sys_id else None, data)


class TicketOrchestrator:
    def __init__(self, providers: list[TicketProvider] | None = None) -> None:
        self.providers = providers or [JiraProvider(), ServiceNowProvider()]

    async def create_from_decision(self, *, provider: str, decision: dict[str, Any], evidence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        matched = next((item for item in self.providers if item.name == provider.lower().strip()), None)
        if not matched:
            raise ValueError(f"unsupported ticket provider: {provider}")
        finding = decision.get("finding") if isinstance(decision.get("finding"), dict) else decision
        title = str(decision.get("title") or finding.get("title") or "AegisScan Security Remediation")
        severity = str(decision.get("severity") or finding.get("severity") or "medium").lower()
        description = self._description(decision, evidence or [])
        result = await matched.create(title=title, description=description, priority=severity, evidence=evidence or [], finding=finding)
        return {"provider": result.provider, "status": result.status, "external_id": result.external_id, "url": result.url, "response": result.response}

    @staticmethod
    def _description(decision: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
        fusion = decision.get("fusion") if isinstance(decision.get("fusion"), dict) else {}
        risk = decision.get("dynamic_risk") if isinstance(decision.get("dynamic_risk"), dict) else {}
        lines = [
            "AegisScan automated remediation ticket.",
            f"Severity: {decision.get('severity', 'unknown')}",
            f"Risk score: {decision.get('final_score', risk.get('score', 'unknown'))}",
            f"Fusion confidence: {decision.get('confidence', fusion.get('confidence', 'unknown'))}",
            f"Recommended action: {decision.get('recommended_action', 'Investigate and remediate the finding.')}",
        ]
        if fusion.get("rationale"):
            lines.append(f"Fusion rationale: {fusion['rationale']}")
        if risk.get("rationale"):
            lines.append(f"Dynamic risk rationale: {risk['rationale']}")
        lines.append(f"Evidence items: {len(evidence)}")
        return "\n".join(lines)

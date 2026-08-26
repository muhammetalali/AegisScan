"""Digital Twin Engine — محرك النموذج الافتراضي المحسّن.

يبني نموذجاً افتراضياً للبيئة لاختبار أثر التغييرات قبل التطبيق الحقيقي.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.twin_engine")


class TwinStatus(str, Enum):
    BUILDING = "building"
    READY = "ready"
    TESTING = "testing"
    DRIFTED = "drifted"
    DESTROYED = "destroyed"


class ChangeType(str, Enum):
    PATCH = "patch"
    CONFIG_CHANGE = "config_change"
    ARCHITECTURE = "architecture"
    RULE_UPDATE = "rule_update"


@dataclass
class TwinNode:
    """عقدة في النموذج الافتراضي."""
    node_id: str
    node_type: str
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    connections: List[str] = field(default_factory=list)


@dataclass
class ChangeScenario:
    """سيناريو تغيير."""
    scenario_id: str
    change_type: ChangeType
    title: str
    description: str
    affected_nodes: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChangeImpact:
    """تأثير التغيير."""
    scenario_id: str
    affected_nodes: List[str]
    security_impact: float = 0.0
    performance_impact: float = 0.0
    compatibility_issues: List[str] = field(default_factory=list)
    recommendation: str = ""
    risk_before: float = 0.0
    risk_after: float = 0.0
    risk_reduction: float = 0.0
    details: List[str] = field(default_factory=list)


class DigitalTwinEngine:
    """محرك النموذج الافتراضي — يختبر أثر التغييرات."""

    name = "DigitalTwinEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._nodes: Dict[str, TwinNode] = {}
        self._status = TwinStatus.BUILDING
        self._scenarios: Dict[str, ChangeScenario] = {}
        self._impacts: List[ChangeImpact] = []

    async def build_model(
        self, assets: List[Dict[str, Any]], controls: List[Dict[str, Any]]
    ) -> TwinStatus:
        """بناء النموذج الافتراضي."""
        self._nodes.clear()

        for asset in assets:
            node = TwinNode(
                node_id=asset.get("asset_id", ""),
                node_type=asset.get("asset_type", "unknown"),
                name=asset.get("name", ""),
                properties=asset,
                connections=[],
            )
            self._nodes[node.node_id] = node

        for control in controls:
            node = TwinNode(
                node_id=control.get("control_id", ""),
                node_type="control",
                name=control.get("name", ""),
                properties=control,
                connections=control.get("protected_assets", []),
            )
            self._nodes[node.node_id] = node

        self._status = TwinStatus.READY
        await self.event_bus.publish(
            topic="twin.built",
            payload={"nodes": len(self._nodes)},
            source=self.name,
        )
        return self._status

    async def simulate_change(
        self, scenario: ChangeScenario
    ) -> ChangeImpact:
        """محاكاة تغيير."""
        self._scenarios[scenario.scenario_id] = scenario
        self._status = TwinStatus.TESTING

        # تحليل التأثير
        security_impact = 0.0
        perf_impact = 0.0
        compat_issues: List[str] = []
        details: List[str] = []

        for node_id in scenario.affected_nodes:
            node = self._nodes.get(node_id)
            if not node:
                compat_issues.append(f"العقدة {node_id} غير موجودة في النموذج")
                continue

            if node.node_type == "control":
                # تغيير ضابط → تأثير أمني
                if scenario.change_type == ChangeType.PATCH:
                    security_impact += 2.0
                    details.append(f"تحديث الضابط {node.name}: تحسن أمني")
                elif scenario.change_type == ChangeType.RULE_UPDATE:
                    security_impact += 1.5
                    details.append(f"تحديث قواعد {node.name}: تغيير في الكشف")

                # التأثير على الأصول المحمية
                for conn in node.connections:
                    if conn in self._nodes:
                        details.append(f"الأصل {conn} متأثر بالتغيير")
            elif node.node_type in ("server", "web_app", "api"):
                # تغيير أصل → تأثير على الأداء
                if scenario.change_type == ChangeType.CONFIG_CHANGE:
                    perf_impact += 1.0
                    details.append(f"تغيير إعدادات {node.name}")

        # حساب مخاطر قبل وبعد
        risk_before = len(scenario.affected_nodes) * 2.0
        risk_after = max(risk_before - security_impact, 0)
        risk_reduction = risk_before - risk_after

        # التوصية
        if risk_reduction > 3:
            recommendation = "التغيير مُوصى به — يقلل المخاطر بشكل ملحوظ"
        elif risk_reduction > 0:
            recommendation = "التغيير مقبول — تحسن طفيف"
        elif len(compat_issues) > 0:
            recommendation = "مراجعة التوافق قبل التطبيق"
        else:
            recommendation = "لا يوجد تأثير أمني واضح"

        impact = ChangeImpact(
            scenario_id=scenario.scenario_id,
            affected_nodes=scenario.affected_nodes,
            security_impact=round(security_impact, 1),
            performance_impact=round(perf_impact, 1),
            compatibility_issues=compat_issues,
            recommendation=recommendation,
            risk_before=risk_before,
            risk_after=risk_after,
            risk_reduction=round(risk_reduction, 1),
            details=details,
        )

        self._impacts.append(impact)
        self._status = TwinStatus.READY

        await self.event_bus.publish(
            topic="twin.simulated",
            payload={
                "scenario_id": scenario.scenario_id,
                "risk_reduction": risk_reduction,
                "recommendation": recommendation,
            },
            source=self.name,
        )
        return impact

    async def check_drift(self, current_assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """فحص انحراف النموذج عن الواقع."""
        current_ids = {a.get("asset_id", "") for a in current_assets}
        model_ids = set(self._nodes.keys())

        missing = current_ids - model_ids
        extra = model_ids - current_ids

        drift = len(missing) + len(extra)
        if drift > 0:
            self._status = TwinStatus.DRIFTED

        return {
            "drift": drift,
            "missing_in_model": list(missing),
            "extra_in_model": list(extra),
            "status": self._status.value,
        }

    def get_status(self) -> TwinStatus:
        return self._status

    def get_impacts(self) -> List[ChangeImpact]:
        return list(self._impacts)

    def summary(self) -> Dict[str, Any]:
        return {
            "status": self._status.value,
            "total_nodes": len(self._nodes),
            "total_scenarios": len(self._scenarios),
            "total_impacts": len(self._impacts),
        }

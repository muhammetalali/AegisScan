"""Recon & Asset Discovery Engine — محرك الاستطلاع واكتشاف الأصول.

المرحلة الأولى: نحدد الأصول، الخدمات، المنافذ، التطبيقات، ونصنفها حسب الأهمية.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.recon")


class AssetCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetType(str, Enum):
    SERVER = "server"
    DATABASE = "database"
    WEB_APP = "web_app"
    API = "api"
    CONTAINER = "container"
    NETWORK_DEVICE = "network_device"
    IDENTITY_PROVIDER = "identity_provider"
    STORAGE = "storage"
    UNKNOWN = "unknown"


@dataclass
class DiscoveredAsset:
    asset_id: str
    name: str
    asset_type: AssetType
    criticality: AssetCriticality
    ip_address: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    owner: str = ""
    environment: str = "production"
    metadata: Dict[str, Any] = field(default_factory=dict)


class ReconAssetDiscoveryEngine:
    """محرك الاستطلاع واكتشاف الأصول — يحدد ويصنف كل أصل في البيئة."""

    name = "ReconAssetDiscoveryEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._assets: Dict[str, DiscoveredAsset] = {}

    async def discover_from_code(
        self, code_path: str, scan_id: str
    ) -> List[DiscoveredAsset]:
        """اكتشاف الأصول من هيكل المشروع."""
        from pathlib import Path
        path = Path(code_path)
        if not path.exists():
            return []

        discovered: List[DiscoveredAsset] = []

        # كشف قواعد البيانات
        db_indicators = {
            "sqlite": AssetType.DATABASE,
            "postgres": AssetType.DATABASE,
            "mysql": AssetType.DATABASE,
            "mongodb": AssetType.DATABASE,
            "redis": AssetType.DATABASE,
        }
        # كشف الأطر
        framework_indicators = {
            "flask": AssetType.WEB_APP,
            "django": AssetType.WEB_APP,
            "fastapi": AssetType.API,
            "express": AssetType.WEB_APP,
            "spring": AssetType.WEB_APP,
        }

        for py_file in path.rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            content_lower = content.lower()

            # كشف قواعد البيانات
            for indicator, atype in db_indicators.items():
                if indicator in content_lower:
                    asset = DiscoveredAsset(
                        asset_id=f"db_{indicator}_{py_file.stem}",
                        name=f"{indicator} ({py_file.name})",
                        asset_type=atype,
                        criticality=AssetCriticality.HIGH,
                        services=[indicator],
                        technologies=[indicator],
                        metadata={"source_file": str(py_file)},
                    )
                    discovered.append(asset)

            # كشف الأطر
            for indicator, atype in framework_indicators.items():
                if indicator in content_lower:
                    asset = DiscoveredAsset(
                        asset_id=f"app_{indicator}_{py_file.stem}",
                        name=f"{indicator} app ({py_file.name})",
                        asset_type=atype,
                        criticality=AssetCriticality.MEDIUM,
                        services=[indicator],
                        technologies=[indicator],
                        metadata={"source_file": str(py_file)},
                    )
                    discovered.append(asset)

        # حفظ ونشر
        for asset in discovered:
            self._assets[asset.asset_id] = asset
            await self.event_bus.publish(
                topic="asset.discovered",
                payload={
                    "asset_id": asset.asset_id,
                    "type": asset.asset_type.value,
                    "criticality": asset.criticality.value,
                },
                source=self.name,
            )

        logger.info("اكتشاف %d أصل من %s", len(discovered), code_path)
        return discovered

    async def discover_from_config(
        self, config_path: str, scan_id: str
    ) -> List[DiscoveredAsset]:
        """اكتشاف الأصول من ملفات الإعدادات."""
        from pathlib import Path
        path = Path(config_path)
        if not path.exists():
            return []

        discovered: List[DiscoveredAsset] = []

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        content_lower = content.lower()

        # كشف Docker
        if "dockerfile" in path.name.lower() or "docker-compose" in path.name.lower():
            discovered.append(DiscoveredAsset(
                asset_id=f"container_{path.stem}",
                name=f"Container ({path.name})",
                asset_type=AssetType.CONTAINER,
                criticality=AssetCriticality.MEDIUM,
                services=["docker"],
                technologies=["docker"],
                metadata={"source_file": str(path)},
            ))

        # كشف خوادم
        import re
        hosts = re.findall(r'(?:host|server|hostname)\s*[=:]\s*["\']?([^\s"\']+)', content_lower)
        for host in hosts:
            if host not in ("localhost", "127.0.0.1", "0.0.0.0"):  # nosec B104 - this is input classification, not a bind operation
                discovered.append(DiscoveredAsset(
                    asset_id=f"server_{host.replace('.', '_')}",
                    name=f"Server ({host})",
                    asset_type=AssetType.SERVER,
                    criticality=AssetCriticality.HIGH,
                    ip_address=host,
                    metadata={"source_file": str(path)},
                ))

        for asset in discovered:
            self._assets[asset.asset_id] = asset

        logger.info("اكتشاف %d أصل من الإعدادات", len(discovered))
        return discovered

    def get_assets(self) -> List[DiscoveredAsset]:
        """استرجاع كل الأصول المكتشفة."""
        return list(self._assets.values())

    def get_asset(self, asset_id: str) -> Optional[DiscoveredAsset]:
        """استرجاع أصل واحد."""
        return self._assets.get(asset_id)

    def get_by_criticality(self, criticality: AssetCriticality) -> List[DiscoveredAsset]:
        """استرجاع أصول حسب الأهمية."""
        return [a for a in self._assets.values() if a.criticality == criticality]

    def get_by_type(self, asset_type: AssetType) -> List[DiscoveredAsset]:
        """استرجاع أصول حسب النوع."""
        return [a for a in self._assets.values() if a.asset_type == asset_type]

    def summary(self) -> Dict[str, Any]:
        """ملخص الاكتشاف."""
        by_type: Dict[str, int] = {}
        by_crit: Dict[str, int] = {}
        for a in self._assets.values():
            by_type[a.asset_type.value] = by_type.get(a.asset_type.value, 0) + 1
            by_crit[a.criticality.value] = by_crit.get(a.criticality.value, 0) + 1
        return {
            "total_assets": len(self._assets),
            "by_type": by_type,
            "by_criticality": by_crit,
        }

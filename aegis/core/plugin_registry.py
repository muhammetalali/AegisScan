"""سجل مكونات إضافية ثابت وآمن؛ لا ينفذ تنزيلات تلقائية."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


class PluginMetadata(BaseModel):
    name: str
    version: str
    source_url: str | None = None
    min_tool_versions: dict[str, str] = Field(default_factory=dict)
    trust_level: float = Field(default=0.5, ge=0.0, le=1.0)
    enabled: bool = True


class PluginRegistry:
    """يقرأ metadata من JSON ويترك التثبيت لعملية مراجعة وصريحة."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._plugins: dict[str, PluginMetadata] = {}
        if self.path and self.path.exists():
            self.load()

    def load(self) -> int:
        if not self.path:
            return 0
        raw = json.loads(self.path.read_text(encoding='utf-8'))
        records = raw.get('plugins', raw) if isinstance(raw, dict) else raw
        self._plugins = {
            item['name']: PluginMetadata.model_validate(item)
            for item in records
        }
        return len(self._plugins)

    def get(self, name: str) -> PluginMetadata | None:
        return self._plugins.get(name)

    def all(self) -> tuple[PluginMetadata, ...]:
        return tuple(self._plugins[name] for name in sorted(self._plugins))

    def update_candidates(self, installed: dict[str, str]) -> list[PluginMetadata]:
        """يعرض المرشحين المختلفين فقط؛ لا يثبت أو يشغل كودًا خارجيًا."""
        return [item for item in self.all() if installed.get(item.name) != item.version]

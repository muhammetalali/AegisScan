"""سجل مكونات إضافية ثابت وآمن؛ لا ينفذ تنزيلات تلقائية."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from pydantic import BaseModel, Field


class PluginMetadata(BaseModel):
    name: str
    version: str
    source_url: str | None = None
    sha256: str | None = None
    min_tool_versions: dict[str, str] = Field(default_factory=dict)
    trust_level: float = Field(default=0.5, ge=0.0, le=1.0)
    enabled: bool = True


class PluginRegistry:
    """سجل إضافات مع تنزيل موثّق لا يقوم بتشغيل كود خارجي تلقائيًا."""

    max_download_bytes = 25 * 1024 * 1024

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

    def sync_verified(
        self,
        installed: dict[str, str],
        target_dir: str | Path,
    ) -> dict[str, Path]:
        """تنزيل الإضافات الجديدة/المحدثة بعد التحقق؛ لا يستورد أي كود."""
        downloaded: dict[str, Path] = {}
        for metadata in self.update_candidates(installed):
            if not metadata.enabled:
                continue
            downloaded[metadata.name] = self.download_verified(
                metadata.name,
                target_dir,
            )
        return downloaded

    def download_verified(
        self,
        name: str,
        target_dir: str | Path,
        timeout: float = 20.0,
    ) -> Path:
        """تنزيل إضافة موثقة إلى مجلد عزل دون استيرادها أو تنفيذها."""
        metadata = self.get(name)
        if not metadata:
            raise ValueError(f"Unknown plugin: {name}")
        if not metadata.source_url or urlparse(metadata.source_url).scheme != "https":
            raise ValueError("Plugin source_url must use HTTPS")
        expected = (metadata.sha256 or "").lower()
        if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
            raise ValueError("Plugin registry entry must include a valid SHA-256")

        root = Path(target_dir).resolve()
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=root, prefix=f".{name}-", suffix=".download", delete=False
        ) as handle:
            temporary = Path(handle.name)
            try:
                request = Request(
                    metadata.source_url,
                    headers={"User-Agent": "AegisScan-PluginManager/1"},
                )
                digest = hashlib.sha256()
                total = 0
                with urlopen(request, timeout=timeout) as response:  # nosec B310 - HTTPS URL validated above
                    while True:
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > self.max_download_bytes:
                            raise ValueError("Plugin download exceeds size limit")
                        digest.update(chunk)
                        handle.write(chunk)
                if digest.hexdigest() != expected:
                    raise ValueError("Plugin SHA-256 verification failed")
            except Exception:
                temporary.unlink(missing_ok=True)
                raise

        install_dir = root / name / metadata.version
        install_dir.mkdir(parents=True, exist_ok=False)
        try:
            if zipfile.is_zipfile(temporary):
                with zipfile.ZipFile(temporary) as archive:
                    self._safe_extract(archive, install_dir)
            else:
                shutil.move(
                    str(temporary),
                    str(install_dir / (Path(urlparse(metadata.source_url).path).name or "plugin.bin")),
                )
        finally:
            temporary.unlink(missing_ok=True)
        return install_dir

    @staticmethod
    def _safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
        destination = destination.resolve()
        for member in archive.infolist():
            unix_mode = (member.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                raise ValueError("Plugin archive contains a symbolic link")
            member_path = (destination / member.filename).resolve()
            if member_path != destination and destination not in member_path.parents:
                raise ValueError("Plugin archive contains an unsafe path")
        archive.extractall(destination)

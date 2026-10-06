from __future__ import annotations

import logging
import os
import re
import shutil
from pathlib import Path

from django.db.models.signals import post_delete
from django.dispatch import receiver

from .models import Asset


logger = logging.getLogger(__name__)
_UPLOAD_BUCKET_RE = re.compile(r"^[0-9a-f]{32}$")


def _managed_upload_bucket(instance: Asset) -> Path | None:
    if getattr(instance, "type", None) != Asset.Type.FILE:
        return None
    configuration = instance.configuration if isinstance(instance.configuration, dict) else {}
    raw_path = configuration.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        return None

    root = Path(
        os.getenv("AEGIS_SEMGREP_UPLOAD_ROOT", "/var/lib/aegis-semgrep/uploads")
    ).resolve()
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        return None
    try:
        relative = candidate.resolve(strict=False).relative_to(root)
    except (OSError, ValueError):
        return None
    if not relative.parts or not _UPLOAD_BUCKET_RE.fullmatch(relative.parts[0]):
        return None

    bucket = root / relative.parts[0]
    if bucket.is_symlink():
        return None
    try:
        resolved_bucket = bucket.resolve(strict=False)
    except OSError:
        return None
    if resolved_bucket.parent != root:
        return None
    return resolved_bucket


@receiver(post_delete, sender=Asset)
def cleanup_managed_file_upload(sender, instance: Asset, **_kwargs) -> None:
    bucket = _managed_upload_bucket(instance)
    if bucket is None or not bucket.exists():
        return
    if bucket.is_symlink() or not bucket.is_dir():
        return
    try:
        shutil.rmtree(bucket)
    except OSError:
        logger.exception("Failed to remove managed file upload workspace: %s", bucket)

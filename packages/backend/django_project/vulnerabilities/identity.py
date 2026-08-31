"""Canonical vulnerability identity and fingerprinting helpers."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit


_TITLE_ALIASES = {
    "https response lacks strict-transport-security": "missing-hsts",
    "missing strict-transport-security": "missing-hsts",
    "missing hsts": "missing-hsts",
}


def _clean(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def normalize_target(url: object) -> str:
    """Normalize a network target without collapsing distinct paths."""
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
        default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        netloc = hostname if not port or default_port else f"{hostname}:{port}"
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path.rstrip("/") or "/", "", ""))
    except ValueError:
        return _clean(raw).rstrip("/")


def canonical_rule_key(title: object, category: object = "", cwe_id: object = "") -> str:
    normalized_title = _clean(title)
    alias = _TITLE_ALIASES.get(normalized_title)
    if alias:
        return alias
    category_value = _clean(category)
    cwe_value = _clean(cwe_id)
    return "|".join(part for part in (category_value, cwe_value, normalized_title) if part)[:200]


def build_canonical_identity(vulnerability) -> tuple[str, str, str, str]:
    """Return fingerprint, rule key, normalized target, and canonical title."""
    raw = vulnerability.raw_data or {}
    target = vulnerability.url or raw.get("url") or raw.get("target") or raw.get("asset") or ""
    normalized_target = normalize_target(target)
    rule_key = canonical_rule_key(vulnerability.title, vulnerability.category, vulnerability.cwe_id)
    method = _clean(vulnerability.method)
    parameter = _clean(vulnerability.parameter)
    file_path = _clean(vulnerability.file_path)
    function_name = _clean(vulnerability.function_name)
    asset_key = str(vulnerability.asset_id or _clean(raw.get("asset")))

    identity_parts = [
        "v1",
        str(vulnerability.project_id),
        asset_key,
        normalized_target,
        method,
        parameter,
        file_path,
        function_name,
        rule_key,
    ]
    digest = hashlib.sha256("\x1f".join(identity_parts).encode("utf-8")).hexdigest()

    return digest, rule_key, normalized_target, vulnerability.title

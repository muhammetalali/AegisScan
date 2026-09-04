from __future__ import annotations

import re
from pathlib import Path


def test_nginx_location_directives_are_unique_per_server() -> None:
    """Reject duplicate locations before Nginx enters a restart loop in CI."""
    config = (Path(__file__).parents[1] / "aegis-platform/docker/nginx.conf").read_text()
    locations = re.findall(r"^\s*location\s+([^\s{]+(?:\s+[^\s{]+)?)\s*\{", config, re.MULTILINE)

    duplicates = sorted({location for location in locations if locations.count(location) > 1})

    assert duplicates == []


def test_legacy_vulnerability_route_cannot_fall_through_to_spa() -> None:
    config = (Path(__file__).parents[1] / "aegis-platform/docker/nginx.conf").read_text()

    assert "location /vulnerabilities/" in config
    assert "proxy_pass http://fastapi/api/v1/vulnerabilities/;" in config

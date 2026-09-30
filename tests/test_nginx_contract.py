from __future__ import annotations

import re
from pathlib import Path


def _server_blocks(config: str) -> list[str]:
    blocks: list[str] = []
    for match in re.finditer(r"(?m)^\s*server\s*\{", config):
        start = match.start()
        brace = config.find("{", match.start(), match.end())
        depth = 0
        for index in range(brace, len(config)):
            char = config[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(config[start : index + 1])
                    break
        else:
            raise AssertionError("unterminated nginx server block")
    return blocks



def _location_blocks(config: str) -> list[str]:
    blocks: list[str] = []
    for match in re.finditer(r"(?m)^\s*location\s+[^\n{]+\{", config):
        start = match.start()
        brace = config.find("{", match.start(), match.end())
        depth = 0
        for index in range(brace, len(config)):
            char = config[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(config[start : index + 1])
                    break
        else:
            raise AssertionError("unterminated nginx location block")
    return blocks


def test_nginx_location_directives_are_unique_per_server() -> None:
    """Reject duplicate locations inside one server without conflating sibling servers."""
    config = (Path(__file__).parents[1] / "aegis-platform/docker/nginx.conf").read_text()
    blocks = _server_blocks(config)
    assert blocks

    for block in blocks:
        locations = re.findall(
            r"^\s*location\s+([^\s{]+(?:\s+[^\s{]+)?)\s*\{",
            block,
            re.MULTILINE,
        )
        duplicates = sorted(
            {location for location in locations if locations.count(location) > 1}
        )
        assert duplicates == []


def test_legacy_vulnerability_route_cannot_fall_through_to_spa() -> None:
    config = (Path(__file__).parents[1] / "aegis-platform/docker/nginx.conf").read_text()

    assert "location /vulnerabilities/" in config
    assert "proxy_pass http://fastapi/api/v1/vulnerabilities/;" in config


def test_fastapi_upstream_keepalive_is_enabled_in_http_and_tls_gateways() -> None:
    root = Path(__file__).parents[1]
    for relative in (
        "aegis-platform/docker/nginx.conf",
        "aegis-platform/docker/nginx-ssl.conf",
    ):
        config = (root / relative).read_text(encoding="utf-8")
        assert "upstream fastapi {" in config
        assert "server fastapi:8001 resolve;" in config
        assert "keepalive 128;" in config
        assert "proxy_http_version 1.1;" in config
        assert 'proxy_set_header Connection "";' in config


def test_http_proxy_locations_redeclare_connection_keepalive_header() -> None:
    root = Path(__file__).parents[1]
    for relative in (
        "aegis-platform/docker/nginx.conf",
        "aegis-platform/docker/nginx-ssl.conf",
    ):
        config = (root / relative).read_text(encoding="utf-8")
        upstream_locations = [
            block
            for block in _location_blocks(config)
            if "proxy_pass http://fastapi" in block or "proxy_pass http://django" in block
        ]
        assert upstream_locations

        for block in upstream_locations:
            if "proxy_set_header Upgrade $http_upgrade;" in block:
                assert 'proxy_set_header Connection "upgrade";' in block
            else:
                assert 'proxy_set_header Connection "";' in block



def test_gateway_service_dns_tracks_recreated_containers() -> None:
    root = Path(__file__).parents[1]
    for relative in ("aegis-platform/docker/nginx.conf", "aegis-platform/docker/nginx-ssl.conf"):
        config = (root / relative).read_text(encoding="utf-8")
        assert "resolver 127.0.0.11 valid=5s ipv6=off;" in config
        for service, port in (("frontend", 80), ("django", 8000), ("fastapi", 8001)):
            assert f"zone {service}_peers 64k;" in config
            assert f"server {service}:{port} resolve;" in config

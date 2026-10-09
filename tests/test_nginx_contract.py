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


def test_vulnerability_spa_and_legacy_api_are_disambiguated() -> None:
    root = Path(__file__).parents[1]
    for relative in (
        "aegis-platform/docker/nginx.conf",
        "aegis-platform/docker/nginx-ssl.conf",
    ):
        config = (root / relative).read_text(encoding="utf-8")

        assert "location = /vulnerabilities {" in config
        assert "proxy_pass http://frontend;" in config
        assert "location /vulnerabilities/ {" in config
        assert 'if ($http_accept ~* "text/html") { return 418; }' in config
        assert "error_page 418 = @vulnerabilities_spa;" in config
        assert "location @vulnerabilities_spa {" in config
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


def test_tls_gateway_rewrites_same_host_upstream_redirects_to_https() -> None:
    config = (Path(__file__).parents[1] / "aegis-platform/docker/nginx-ssl.conf").read_text(encoding="utf-8")
    servers = _server_blocks(config)
    public = next(block for block in servers if "listen 443 ssl;" in block)

    assert "proxy_redirect http://$host/ https://$host/;" in public


def test_tls_gateway_exposes_only_authenticated_internal_alert_ingress():
    config = (Path(__file__).parents[1] / "aegis-platform/docker/nginx-ssl.conf").read_text(encoding="utf-8")
    assert "upstream alert_receiver {" in config
    assert "server alert_receiver:8080 resolve;" in config
    assert config.count("location = /_aegis/alerts {") == 1
    servers = _server_blocks(config)
    internal = next(block for block in servers if "listen 8443 ssl;" in block)
    public = next(block for block in servers if "listen 443 ssl;" in block)
    assert "location = /_aegis/alerts {" in internal
    assert "location = /_aegis/alerts {" not in public
    block = next(item for item in _location_blocks(internal) if "location = /_aegis/alerts" in item)
    assert "limit_except POST { deny all; }" in block
    assert "limit_req zone=aegis_alert_ingress burst=60 nodelay;" in block
    assert "client_max_body_size 1m;" in block
    assert "proxy_pass http://alert_receiver/alert;" in block
    assert "proxy_set_header Authorization $http_authorization;" in block
    assert "proxy_set_header X-Forwarded-Proto https;" in block


def test_nginx_does_not_expose_version_tokens() -> None:
    root = Path(__file__).parents[1]
    for relative in (
        "aegis-platform/docker/nginx.conf",
        "aegis-platform/docker/nginx-ssl.conf",
    ):
        config = (root / relative).read_text(encoding="utf-8")
        assert re.search(r"(?m)^\s*server_tokens\s+off\s*;", config)


def test_frontend_assets_spa_route_does_not_collide_with_vite_assets_directory() -> None:
    config = (
        Path(__file__).parents[1] / "aegis-platform/frontend/nginx.conf"
    ).read_text(encoding="utf-8")

    blocks = _location_blocks(config)
    exact_assets = next(block for block in blocks if re.search(r"location\s+=\s+/assets\s*\{", block))
    generic = next(block for block in blocks if re.search(r"location\s+/\s*\{", block))

    assert "try_files /index.html =404;" in exact_assets
    assert "try_files $uri $uri/ /index.html;" in generic
    assert config.index("location = /assets {") < config.index("location / {")


def test_real_gateway_dns_proof_accepts_only_version_pinned_mirror_images() -> None:
    import importlib.util

    path = Path(__file__).parents[0] / "production_gateway_dns_reality.py"
    spec = importlib.util.spec_from_file_location("gateway_dns_reality", path)
    assert spec and spec.loader
    reality = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reality)

    valid = "mirror.gcr.io/library/nginx:1.30.5-alpine"
    assert reality._validate_gateway_image(valid) == valid
    for invalid in (
        "nginx:1.30.5-alpine",
        "nginx:latest",
        "mirror.gcr.io/library/nginx:latest",
        "mirror.gcr.io/library/nginx:1.30-alpine",
    ):
        try:
            reality._validate_gateway_image(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Unpinned or unapproved gateway image accepted: {invalid}")

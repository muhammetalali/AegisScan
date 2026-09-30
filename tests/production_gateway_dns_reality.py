"""Prove production gateway recovery with actual Docker DNS and verified TLS.

Uses only uniquely named disposable containers and a private test network.
The legacy control must reproduce 502; current HTTP/TLS configs must recover
after all three upstream addresses change without restarting their gateway.
"""
from __future__ import annotations

import http.client
import json
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import time
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
PORTS = {"frontend": 80, "django": 8000, "fastapi": 8001}
BACKEND = r"""
import base64
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith("/ws/") and self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.send_header("X-Reality-Service", os.environ["SERVICE"])
            self.send_header("X-Reality-Generation", os.environ["GENERATION"])
            self.end_headers()
            self.wfile.flush()
            self.close_connection = True
            return
        body = json.dumps({
            "service": os.environ["SERVICE"],
            "generation": int(os.environ["GENERATION"]),
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "proto": self.headers.get("X-Forwarded-Proto", ""),
            "connection": self.headers.get("Connection", ""),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

ThreadingHTTPServer(("0.0.0.0", int(os.environ["PORT"])), Handler).serve_forever()
"""


def docker(*args: str, check: bool = True, timeout: int = 90) -> str:
    result = subprocess.run(
        ["docker", *args], text=True, capture_output=True, timeout=timeout,
    )
    if check and result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr[-4000:]}")
    return result.stdout.strip()


class Proof:
    def __init__(self, directory: Path, image: str):
        self.directory = directory
        self.image = image
        self.prefix = "aegis-gateway-reality-" + uuid.uuid4().hex[:12]
        self.network = self.prefix + "-net"
        self.containers: set[str] = set()
        self.generations = dict.fromkeys(PORTS, 1)
        self.cert = directory / "ssl" / "fullchain.pem"
        self.context = ssl.create_default_context(cafile=str(self.cert))
        self.holders = 0
        self.changes = []

    def start_backend(self, service: str) -> None:
        name = self.prefix + "-" + service
        self.containers.add(name)
        docker(
            "run", "-d", "--name", name, "--network", self.network,
            "--network-alias", service, "--read-only",
            "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
            "--security-opt", "no-new-privileges", "--user", "65534:65534",
            "-e", f"SERVICE={service}", "-e", f"PORT={PORTS[service]}",
            "-e", f"GENERATION={self.generations[service]}",
            "-v", f"{self.directory / 'backend.py'}:/backend.py:ro",
            "python:3.12-alpine", "python", "-B", "/backend.py",
        )

    def address(self, name: str) -> str:
        return docker(
            "inspect", "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name,
        )

    def replace_backend(self, service: str) -> None:
        name = self.prefix + "-" + service
        old_address = self.address(name)
        docker("rm", "-f", name)
        self.holders += 1
        holder = f"{self.prefix}-holder-{self.holders}"
        self.containers.add(holder)
        # Occupy the old address so the replacement cannot accidentally reuse it.
        docker(
            "run", "-d", "--name", holder, "--network", self.network,
            "--ip", old_address, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", "65534:65534",
            "python:3.12-alpine", "python", "-c", "import time; time.sleep(600)",
        )
        self.generations[service] += 1
        self.start_backend(service)
        new_address = self.address(name)
        assert old_address != new_address, (service, old_address, new_address)
        self.changes.append({
            "service": service, "before": old_address, "after": new_address,
            "generation": self.generations[service],
        })

    def start_gateway(self, config: Path, scheme: str) -> tuple[str, int]:
        name = self.prefix + "-gateway"
        self.containers.add(name)
        port = 443 if scheme == "https" else 80
        docker(
            "run", "-d", "--name", name, "--network", self.network,
            "--security-opt", "no-new-privileges",
            "-p", f"127.0.0.1::{port}",
            "-v", f"{config}:/etc/nginx/nginx.conf:ro",
            "-v", f"{self.cert.parent}:/etc/nginx/ssl:ro", self.image,
        )
        mapping = docker("port", name, f"{port}/tcp").splitlines()[0]
        return name, int(mapping.rsplit(":", 1)[1])

    def request(self, scheme: str, port: int, path: str, websocket: bool = False):
        if scheme == "https":
            connection = http.client.HTTPSConnection(
                "127.0.0.1", port, timeout=5, context=self.context,
            )
        else:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {}
        if websocket:
            headers = {
                "Upgrade": "websocket", "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            }
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            result_headers = dict((k.lower(), v) for k, v in response.getheaders())
            body = response.read(8192) if response.status != 101 else b""
            payload = json.loads(body) if response.status == 200 else body.decode(errors="replace")
            return response.status, result_headers, payload
        finally:
            connection.close()

    def wait_generation(self, scheme: str, port: int, service: str) -> None:
        path = {"fastapi": "/health", "django": "/django-health", "frontend": "/"}[service]
        deadline = time.monotonic() + 40
        last = None
        while time.monotonic() < deadline:
            try:
                last = self.request(scheme, port, path)
                if (
                    last[0] == 200 and last[2]["service"] == service
                    and last[2]["generation"] == self.generations[service]
                ):
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.25)
        raise AssertionError(f"{scheme} did not recover {service}: {last}")

    def assert_routes(self, scheme: str, port: int) -> None:
        cases = [
            ("/health", "fastapi", "/health"),
            ("/ready", "fastapi", "/ready"),
            ("/api/v1/workflows/probe?state=a%2Fb&limit=2", "fastapi", "/api/v1/workflows/probe?state=a%2Fb&limit=2"),
            ("/api/v1/auth/probe?next=%2F", "django", "/api/v1/auth/probe?next=%2F"),
            ("/api/v1/projects/probe", "django", "/api/v1/projects/probe"),
            ("/vulnerabilities/probe?state=open", "fastapi", "/api/v1/vulnerabilities/probe?state=open"),
            ("/scans/probe?details=1", "fastapi", "/api/v1/scans/probe?details=1"),
            ("/django-health", "django", "/health/"),
            ("/dashboard?tab=scans", "frontend", "/dashboard?tab=scans"),
        ]
        for path, service, upstream_path in cases:
            status, headers, payload = self.request(scheme, port, path)
            assert status == 200, (path, status, payload)
            assert payload == {
                "service": service, "generation": self.generations[service],
                "path": upstream_path, "host": "127.0.0.1",
                "proto": scheme, "connection": "",
            }, (path, payload)
            if scheme == "https":
                assert "max-age=31536000" in headers["strict-transport-security"]
                assert headers["x-content-type-options"] == "nosniff"
        status, headers, _ = self.request(scheme, port, "/ws/probe?channel=scans", True)
        assert status == 101, status
        assert headers["upgrade"].lower() == "websocket"
        assert headers["sec-websocket-accept"] == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        assert headers["x-reality-service"] == "fastapi"
        assert int(headers["x-reality-generation"]) == self.generations["fastapi"]

    def run(self) -> dict:
        docker("network", "create", self.network)
        for service in PORTS:
            self.start_backend(service)

        tls_config = ROOT / "aegis-platform/docker/nginx-ssl.conf"
        legacy = tls_config.read_text()
        legacy = re.sub(r"^\s*(?:resolver|resolver_timeout|zone)\s+[^;]+;\n", "", legacy, flags=re.MULTILINE)
        legacy = legacy.replace(" resolve;", ";")
        legacy_path = self.directory / "legacy-static.conf"
        legacy_path.write_text(legacy)
        gateway, port = self.start_gateway(legacy_path, "https")
        for service in PORTS:
            self.wait_generation("https", port, service)
        self.assert_routes("https", port)
        self.replace_backend("fastapi")
        deadline = time.monotonic() + 15
        legacy_status = None
        while time.monotonic() < deadline:
            legacy_status = self.request("https", port, "/health")[0]
            if legacy_status == 502:
                break
            time.sleep(0.25)
        assert legacy_status == 502, f"legacy control did not reproduce 502: {legacy_status}"
        docker("rm", "-f", gateway)

        results = []
        for scheme, config in (
            ("https", tls_config),
            ("http", ROOT / "aegis-platform/docker/nginx.conf"),
        ):
            gateway, port = self.start_gateway(config, scheme)
            gateway_id = docker("inspect", "--format", "{{.Id}}", gateway)
            for service in PORTS:
                self.wait_generation(scheme, port, service)
            self.assert_routes(scheme, port)
            for service in PORTS:
                self.replace_backend(service)
                self.wait_generation(scheme, port, service)
                self.assert_routes(scheme, port)
                assert docker("inspect", "--format", "{{.Id}}", gateway) == gateway_id
            results.append({"scheme": scheme, "gateway_unchanged": True, "routes_and_websocket": "passed"})
            docker("rm", "-f", gateway)
        return {
            "schema": "aegisscan.production-gateway-dns-reality.v1",
            "status": "passed", "image": self.image,
            "legacy_health_status": legacy_status, "checks": results,
            "address_changes": self.changes, "tls_verification": "enabled",
        }

    def cleanup(self) -> None:
        for name in sorted(self.containers):
            docker("rm", "-f", name, check=False)
        docker("network", "rm", self.network, check=False)


def main() -> None:
    image = yaml.safe_load((ROOT / "aegis-platform/docker-compose.yml").read_text())["services"]["nginx"]["image"]
    assert re.fullmatch(r"nginx:\d+\.\d+\.\d+-alpine", image), image
    docker("pull", image, timeout=180)
    docker("pull", "python:3.12-alpine", timeout=180)
    with tempfile.TemporaryDirectory(prefix="aegis-gateway-reality-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        (directory / "backend.py").write_text(BACKEND)
        (directory / "ssl").mkdir()
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(directory / "ssl/privkey.pem"),
            "-out", str(directory / "ssl/fullchain.pem"),
            "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ], check=True, capture_output=True, timeout=30)
        proof = Proof(directory, image)
        try:
            print(json.dumps(proof.run(), sort_keys=True))
        except Exception:
            gateway = proof.prefix + "-gateway"
            print(docker("logs", "--tail", "50", gateway, check=False))
            raise
        finally:
            proof.cleanup()


if __name__ == "__main__":
    main()

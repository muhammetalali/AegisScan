from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "0.0.0.0"
PORT = int(os.getenv("LAB_EXECUTOR_PORT", "9000"))
TOKEN = os.getenv("AEGIS_LAB_EXECUTOR_TOKEN", "").strip()
IMAGE = os.getenv("LAB_EXECUTOR_IMAGE", "aegisscan-network-lab:local")


def reply(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def target_kind(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        try:
            ipaddress.ip_network(target, strict=False)
            return "cidr"
        except ValueError:
            if len(target) > 253 or any(not part or len(part) > 63 for part in target.split(".")):
                raise ValueError("Invalid hostname")
            socket.getaddrinfo(target, None)
            return "hostname"


def parse_nmap(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    items: list[dict] = []
    for host in root.findall("host"):
        host_addr = next((a.attrib.get("addr") for a in host.findall("address") if a.attrib.get("addr")), None)
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            service = port.find("service")
            items.append({
                "host": host_addr,
                "protocol": port.attrib.get("protocol", "tcp"),
                "port": int(port.attrib.get("portid", "0")),
                "state": "open",
                "service": service.attrib.get("name") if service is not None else None,
                "product": service.attrib.get("product") if service is not None else None,
                "version": service.attrib.get("version") if service is not None else None,
            })
    return items


def parse_masscan(text: str) -> list[dict]:
    items: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] != "Discovered":
            continue
        try:
            port = int(parts[3].split("/")[0])
            host = parts[5]
        except (IndexError, ValueError):
            continue
        items.append({"host": host, "protocol": "tcp", "port": port, "state": "open"})
    return items


def run(command: list[str], timeout: int) -> dict:
    started = time.time()
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return_code = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        return_code = 124
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + "\nCommand timed out"
    finished = time.time()
    return {
        "return_code": return_code,
        "stdout": stdout,
        "stderr": stderr,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished)),
    }


def execute(tool: str, target: str, profile: str) -> dict:
    if tool not in {"nmap", "masscan"}:
        return {"status": "failed", "error": "Unsupported tool"}
    try:
        kind = target_kind(target)
    except ValueError as exc:
        return {"status": "failed", "error": str(exc)}
    resolved = []
    if kind == "hostname":
        resolved = sorted({item[4][0] for item in socket.getaddrinfo(target, None) if item[4]})

    execution_id = str(uuid.uuid4())
    if tool == "nmap":
        if profile not in {"connect-discovery", "service-enumeration"}:
            return {"status": "failed", "error": "Unsupported Nmap profile"}
        # Use a TCP connect scan so the lab agent can run Nmap as its non-root user.
        # Service/version detection remains real (-sV); no synthetic observations are created.
        command = ["nmap", "-Pn", "-T10", "--open", "-sT", "-sV", "-oX", "-", target]
        parser = parse_nmap
        timeout = 180
    else:
        if profile != "low-rate-discovery":
            return {"status": "failed", "error": "Unsupported Masscan profile"}
        command = ["masscan", target, "-p1-1024", "--rate", "1000", "--wait", "3"]
        parser = parse_masscan
        timeout = 120

    result = run(command, timeout)
    version_proc = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=10, check=False)
    version_text = version_proc.stdout.strip() or version_proc.stderr.strip()
    version_line = next((line.strip() for line in version_text.splitlines() if line.strip()), "unknown")
    if result["return_code"] != 0:
        return {
            "status": "failed",
            "execution_id": execution_id,
            "target_type": kind,
            "resolved_addresses": resolved,
            "command": command,
            "executor_image": IMAGE,
            "tool_version": version_line,
            **result,
        }
    raw_sha256 = hashlib.sha256(result["stdout"].encode("utf-8")).hexdigest()
    return {
        "status": "completed",
        "execution_id": execution_id,
        "target_type": kind,
        "resolved_addresses": resolved,
        "command": command,
        "executor_image": IMAGE,
        "tool_version": version_line,
        "observations": parser(result["stdout"]),
        "stdout_sha256": raw_sha256,
        **result,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AegisScanLabExecutor/1.1"

    def do_GET(self) -> None:
        if self.path == "/health":
            reply(self, 200, {"status": "healthy", "executor": "network-lab", "tools": ["nmap", "masscan"]})
            return
        reply(self, 404, {"detail": "Not found"})

    def do_POST(self) -> None:
        if self.path != "/v1/execute":
            reply(self, 404, {"detail": "Not found"})
            return
        if TOKEN and self.headers.get("Authorization", "") != f"Bearer {TOKEN}":
            reply(self, 401, {"detail": "Unauthorized"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > 32768:
                raise ValueError("Invalid request size")
            body = json.loads(self.rfile.read(size))
            target = str(body.get("target", "")).strip()
            tool = str(body.get("tool", "")).strip()
            profile = str(body.get("profile", "")).strip()
            if not target:
                raise ValueError("Target is required")
            reply(self, 200, execute(tool, target, profile))
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            reply(self, 400, {"status": "failed", "error": str(exc)})

    def log_message(self, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

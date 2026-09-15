#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.server
import ssl
import socketserver
import struct
import threading
from urllib.parse import parse_qs, urlsplit

API_HOST = "dnsrepo.noc.org"
BGP_HOST = "bgp.tools"
TARGET = "parity.test"
TARGET_IP = "172.30.0.10"
RESULTS = (
    "www.parity.test",
    "api.parity.test",
    "mail.parity.test",
)


def _parse_question(packet: bytes) -> tuple[str, int, int, bytes]:
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    if struct.unpack("!H", packet[4:6])[0] != 1:
        raise ValueError("fixture accepts exactly one DNS question")
    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[offset:offset + length].decode("ascii").lower())
        offset += length
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    offset += 4
    return ".".join(labels), qtype, qclass, packet[12:offset]


def _response(packet: bytes, fixture_ip: str) -> bytes:
    query_id = packet[:2]
    request_flags = struct.unpack("!H", packet[2:4])[0]
    name, qtype, qclass, question = _parse_question(packet)
    answers: list[bytes] = []
    if qclass != 1:
        rcode = 4
    elif name not in {API_HOST, BGP_HOST, TARGET}:
        rcode = 3
    else:
        rcode = 0
        if qtype in {1, 255}:
            resolved_ip = fixture_ip if name in {API_HOST, BGP_HOST} else TARGET_IP
            rdata = bytes(int(part) for part in resolved_ip.split("."))
            answers.append(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, len(rdata)) + rdata)
    flags = 0x8000 | 0x0400 | (request_flags & 0x0100) | rcode
    header = query_id + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0)
    return header + question + b"".join(answers)


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class HTTPSFixture(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path != "/" or query.get("domain") != [TARGET]:
            body = b"fixture request rejected\n"
            self.send_response(404)
        else:
            body = (
                "<!doctype html><html><body>"
                + "".join(f"<div>{name}</div>" for name in RESULTS)
                + "</body></html>\n"
            ).encode("ascii")
            self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--fixture-ip", default="172.30.0.53")
    args = parser.parse_args()

    class UDPHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data, sock = self.request
            try:
                response = _response(data, args.fixture_ip)
            except (ValueError, UnicodeError):
                return
            sock.sendto(response, self.client_address)

    class TCPHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            prefix = self.request.recv(2)
            if len(prefix) != 2:
                return
            length = struct.unpack("!H", prefix)[0]
            packet = b""
            while len(packet) < length:
                chunk = self.request.recv(length - len(packet))
                if not chunk:
                    return
                packet += chunk
            try:
                response = _response(packet, args.fixture_ip)
            except (ValueError, UnicodeError):
                return
            self.request.sendall(struct.pack("!H", len(response)) + response)

    udp = UDPServer(("0.0.0.0", 53), UDPHandler)
    tcp = TCPServer(("0.0.0.0", 53), TCPHandler)
    https = http.server.ThreadingHTTPServer(("0.0.0.0", 443), HTTPSFixture)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    https.socket = context.wrap_socket(https.socket, server_side=True)

    threading.Thread(target=udp.serve_forever, name="dns-udp", daemon=True).start()
    threading.Thread(target=tcp.serve_forever, name="dns-tcp", daemon=True).start()
    threading.Thread(target=https.serve_forever, name="https", daemon=True).start()
    print(
        f"AEGIS_AMASS_PASSIVE_FIXTURE_READY {API_HOST} {BGP_HOST} {args.fixture_ip}",
        flush=True,
    )
    threading.Event().wait()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import socketserver
import struct
import threading

ZONE = "parity.test"
A_RECORDS = {
    "parity.test": "172.28.0.10",
    "www.parity.test": "172.28.0.11",
    "mail.parity.test": "172.28.0.12",
    "api.parity.test": "172.28.0.13",
    "ns1.parity.test": "172.28.0.53",
}


def _encode_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def _parse_question(packet: bytes) -> tuple[str, int, int, bytes]:
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    qdcount = struct.unpack("!H", packet[4:6])[0]
    if qdcount != 1:
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
        if length & 0xC0:
            raise ValueError("compressed query name is not accepted")
        if length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[offset:offset + length].decode("ascii").lower())
        offset += length
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    offset += 4
    return ".".join(labels), qtype, qclass, packet[12:offset]


def _a_rdata(address: str) -> bytes:
    return bytes(int(part) for part in address.split("."))


def _rr(owner: bytes, rtype: int, rdata: bytes, ttl: int = 60) -> bytes:
    return owner + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def _response(packet: bytes) -> bytes:
    query_id = packet[:2]
    request_flags = struct.unpack("!H", packet[2:4])[0]
    name, qtype, qclass, question = _parse_question(packet)
    if qclass != 1:
        rcode = 4  # NOTIMP
        answers: list[bytes] = []
    elif name != ZONE and not name.endswith("." + ZONE):
        rcode = 5  # REFUSED
        answers = []
    else:
        answers = []
        owner = b"\xc0\x0c"
        if qtype in {1, 255} and name in A_RECORDS:
            answers.append(_rr(owner, 1, _a_rdata(A_RECORDS[name])))
        if name == ZONE and qtype in {2, 255}:
            answers.append(_rr(owner, 2, _encode_name("ns1.parity.test")))
        if name == ZONE and qtype in {15, 255}:
            answers.append(_rr(owner, 15, struct.pack("!H", 10) + _encode_name("mail.parity.test")))
        if name == ZONE and qtype in {6, 255}:
            soa = (
                _encode_name("ns1.parity.test")
                + _encode_name("hostmaster.parity.test")
                + struct.pack("!IIIII", 2026091501, 60, 60, 3600, 60)
            )
            answers.append(_rr(owner, 6, soa))
        if name == ZONE and qtype in {16, 255}:
            value = b"aegis-m3-deterministic-fixture"
            answers.append(_rr(owner, 16, bytes([len(value)]) + value))
        known = name in A_RECORDS or name == ZONE
        rcode = 0 if answers or known else 3  # NXDOMAIN for unknown in-zone labels

    flags = 0x8000 | 0x0400 | (request_flags & 0x0100) | rcode
    header = query_id + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0)
    return header + question + b"".join(answers)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        try:
            response = _response(data)
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
            response = _response(packet)
        except (ValueError, UnicodeError):
            return
        self.request.sendall(struct.pack("!H", len(response)) + response)


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main() -> None:
    udp = UDPServer(("0.0.0.0", 53), UDPHandler)
    tcp = TCPServer(("0.0.0.0", 53), TCPHandler)
    threading.Thread(target=tcp.serve_forever, name="dns-tcp", daemon=True).start()
    print("AEGIS_M3_DNS_FIXTURE_READY parity.test 172.28.0.53", flush=True)
    try:
        udp.serve_forever()
    finally:
        udp.server_close()
        tcp.shutdown()
        tcp.server_close()


if __name__ == "__main__":
    main()

from __future__ import annotations

import socketserver
import struct
import threading
from typing import Any

from .governed_oast import OASTRuntimeError, ingest_dns_callback


_MAX_DNS_PACKET = 1232


class DNSPacketError(ValueError):
    pass


def parse_dns_question(packet: bytes) -> tuple[str, int, bytes]:
    if not isinstance(packet, (bytes, bytearray)) or not 12 <= len(packet) <= _MAX_DNS_PACKET:
        raise DNSPacketError('DNS packet size is invalid')
    raw = bytes(packet)
    _query_id, _flags, qdcount, _ancount, _nscount, _arcount = struct.unpack('!HHHHHH', raw[:12])
    if qdcount != 1:
        raise DNSPacketError('OAST DNS collector requires exactly one question')

    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(raw):
            raise DNSPacketError('DNS question name is truncated')
        length = raw[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise DNSPacketError('Compressed DNS question names are not accepted')
        if length > 63 or offset + length > len(raw):
            raise DNSPacketError('DNS label is invalid')
        label_bytes = raw[offset:offset + length]
        offset += length
        try:
            label = label_bytes.decode('ascii').lower()
        except UnicodeDecodeError as exc:
            raise DNSPacketError('DNS callback labels must be ASCII') from exc
        if not label or any(ch not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for ch in label):
            raise DNSPacketError('DNS callback label contains invalid characters')
        labels.append(label)
        if len(labels) > 16:
            raise DNSPacketError('DNS callback name contains too many labels')

    if offset + 4 > len(raw):
        raise DNSPacketError('DNS question type/class is truncated')
    qtype, qclass = struct.unpack('!HH', raw[offset:offset + 4])
    if qclass != 1:
        raise DNSPacketError('OAST DNS collector accepts IN-class questions only')
    question_end = offset + 4
    qname = '.'.join(labels)
    if not qname or len(qname) > 253:
        raise DNSPacketError('DNS callback name is invalid')
    return qname, int(qtype), raw[12:question_end]


def nxdomain_response(packet: bytes, question: bytes) -> bytes:
    if len(packet) < 4:
        raise DNSPacketError('DNS packet header is truncated')
    query_id, request_flags = struct.unpack('!HH', packet[:4])
    response_flags = 0x8403 | (request_flags & 0x0100)  # QR + AA + copied RD + NXDOMAIN
    header = struct.pack('!HHHHHH', query_id, response_flags, 1, 0, 0, 0)
    return header + question


class GovernedOASTDNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class=None):
        super().__init__(
            server_address,
            handler_class or GovernedOASTDNSHandler,
        )
        self._events_lock = threading.Lock()
        self.accepted_events: list[dict[str, Any]] = []

    def record(self, event: dict[str, Any]) -> None:
        with self._events_lock:
            self.accepted_events.append(dict(event))


class GovernedOASTDNSHandler(socketserver.BaseRequestHandler):
    server: GovernedOASTDNSServer

    def handle(self) -> None:
        packet, sock = self.request
        try:
            qname, qtype, question = parse_dns_question(packet)
        except DNSPacketError:
            return
        try:
            result = ingest_dns_callback(
                qname=qname,
                source_ip=str(self.client_address[0]),
                qtype=qtype,
            )
            self.server.record(result)
        except OASTRuntimeError:
            pass
        response = nxdomain_response(packet, question)
        sock.sendto(response, self.client_address)


def start_dns_collector(
    host: str = '0.0.0.0',
    port: int = 53535,
) -> GovernedOASTDNSServer:
    if not 0 <= int(port) <= 65535:
        raise ValueError('DNS collector port is invalid')
    return GovernedOASTDNSServer((str(host), int(port)))


__all__ = [
    'DNSPacketError',
    'GovernedOASTDNSServer',
    'nxdomain_response',
    'parse_dns_question',
    'start_dns_collector',
]

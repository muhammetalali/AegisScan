#!/usr/bin/env python3
from __future__ import annotations

import socketserver
import threading

RESPONSES = {
    22: b'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7\r\n',
    80: b'HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 2\r\n\r\nOK',
}


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        port = self.server.server_address[1]
        self.request.sendall(RESPONSES[port])


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    servers = [Server(('0.0.0.0', port), Handler) for port in RESPONSES]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print('AEGIS_NMAP_PARITY_FIXTURE_READY', flush=True)
    threading.Event().wait()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

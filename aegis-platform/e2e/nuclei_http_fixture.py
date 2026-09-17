#!/usr/bin/env python3
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "0.0.0.0"
PORT = 8080


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/healthz":
            body = b"ok\n"
            status = 200
        elif self.path == "/aegis-nuclei-parity":
            body = b"AEGIS_NUCLEI_PARITY_OK\n"
            status = 200
        else:
            body = b"not found\n"
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Aegis-Parity", "nuclei")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    print("AEGIS_NUCLEI_PARITY_FIXTURE_READY", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

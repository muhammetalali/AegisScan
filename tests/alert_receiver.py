#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EVIDENCE = Path("/evidence/alert.json")
MAX_BODY = 1024 * 1024


class Receiver(BaseHTTPRequestHandler):
    def _empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/ready":
            self._empty(200)
            return
        self._empty(404)

    def do_POST(self) -> None:
        if self.path != "/aegis":
            self._empty(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._empty(400)
            return
        if length <= 0 or length > MAX_BODY:
            self._empty(413)
            return
        payload = self.rfile.read(length)
        if len(payload) != length:
            self._empty(400)
            return
        try:
            with EVIDENCE.open("ab", buffering=0) as evidence:
                evidence.write(payload + b"\n")
                os.fsync(evidence.fileno())
        except OSError as exc:
            print(f"alert receiver evidence write failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            self._empty(500)
            return
        self._empty(200)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"alert-receiver: {fmt % args}", file=sys.stderr, flush=True)


ThreadingHTTPServer(("0.0.0.0", int(os.getenv("PORT", "8080"))), Receiver).serve_forever()

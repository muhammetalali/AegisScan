#!/usr/bin/env python3
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)
        with open("/evidence/alert.json", "ab") as evidence:
            evidence.write(payload + b"\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


HTTPServer(("0.0.0.0", int(os.getenv("PORT", "8080"))), Receiver).serve_forever()

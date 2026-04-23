#!/usr/bin/env python3
"""Minimal in-memory pkarr HTTP relay.
PUT /<pubkey>: accept a signed packet body, store by pubkey.
GET /<pubkey>: return the stored body.
No upstream, no rate-limiting. Intended for local testing of
the `oh` CLI + web app without burning through the public
pkarr-relay quotas.
Runs on 127.0.0.1:8080 with CORS wildcard so browser fetches
from any origin work.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

STORE = {}
LOCK = Lock()


def cors(h):
    h.send_header("Access-Control-Allow-Origin", "*")
    h.send_header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
    h.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
    h.send_header("Access-Control-Max-Age", "3600")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        msg = fmt % args
        print(f"[relay] {self.command} {self.path} -> {msg}")

    def do_OPTIONS(self):
        self.send_response(204)
        cors(self)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        key = self.path.lstrip("/")
        with LOCK:
            body = STORE.get(key)
        if body is None:
            self.send_response(404)
            cors(self)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        cors(self)
        self.send_header("Content-Type", "application/pkarr.org.relays.v1+octet")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        key = self.path.lstrip("/")
        with LOCK:
            STORE[key] = body
        self.send_response(200)
        cors(self)
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    print("[relay] listening on 0.0.0.0:8080 (in-memory pkarr store)")
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()

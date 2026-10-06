"""Toniebox simulator: connects to a (sandboxed) TeddyCloud server like a box does,
with a client certificate signed by the server's own CA and no SNI."""

import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BIN = REPO / "bin" / "teddycloud"


class Box:
    def __init__(self, mac, base_dir, host, https_port, user_agent="TB/sim", profile=None):
        if profile is not None:
            mac, user_agent = profile.mac, profile.user_agent
            if profile.generation == 2:
                raise NotImplementedError("TB2 needs the EC client certificate of the server_tb2 CA and its TLS chain, not simulated yet")
        self.profile = profile
        self.mac = mac.lower()
        self.host = host
        self.port = https_port
        self.user_agent = user_agent
        self._dir = tempfile.TemporaryDirectory(prefix="tcbox_")
        # the sandbox is a copy of the template, so they share the CA: box certificates
        # (slow RSA keygen) are cached in the template and reused by every test run
        template = os.environ.get("TC_TEMPLATE")
        cache = Path(template) / "boxcerts" / self.mac if template else None
        if cache and (cache / "client.pem").exists():
            self.cert, self.key = cache / "client.pem", cache / "private.pem"
            return
        d = Path(self._dir.name)
        # the CLI writes ca.der/client.der/private.der; Python's ssl needs PEM
        subprocess.run([BIN, "--base_path", base_dir, "--generate-client-cert", self.mac, "--destination", d],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "x509", "-inform", "der", "-in", d / "client.der", "-outform", "pem", "-out", d / "client.pem"], check=True)
        subprocess.run(["openssl", "rsa", "-inform", "der", "-in", d / "private.der", "-outform", "pem", "-out", d / "private.pem"],
                       check=True, capture_output=True)
        self.cert, self.key = d / "client.pem", d / "private.pem"
        if cache:
            cache.mkdir(parents=True, exist_ok=True)
            for f in ("client.pem", "private.pem"):
                shutil.copy(d / f, cache / f)

    def close(self):
        self._dir.cleanup()

    def connect(self, use_cert=True):
        # IP literal: no SNI, like a real box (the server picks other certs when SNI is present)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = self.profile.tls if self.profile else None
        if tls:
            ctx.minimum_version = getattr(ssl.TLSVersion, tls.min_version)
            ctx.maximum_version = getattr(ssl.TLSVersion, tls.max_version)
            if tls.ciphers:
                ctx.set_ciphers(tls.ciphers)
        if use_cert:
            ctx.load_cert_chain(certfile=self.cert, keyfile=self.key)
        return ctx.wrap_socket(socket.create_connection((self.host, self.port), timeout=5), server_hostname=(tls.sni if tls and tls.sni else None))

    def request(self, method, path, body=b"", headers=None, use_cert=True):
        """One request on a fresh connection. Returns (status, headers, body)."""
        s = self.connect(use_cert)
        try:
            head = f"{method} {path} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: {self.user_agent}\r\nConnection: close\r\n"
            head += f"Content-Length: {len(body)}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
            s.sendall(head.encode() + b"\r\n" + body)
            data = b""
            while chunk := s.recv(65536):
                data += chunk
        finally:
            s.close()
        raw_head, _, payload = data.partition(b"\r\n\r\n")
        lines = raw_head.decode(errors="replace").split("\r\n")
        return int(lines[0].split()[1]), dict(l.split(": ", 1) for l in lines[1:] if ": " in l), payload

    def rtnl(self, *frames, keep_open=False):
        """Sends raw RTNL frames (see rtnl.frame). Returns the socket if keep_open."""
        s = self.connect()
        for f in frames:
            s.sendall(f)
        if keep_open:
            return s
        time.sleep(0.3)  # a real box keeps the connection open; let the server read before the close
        s.close()


class SseListener:
    """Collects the server-sent events of /api/sse (plain HTTP port) in the background."""

    def __init__(self, host, http_port):
        self.events = []  # (event name, data)
        self._conn = http.client.HTTPConnection(host, http_port, timeout=30)
        self._conn.request("GET", "/api/sse")
        self._resp = self._conn.getresponse()
        self._stop = False
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self):
        # the response is chunked and the server writes events in many small pieces:
        # let http.client dechunk (read1) and split the events on the blank line
        buf = b""
        try:
            while not self._stop:
                chunk = self._resp.read1(65536)
                if not chunk:
                    return
                buf += chunk
                while b"\n\n" in buf:
                    raw, buf = buf.split(b"\n\n", 1)
                    name = data = None
                    for line in raw.decode(errors="replace").split("\n"):
                        if line.startswith("event:"):
                            name = line[6:].strip()
                        elif line.startswith("data:"):
                            data = line[5:].strip()
                    if name and data:
                        try:
                            self.events.append((name, json.loads(data)["data"]))
                        except (ValueError, KeyError):
                            self.events.append((name, data))
        except (OSError, ValueError, AttributeError, http.client.HTTPException):  # closed under our feet
            pass

    def wait_for(self, name, timeout=5, count=1):
        deadline = time.time() + timeout
        while time.time() < deadline:
            found = [d for n, d in self.events if n == name]
            if len(found) >= count:
                return found
            time.sleep(0.05)
        raise AssertionError(f"no '{name}' event within {timeout}s, got {[n for n, _ in self.events]}")

    def close(self):
        self._stop = True
        try:
            self._conn.sock.shutdown(socket.SHUT_RDWR)  # unblocks the reader thread
        except (OSError, AttributeError):
            pass
        self._thread.join(2)
        self._conn.close()

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
        self._contexts = {}
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

    def connect(self, use_cert=True, session=None):
        # IP literal: no SNI, like a real box (the server picks other certs when SNI is present)
        ctx = self._contexts.get(use_cert) or self._context(use_cert)
        return ctx.wrap_socket(socket.create_connection((self.host, self.port), timeout=5),
                               server_hostname=(self.profile.tls.sni if self.profile and self.profile.tls.sni else None),
                               session=session)

    def _context(self, use_cert):
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
        self._contexts[use_cert] = ctx
        return ctx

    def request(self, method, path, body=b"", headers=None, use_cert=True, session=None):
        """One request on a fresh connection. Returns (status, headers, body)."""
        s = self.connect(use_cert, session)
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

    def keep_alive(self):
        """A connection that sends requests like the firmware does, see BoxConnection."""
        return BoxConnection(self)

    def openssl_request(self, method, path):
        """One request over openssl s_client with the profile's TLS parameters (signature algorithms,
        curves), which Python's ssl module cannot set. Returns the raw response."""
        req = f"{method} {path} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: {self.user_agent}\r\nConnection: close\r\n\r\n"
        cmd = ["openssl", "s_client", "-connect", f"{self.host}:{self.port}", "-noservername", "-quiet", "-ign_eof",
               "-cert", str(self.cert), "-key", str(self.key), *self.profile.tls.openssl]
        return subprocess.run(cmd, input=req.encode(), capture_output=True, timeout=10).stdout

    def rtnl(self, *frames, keep_open=False):
        """Sends raw RTNL frames (see rtnl.frame). Returns the socket if keep_open."""
        s = self.connect()
        for f in frames:
            s.sendall(f)
        if keep_open:
            return s
        time.sleep(0.3)  # a real box keeps the connection open; let the server read before the close
        s.close()


class BoxConnection:
    """Keep-alive connection with the request format of the profile: Host and User-Agent, the profile's
    extra headers, Content-Length only with a body, and the body in its own TLS record."""

    def __init__(self, box):
        self.box = box
        self.sock = box.connect()
        self._buf = b""

    def request(self, method, path, body=b"", headers=None):
        p = self.box.profile
        lines = [f"{method} {path} HTTP/1.1", f"Host: {self.box.host}", f"User-Agent: {self.box.user_agent}"]
        lines += [f"{k}: {v.format(mac=self.box.mac)}" for k, v in p.extra_headers]
        lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
        if body:
            lines.append(f"Content-Length: {len(body)}")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        if body:
            self.sock.sendall(body)
        return self._response()

    def _response(self):
        while b"\r\n\r\n" not in self._buf:
            self._recv()
        raw_head, self._buf = self._buf.split(b"\r\n\r\n", 1)
        self.header_size = len(raw_head) + 4
        lines = raw_head.decode(errors="replace").split("\r\n")
        headers = dict(l.split(": ", 1) for l in lines[1:] if ": " in l)
        length = int(headers.get("Content-Length", 0))
        while len(self._buf) < length:
            self._recv()
        body, self._buf = self._buf[:length], self._buf[length:]
        return int(lines[0].split()[1]), headers, body

    def _recv(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("server closed the connection")
        self._buf += chunk

    def finish(self, ending, timeout=5):
        """Ends the connection like the firmware does (see BoxProfile.endings). Returns once the server has
        closed its side too."""
        self.sock.settimeout(timeout)
        if ending == "close_notify":
            raw = self.sock.unwrap()  # raises unless the server answers with its close_notify
        else:
            self.sock.shutdown(socket.SHUT_WR)  # a plain FIN: SSLSocket.shutdown drops the TLS layer first
            raw = self.sock
        while raw.recv(4096):
            pass
        raw.close()

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


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

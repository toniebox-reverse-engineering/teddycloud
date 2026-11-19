"""Fake Boxine cloud: a local HTTPS server (self-signed certificate) the server under test
can be pointed at with cloud.remote_hostname/cloud.remote_port. Records every request."""

import http.server
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path


class FakeCloud:
    def __init__(self, sandbox):
        """The server validates the cloud certificate against its client CA (certs/client/ca.der, which the
        test template sets to the server CA) and the host name, so the certificate is signed by that CA
        for "localhost" - point cloud.remote_hostname at localhost."""
        self.requests = []  # (method, path, headers dict, body)
        self.drops = []  # (path, bytes sent) of every connection stream() dropped
        self.completed = []  # (path, time) of every body stream() sent completely
        self.script = self._default
        self._dir = tempfile.TemporaryDirectory(prefix="tccloud_")
        d = Path(self._dir.name)
        certs = Path(sandbox) / "certs" / "server"
        run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)  # noqa: E731
        run("pkey", "-in", certs / "ca-key.pem", "-out", d / "ca-key.pem")  # CRLF PEM, the server logs it as DER
        run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", d / "key.pem", "-out", d / "csr.pem", "-subj", "/CN=localhost")
        (d / "ext.cnf").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
        run("x509", "-req", "-in", d / "csr.pem", "-CA", certs / "ca-root.pem", "-CAkey", d / "ca-key.pem", "-CAcreateserial",
            "-out", d / "cert.pem", "-days", "2", "-extfile", d / "ext.cnf")
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def handle_any(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
                outer.requests.append((self.command, self.path, dict(self.headers), body))
                outer.script(self)

            do_GET = do_POST = do_PUT = handle_any

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(d / "cert.pem", d / "key.pem")
        self._srv.socket = ctx.wrap_socket(self._srv.socket, server_side=True)
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    @staticmethod
    def reply(h, status=200, body=b"", headers=None):
        h.send_response(status)
        for k, v in (headers or {}).items():
            h.send_header(k, v)
        h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        h.wfile.write(body)

    def stream(self, h, body, headers=None, chunk=16384, idle_timeout=None, drop_after=None, rate=None, framing="length",
               hold=None, hold_at=0):
        """Sends a 200 with the body in chunks, like the content CDN. idle_timeout: drops the connection when a
        chunk could not be sent for that long (the client stopped reading; nginx's send_timeout, 60 s at Boxine).
        drop_after: drops it after that many body bytes. rate: bytes per second (a slow cloud). framing: "length"
        (Content-Length), "chunked" (Transfer-Encoding) or "close" (neither, the body ends with the connection).
        A drop is a plain FIN without close_notify and is recorded in self.drops, a complete body in
        self.completed. headers: a dict, or (name, value) pairs for a name sent more than once. hold: a
        threading.Event; from hold_at body bytes on, until it is set, only a trickle is sent (1 KB every 0.5 s,
        so the server's client does not time out), then the rest."""
        h.send_response(200)
        headers = headers or {"Content-Type": "binary/octet-stream"}
        for k, v in (headers.items() if isinstance(headers, dict) else headers):
            h.send_header(k, v)
        if framing == "length":
            h.send_header("Content-Length", str(len(body)))
        elif framing == "chunked":
            h.send_header("Transfer-Encoding", "chunked")
        else:
            h.send_header("Connection", "close")
            h.close_connection = True
        h.end_headers()
        # a small send buffer, so a client that stops reading stalls the sender soon (no autotuning)
        h.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        h.connection.settimeout(idle_timeout)
        sent = 0
        try:
            while sent < len(body):
                n = min(chunk, len(body) - sent)
                if drop_after is not None:
                    if sent >= drop_after:
                        raise ConnectionAbortedError("drop_after")
                    n = min(n, drop_after - sent)
                if hold is not None and sent >= hold_at and not hold.is_set():
                    n = min(n, 1024)
                    hold.wait(0.5)
                elif rate:
                    time.sleep(n / rate)
                data = body[sent:sent + n]
                h.wfile.write(b"%x\r\n%s\r\n" % (n, data) if framing == "chunked" else data)
                sent += n
            if framing == "chunked":
                h.wfile.write(b"0\r\n\r\n")
            self.completed.append((h.path, time.time()))
        except (OSError, ssl.SSLError):  # socket.timeout is an OSError
            self.drops.append((h.path, sent))
            h.close_connection = True
            try:
                h.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    TIME = b"1700000000"  # a valid time, but far from the local one

    def _default(self, h):
        self.reply(h, 200, self.TIME, {"Content-Type": "text/plain"})

    def close(self):
        self._srv.shutdown()
        self._srv.server_close()
        self._dir.cleanup()

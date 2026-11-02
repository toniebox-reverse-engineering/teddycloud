"""Fake Boxine cloud: a local HTTPS server (self-signed certificate) the server under test
can be pointed at with cloud.remote_hostname/cloud.remote_port. Records every request."""

import http.server
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path


class FakeCloud:
    def __init__(self, sandbox):
        """The server validates the cloud certificate against its client CA (certs/client/ca.der, which the
        test template sets to the server CA) and the host name, so the certificate is signed by that CA
        for "localhost" - point cloud.remote_hostname at localhost."""
        self.requests = []  # (method, path, headers dict, body)
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

    TIME = b"1700000000"  # a valid time, but far from the local one

    def _default(self, h):
        self.reply(h, 200, self.TIME, {"Content-Type": "text/plain"})

    def close(self):
        self._srv.shutdown()
        self._srv.server_close()
        self._dir.cleanup()

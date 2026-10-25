#!/usr/bin/env python3
"""
Regression test for the pooled HTTPS connection reuse leaking client
certificate authentication (`connection->private.authenticated`) from one
client to another.

Recommended usage:

1) Fully automated via Makefile (build + start server + generate a box
   certificate + run the test + stop server):
   make test_auth_pool_reuse_with_server

2) Against an already running TeddyCloud server, given a box client
   certificate signed by that server's own CA (see
   `--generate-client-cert <mac> --destination <dir>`):
   TEDDYCLOUD_HTTPS_API_PORT=443 \
   TEDDYCLOUD_CLIENT_CERT=/path/client.pem \
   TEDDYCLOUD_CLIENT_KEY=/path/private.pem \
   python3 tests/py/test_auth_pool_reuse.py
"""

import concurrent.futures
import os
import socket
import ssl
import time
import unittest

HOST = os.environ.get("TEDDYCLOUD_HOST", "127.0.0.1")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "18454"))
CLIENT_CERT = os.environ.get("TEDDYCLOUD_CLIENT_CERT")
CLIENT_KEY = os.environ.get("TEDDYCLOUD_CLIENT_KEY")

PATH = "/v1/time"
# Matches the informal measurement that first found this bug: 10
# certificate-authenticated connections leave enough pooled slots
# `authenticated`, then 16 concurrent certificate-less requests land on
# some of them.
AUTH_CONNECTIONS = 10
NOAUTH_CONCURRENT = 16
ROUNDS = 5


class AuthPoolReuseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CLIENT_CERT or not CLIENT_KEY:
            raise RuntimeError(
                "TEDDYCLOUD_CLIENT_CERT and TEDDYCLOUD_CLIENT_KEY must point at a box "
                "client certificate signed by the running server's own CA, e.g.:\n"
                "  ./bin/teddycloud --generate-client-cert deadbeef0001 --destination /tmp/box-cert\n"
                "or run `make test_auth_pool_reuse_with_server`, which does this for you."
            )
        cls._wait_for_server()

    @classmethod
    def _connect(cls, use_cert):
        # Connect by IP literal so no SNI is sent: this server picks a
        # different (unrelated) certificate chain whenever SNI is present,
        # and a real Toniebox never sends one either.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if use_cert:
            ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
        raw = socket.create_connection((HOST, HTTPS_API_PORT), timeout=5)
        return ctx.wrap_socket(raw)

    @classmethod
    def _status_line(cls, use_cert):
        s = cls._connect(use_cert)
        try:
            s.sendall(f"GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.split(b"\r\n", 1)[0].decode(errors="replace")
        finally:
            s.close()

    @classmethod
    def _wait_for_server(cls, timeout_seconds=12.0):
        deadline = time.time() + timeout_seconds
        last_error = None
        while time.time() < deadline:
            try:
                if "401" in cls._status_line(use_cert=False):
                    return
            except Exception as exc:
                last_error = exc
            time.sleep(0.5)
        raise RuntimeError(
            f"TeddyCloud HTTPS API not reachable at {HOST}:{HTTPS_API_PORT}. "
            f"Original error: {last_error!r}"
        )

    def test_no_cert_request_never_reuses_an_authenticated_pooled_slot(self):
        """A request presenting no client certificate must always get 401,
        never the 200 a prior, unrelated client's certificate earned on the
        same pooled connection slot."""
        for round_num in range(1, ROUNDS + 1):
            with self.subTest(round=round_num):
                # Burn AUTH_CONNECTIONS pooled slots with a certificate-
                # authenticated request each, then close them so the slot
                # can be reused - each slot is left with `authenticated`
                # however the server last set it.
                for _ in range(AUTH_CONNECTIONS):
                    status = self._status_line(use_cert=True)
                    self.assertIn("200", status, f"certificate request itself failed: {status}")

                # Concurrently hit the same endpoint with NO client
                # certificate. Every one of these must be refused.
                with concurrent.futures.ThreadPoolExecutor(max_workers=NOAUTH_CONCURRENT) as pool:
                    futures = [pool.submit(self._status_line, False) for _ in range(NOAUTH_CONCURRENT)]
                    results = [f.result() for f in concurrent.futures.as_completed(futures)]

                bypassed = [r for r in results if "200" in r]
                self.assertEqual(
                    bypassed,
                    [],
                    f"{len(bypassed)}/{NOAUTH_CONCURRENT} certificate-less requests were "
                    "answered 200 - a pooled connection slot leaked a prior client's "
                    "authentication.",
                )


if __name__ == "__main__":
    unittest.main()

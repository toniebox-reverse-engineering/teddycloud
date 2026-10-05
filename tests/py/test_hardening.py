#!/usr/bin/env python3
"""
Robustness regression tests: malformed input must not crash the server.
Every test checks that the server still answers afterwards.

A crash kills the server for all following tests, so the Makefile starts a
fresh server per test class:

    make test_hardening_with_server

Single class against a running server:

    TEDDYCLOUD_BASE_URL=http://127.0.0.1:80 python3 tests/py/test_hardening.py Cache499
"""

import http.client
import os
import time
import unittest
from urllib.parse import quote, urlparse

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
BOUNDARY = "----hardening"


def request(method, path, body=None, headers=None, timeout=10):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=timeout)
    try:
        conn.request(method, path, body, headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def multipart(parts, boundary=BOUNDARY):
    """parts: list of (filename, bytes). Returns (body, headers)."""
    body = b""
    for name, data in parts:
        body += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + data + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


class Base(unittest.TestCase):
    def setUp(self):
        self.library_files = []

    def tearDown(self):
        alive = self.server_alive()
        if alive:
            for name in self.library_files:
                request("POST", "/api/fileDelete?special=library", name)
        self.assertTrue(alive, "server is not answering after the test (crashed?)")

    @staticmethod
    def server_alive():
        for _ in range(10):
            try:
                if request("GET", "/web/", timeout=3)[0] == 200:
                    return True
            except OSError:
                pass
            time.sleep(0.3)
        return False

    def put_library(self, name, data=b"not audio\n"):
        body, headers = multipart([(name, data)])
        status, text = request("POST", "/api/fileUpload?special=library&path=/", body, headers)
        self.assertEqual(status, 200, text)
        self.library_files.append(name)

    def encode(self, sources, target):
        form = "&".join(["target=" + quote(target)] + ["source=" + quote(s) for s in sources])
        self.library_files.append(target)  # removed in tearDown, ignored if it was never created
        return request(
            "POST", "/api/fileEncode?special=library", form, {"Content-Type": "application/x-www-form-urlencoded"}, timeout=60
        )


class Cache499(Base):
    """GET /cache/00000000 matched the list sentinel (cached_url == NULL)."""

    def test_hash_zero(self):
        status, _ = request("GET", "/cache/00000000")
        self.assertEqual(status, 404)


class Multipart502(Base):
    """A multipart request without boundary made the data length underflow."""

    def test_empty_boundary(self):
        body = b'--\r\nContent-Disposition: form-data; name="file"; filename="x.bin"\r\n\r\ndata\r\n--\r\n'
        try:
            request("POST", "/api/esp32/uploadFirmware", body, {"Content-Type": "multipart/form-data; boundary="})
        except OSError:
            pass  # a dropped connection is fine, tearDown checks that the server survived


class Firmware503(Base):
    """Firmware upload without any file part used the still NULL filename."""

    def test_no_file_part(self):
        body = f"--{BOUNDARY}--\r\n".encode()
        status, _ = request("POST", "/api/esp32/uploadFirmware", body, {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"})
        self.assertEqual(status, 400)


class Encode501(Base):
    """A failing first source made ffmpeg_stream pclose() the same pipe twice."""

    def test_two_undecodable_sources(self):
        self.put_library("__hardening_a.txt")
        self.put_library("__hardening_b.txt")
        status, _ = self.encode(["__hardening_a.txt", "__hardening_b.txt"], "__hardening_out.taf")
        self.assertEqual(status, 500)


class Encode494(Base):
    """More than 99 `source` parameters were stored past the end of a 99 entry array."""

    def test_too_many_sources(self):
        self.put_library("__hardening_a.txt")
        status, _ = self.encode(["__hardening_a.txt"] * 120, "__hardening_out.taf")
        self.assertIn(status, (400, 500))


if __name__ == "__main__":
    unittest.main()

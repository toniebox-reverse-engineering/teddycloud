#!/usr/bin/env python3
"""
Web UI tests: the legacy admin GUI is gone (#489).

Verifies the sunset of the legacy admin GUI:
- "/" and the parser-rewritten "index.shtm" always redirect to the web UI at /web
- "/web/" serves the built SPA
- the removed "/legacy.html" is no longer served

Recommended usage:

1) Fully automated via Makefile (build + start server + run tests + stop server):
   make test_py TESTS=legacy_gone

2) Against an already running TeddyCloud server:
   TEDDYCLOUD_BASE_URL=http://127.0.0.1:80 python3 tests/py/test_web_legacy_gone.py
"""

import http.client
import os
import unittest
import urllib.parse


BASE_URL = os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80").rstrip("/")
_PARSED_URL = urllib.parse.urlsplit(BASE_URL)
HOST = _PARSED_URL.hostname or "127.0.0.1"
PORT = _PARSED_URL.port or 80


class WebLegacyGoneTests(unittest.TestCase):
    @classmethod
    def request(cls, path):
        """Return (status, headers, body) without following redirects."""
        connection = http.client.HTTPConnection(HOST, PORT, timeout=10)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            headers = {name.lower(): value for name, value in response.getheaders()}
            body = response.read().decode("utf-8", errors="replace")
            return response.status, headers, body
        finally:
            connection.close()

    def test_root_redirects_to_web(self):
        status, headers, _ = self.request("/")
        self.assertEqual(status, 301)
        self.assertEqual(headers.get("location"), "/web")

    def test_web_serves_spa(self):
        status, _, body = self.request("/web/")
        self.assertEqual(status, 200)
        self.assertIn('id="root"', body)

    def test_legacy_admin_gui_is_gone(self):
        status, _, body = self.request("/legacy.html")
        self.assertNotEqual(status, 200)
        self.assertNotIn("library/react.development.js", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)

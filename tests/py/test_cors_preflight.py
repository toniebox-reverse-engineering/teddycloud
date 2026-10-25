#!/usr/bin/env python3
"""
CORS preflight must be answered without a login, even when web login is enabled.

Run via: make test_py TESTS=cors
"""

import http.client
import json
import os
import unittest
from urllib.parse import urlparse

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
USER, PASSWORD = "cors-test", "cors-test-password"


def request(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=10)
    h = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body)
        h["Content-Type"] = "application/json"
    conn.request(method, path, data, h)
    resp = conn.getresponse()
    text = resp.read().decode()
    out = (resp.status, {k.lower(): v for k, v in resp.getheaders()}, text)
    conn.close()
    return out


class CorsPreflight(unittest.TestCase):
    token = None

    @classmethod
    def setUpClass(cls):
        status, _, _ = request("POST", "/api/auth/users/create", {"username": USER, "password": PASSWORD})
        assert status == 200, status
        status, _, _ = request("POST", "/api/auth/enabled", {"enabled": True})
        assert status == 200, status
        status, _, text = request("POST", "/api/auth/login", {"username": USER, "password": PASSWORD})
        assert status == 200, status
        cls.token = json.loads(text)["token"]

    @classmethod
    def tearDownClass(cls):
        auth = {"Authorization": f"Bearer {cls.token}"}
        request("POST", "/api/auth/enabled", {"enabled": False}, auth)
        request("POST", "/api/auth/users/delete", {"username": USER}, auth)

    def test_login_is_enforced(self):
        self.assertEqual(request("GET", "/api/auth/users/get")[0], 401)

    def test_preflight_without_login(self):
        status, headers, _ = request(
            "OPTIONS",
            "/api/auth/users/get",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )
        self.assertEqual(status, 204)
        self.assertIn("authorization", headers["access-control-allow-headers"].lower())
        self.assertIn("GET", headers["access-control-allow-methods"])


if __name__ == "__main__":
    unittest.main()

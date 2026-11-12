#!/usr/bin/env python3
"""
/api/auth/refresh-token extends the session that authenticated the request to a full lifetime
(sliding session), so clients that stay open remain logged in while they are used. The cookie is
renewed when the browser holds the session in it.

Run via: make test_py TESTS=session_refresh
"""

import http.client
import json
import os
import re
import unittest
from urllib.parse import urlparse

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
USER, PASSWORD = "refresh-test", "refresh-test-password"
SESSION_TTL = 7 * 24 * 60 * 60


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


def session_cookie(headers):
    match = re.search(r"tc_web_session=([0-9a-f]*);.*Max-Age=(\d+)", headers.get("set-cookie", ""))
    return (match.group(1), int(match.group(2))) if match else None


def login():
    status, _, text = request("POST", "/api/auth/login", {"username": USER, "password": PASSWORD})
    assert status == 200, status
    return json.loads(text)["token"]


class SessionRefresh(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        status, _, _ = request("POST", "/api/auth/users/create", {"username": USER, "password": PASSWORD})
        assert status == 200, status

    @classmethod
    def tearDownClass(cls):
        request("POST", "/api/auth/users/delete", {"username": USER}, {"Authorization": f"Bearer {login()}"})

    def test_refresh_renews_cookie_session(self):
        token = login()
        status, headers, text = request("POST", "/api/auth/refresh-token", headers={"Cookie": f"tc_web_session={token}"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(text)["username"], USER)
        self.assertEqual(session_cookie(headers), (token, SESSION_TTL))

    def test_refresh_bearer_sets_no_cookie(self):
        token = login()
        status, headers, _ = request("POST", "/api/auth/refresh-token", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(status, 200)
        self.assertIsNone(session_cookie(headers))

    def test_refresh_bearer_and_same_cookie_renews_cookie(self):
        token = login()
        headers = {"Authorization": f"Bearer {token}", "Cookie": f"tc_web_session={token}"}
        status, resp_headers, _ = request("POST", "/api/auth/refresh-token", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(session_cookie(resp_headers), (token, SESSION_TTL))

    def test_refresh_does_not_renew_other_cookie_session(self):
        bearer, other = login(), login()
        headers = {"Authorization": f"Bearer {bearer}", "Cookie": f"tc_web_session={other}"}
        status, resp_headers, _ = request("POST", "/api/auth/refresh-token", headers=headers)
        self.assertEqual(status, 200)
        self.assertIsNone(session_cookie(resp_headers))

    def test_refresh_requires_login(self):
        self.assertEqual(request("POST", "/api/auth/refresh-token")[0], 401)
        self.assertEqual(request("POST", "/api/auth/refresh-token", headers={"Cookie": "tc_web_session=00"})[0], 401)


if __name__ == "__main__":
    unittest.main()

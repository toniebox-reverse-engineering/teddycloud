#!/usr/bin/env python3
"""
POST /api/settings/set answers with its result ("OK" or "ERROR"). The response was sent with
Content-Length 0, so clients always received an empty body, and an unknown setting was reported as
success. Clients could not tell success from failure.

Run via: make test_py TESTS=settings_set
"""

import http.client
import unittest

from test_hardening import BASE, Base


def post(path, body):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=30)
    try:
        conn.request("POST", path, body=body, headers={"Content-Type": "text/plain"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


class SettingsSet(Base):
    def test_ok_is_in_the_body(self):
        self.assertEqual(post("/api/settings/set/toniebox.max_vol_spk", b"2"), (200, b"OK"))

    def test_error_is_in_the_body(self):
        self.assertEqual(post("/api/settings/set/does.not.exist", b"1"), (200, b"ERROR"))


if __name__ == "__main__":
    unittest.main()

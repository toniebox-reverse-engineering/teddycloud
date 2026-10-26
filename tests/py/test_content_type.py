#!/usr/bin/env python3
"""
Files of the library and the content folder are served with the type of their extension,
TAFs and extensionless content as Ogg: iOS Safari names a download after its type and saved
pictures or JSON files as ".ogg" (#556).

Run via: make test_py TESTS=content_type
"""

import http.client
import unittest

from test_hardening import BASE, Base


def content_type(path):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=30)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        return resp.status, resp.getheader("Content-Type", "")
    finally:
        conn.close()


class ContentType(Base):
    def test_type_of_the_extension(self):
        for name, mime in (
            ("__ctype.png", "image/png"),
            ("__ctype.json", "application/json"),
            ("__ctype.mp3", "audio/mpeg"),
            ("__ctype.taf", "audio/ogg"),
        ):
            self.put_library(name)
            self.assertEqual(content_type(f"/content/{name}?special=library"), (200, mime), name)


if __name__ == "__main__":
    unittest.main()

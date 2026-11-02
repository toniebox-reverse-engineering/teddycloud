#!/usr/bin/env python3
"""
/content/<path> labels the response by file type: tag configs are JSON, everything else
(extensionless TAFs) stays audio/ogg. iOS/Safari names a download after the Content-Type,
so a JSON file served as audio/ogg was saved as <name>.json.ogg (#556).

Run via: make test_py TESTS=content_mime
"""

import http.client
import json
import unittest

from test_hardening import BASE, BASE_DIR, Base

TAG_DIR, TAG_FILE = "A64E581D", "500304E0"


def get_content_type(path):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=30)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        return resp.status, resp.getheader("Content-Type", "")
    finally:
        conn.close()


class ContentMime(Base):
    def setUp(self):
        super().setUp()
        self.tag_dir = BASE_DIR / "data" / "content" / "default" / TAG_DIR
        self.tag_dir.mkdir(parents=True, exist_ok=True)
        self.files = {
            f"{TAG_FILE}.json": json.dumps({"source": "lib://x.taf", "nocloud": True}),
            f"{TAG_FILE}.JSON": "{}",  # extension is matched case-insensitively
            TAG_FILE: "not a taf\n",
        }
        for name, data in self.files.items():
            (self.tag_dir / name).write_text(data)

    def tearDown(self):
        for name in self.files:
            (self.tag_dir / name).unlink(missing_ok=True)
        super().tearDown()

    def test_json_is_not_audio(self):
        for name in (f"{TAG_FILE}.json", f"{TAG_FILE}.JSON"):
            status, content_type = get_content_type(f"/content/{TAG_DIR}/{name}")
            self.assertEqual(status, 200, name)
            self.assertEqual(content_type, "application/json", name)

    def test_extensionless_stays_audio(self):
        status, content_type = get_content_type(f"/content/{TAG_DIR}/{TAG_FILE}")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "audio/ogg")


if __name__ == "__main__":
    unittest.main()

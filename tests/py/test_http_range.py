#!/usr/bin/env python3
"""
Range handling of the HTTP server: /content (handler_api.c) and static files (http_ext.c).
Known-wrong cases are marked expectedFailure with what they should do; when one is fixed the
test starts to "unexpectedly succeed" and the marker has to go.

Run via: make test_py TESTS=http_range
"""

import http.client
import unittest

from test_hardening import BASE, BASE_DIR, Base

TAG_DIR = "A64E581D"
DATA = bytes(range(100))
# a static file of the web UI, served by the same code but not from /content
STATIC = "/web/wasm/taf_encoder.wasm"


def get(path, byte_range=None, timeout=3):
    """Returns (status, headers, body); a response that does not complete raises."""
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Range": byte_range} if byte_range else {})
        resp = conn.getresponse()
        return resp.status, resp, resp.read()
    finally:
        conn.close()


class RangeContent(Base):
    PATH = f"/content/{TAG_DIR}/500304E0"

    def setUp(self):
        super().setUp()
        self.dir = BASE_DIR / "data" / "content" / "default" / TAG_DIR
        self.dir.mkdir(parents=True, exist_ok=True)
        self.files = ["500304E0", "EMPTY"]
        (self.dir / "500304E0").write_bytes(DATA)
        (self.dir / "EMPTY").write_bytes(b"")

    def tearDown(self):
        for name in self.files:
            (self.dir / name).unlink(missing_ok=True)
        super().tearDown()

    def partial(self, byte_range, first, last):
        status, resp, body = get(self.PATH, byte_range)
        self.assertEqual(status, 206, byte_range)
        self.assertEqual(resp.reason, "Partial Content")  # the status text table moves with the server code
        self.assertEqual(resp.getheader("Content-Range"), f"bytes {first}-{last}/{len(DATA)}")
        self.assertEqual(resp.getheader("Content-Length"), str(last - first + 1))
        self.assertEqual(body, DATA[first : last + 1])

    def test_without_range(self):
        status, resp, body = get(self.PATH)
        self.assertEqual(status, 200)
        self.assertEqual(resp.getheader("Accept-Ranges"), "bytes")
        self.assertEqual(body, DATA)

    def test_closed_range(self):
        self.partial("bytes=10-19", 10, 19)

    def test_open_ended_range(self):
        self.partial("bytes=10-", 10, 99)

    def test_end_beyond_file_is_clamped(self):
        self.partial("bytes=90-200", 90, 99)

    def test_out_of_range_numbers_are_ignored(self):
        # does not fit 32 bits
        status, _, body = get(self.PATH, "bytes=4294967296-")
        self.assertEqual((status, body), (200, DATA))

    def test_unparsable_range_is_ignored(self):
        status, _, body = get(self.PATH, "bytes=abc")
        self.assertEqual((status, body), (200, DATA))

    def test_range_starting_at_zero(self):
        self.partial("bytes=0-9", 0, 9)

    def test_start_past_end(self):
        status, resp, body = get(self.PATH, "bytes=100-")
        self.assertEqual((status, body), (416, b""))
        self.assertEqual(resp.reason, "Range Not Satisfiable")
        self.assertEqual(resp.getheader("Content-Range"), f"bytes */{len(DATA)}")

    def test_reversed_range_is_ignored(self):
        status, _, body = get(self.PATH, "bytes=50-10")
        self.assertEqual((status, body), (200, DATA))

    def test_suffix_range_is_ignored(self):
        status, _, body = get(self.PATH, "bytes=-5")
        self.assertEqual((status, body), (200, DATA))

    def test_range_on_empty_file(self):
        status, _, body = get(f"/content/{TAG_DIR}/EMPTY", "bytes=10-")
        self.assertEqual((status, body), (416, b""))

    def test_empty_file_without_range(self):
        status, _, body = get(f"/content/{TAG_DIR}/EMPTY")
        self.assertEqual((status, body), (200, b""))


class RangeStatic(Base):
    def test_closed_range(self):
        full = get(STATIC)[2]
        status, resp, body = get(STATIC, "bytes=10-19")
        self.assertEqual(status, 206)
        self.assertEqual(resp.getheader("Content-Range"), f"bytes 10-19/{len(full)}")
        self.assertEqual(body, full[10:20])

    def test_open_ended_range(self):
        full = get(STATIC)[2]
        status, resp, body = get(STATIC, "bytes=100-")
        self.assertEqual(status, 206)
        self.assertEqual(resp.getheader("Content-Range"), f"bytes 100-{len(full) - 1}/{len(full)}")
        self.assertEqual(body, full[100:])

    def test_reversed_range_serves_everything(self):
        full = get(STATIC)[2]
        status, _, body = get(STATIC, "bytes=50-10")
        self.assertEqual((status, body), (200, full))

    def test_range_starting_at_zero(self):
        status, resp, body = get(STATIC, "bytes=0-9")
        self.assertEqual(status, 206)
        self.assertEqual(len(body), 10)


if __name__ == "__main__":
    unittest.main()

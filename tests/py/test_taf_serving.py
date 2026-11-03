#!/usr/bin/env python3
"""
How a TAF is served from /v2/content and /v3/chapter: the 4096 byte header can be stripped
(skip_header=true) and a chapter is cut out of the audio. Both live in the patched HTTP server
(httpSendResponseStreamUnsafe), written to pin the current behaviour before that code moves.

Run via: make test_py TESTS=taf_serving
"""

import hashlib
import http.client
import os
import struct
import sys
import unittest
from pathlib import Path

from test_hardening import BASE, BASE_DIR, Base

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import profiles, taf  # noqa: E402
from sim.rtnl import _bytes, _tag, varint  # noqa: E402

BLOCK = 4096
RUID = "fa9c3e0d500304e0"
TRACK_PAGES = (0, 3, 5)  # chapter n starts at audio block TRACK_PAGES[n]
AUDIO = b"".join(bytes([block + 1]) * BLOCK for block in range(8))
CONTENT = taf.build(0x1A8DECAE, AUDIO, track_pages=TRACK_PAGES)


def get(path, byte_range=None):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=5)
    headers = {"Authorization": profiles.AUTHORIZATION}
    if byte_range:
        headers["Range"] = byte_range
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp, resp.read()
    finally:
        conn.close()


class TafServing(Base):
    def setUp(self):
        super().setUp()
        self.paths = []

    def tearDown(self):
        for path in self.paths:
            path.unlink(missing_ok=True)
        super().tearDown()

    def put_content(self, data, ruid=RUID):
        path = BASE_DIR / "data" / "content" / "default" / ruid[:8].upper() / ruid[8:].upper()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.paths.append(path)

    def test_header_is_kept_by_default(self):
        self.put_content(CONTENT)
        status, _, body = get(f"/v2/content/{RUID}")
        self.assertEqual((status, body), (200, CONTENT))

    def test_skip_header(self):
        self.put_content(CONTENT)
        status, resp, body = get(f"/v2/content/{RUID}?skip_header=true")
        self.assertEqual(status, 200)
        self.assertEqual(resp.getheader("Content-Length"), str(len(AUDIO)))
        self.assertEqual(body, AUDIO)

    def test_skip_header_with_open_range(self):
        # the range counts in the stripped file
        self.put_content(CONTENT)
        status, resp, body = get(f"/v2/content/{RUID}?skip_header=true", "bytes=5000-")
        self.assertEqual(status, 206)
        self.assertEqual(resp.getheader("Content-Range"), f"bytes 5000-{len(AUDIO) - 1}/{len(AUDIO)}")
        self.assertEqual(body, AUDIO[5000:])

    def test_skip_header_with_closed_range(self):
        self.put_content(CONTENT)
        status, resp, body = get(f"/v2/content/{RUID}?skip_header=true", "bytes=100-199")
        self.assertEqual(status, 206)
        self.assertEqual(resp.getheader("Content-Range"), f"bytes 100-199/{len(AUDIO)}")
        self.assertEqual(body, AUDIO[100:200])

    def test_skip_header_with_range_from_zero(self):
        self.put_content(CONTENT)
        status, _, body = get(f"/v2/content/{RUID}?skip_header=true", "bytes=0-9")
        self.assertEqual((status, body), (206, AUDIO[:10]))

    def test_skip_header_of_file_shorter_than_header(self):
        # a valid header without padding: stripping 4096 bytes must not underflow the length
        audio = b"x" * 50
        fields = (
            _bytes(1, hashlib.sha1(audio).digest())
            + _tag(2, 0) + varint(len(audio))
            + _tag(3, 0) + varint(7)
            + _bytes(4, varint(0))
            + _bytes(5, bytes(10))
        )
        short = struct.pack(">I", len(fields)) + fields + audio
        self.assertLess(len(short), BLOCK)
        ruid = "fa9c3e0d500304e1"
        self.put_content(short, ruid)

        status, _, body = get(f"/v2/content/{ruid}")
        self.assertEqual((status, body), (200, short))
        status, resp, body = get(f"/v2/content/{ruid}?skip_header=true")
        self.assertEqual((status, resp.getheader("Content-Length"), body), (200, "0", b""))

    def chapter(self, number):
        return get(f"/v3/chapter/teddycloud_{number:02d}_{RUID}")

    def test_chapters(self):
        # chapter 0 is the audio of its pages; every later chapter starts with the first 512 bytes
        # of the audio (the Ogg header pages) so that it can be played on its own
        self.put_content(CONTENT)
        pages = list(TRACK_PAGES) + [len(AUDIO) // BLOCK]
        for number in range(len(TRACK_PAGES)):
            audio = AUDIO[pages[number] * BLOCK : pages[number + 1] * BLOCK]
            expected = audio if number == 0 else AUDIO[:512] + audio
            status, resp, body = self.chapter(number)
            self.assertEqual(status, 200, number)
            self.assertEqual(resp.getheader("Content-Length"), str(len(expected)), number)
            self.assertEqual(body, expected, number)

    def test_unknown_chapter_is_404(self):
        self.put_content(CONTENT)
        self.assertEqual(self.chapter(len(TRACK_PAGES))[0], 404)

    def test_chapter_with_range(self):
        self.put_content(CONTENT)
        expected = AUDIO[:512] + AUDIO[TRACK_PAGES[1] * BLOCK : TRACK_PAGES[2] * BLOCK]
        status, resp, body = get(f"/v3/chapter/teddycloud_01_{RUID}", "bytes=300-799")
        self.assertEqual(status, 206)
        self.assertEqual(resp.getheader("Content-Range"), f"bytes 300-799/{len(expected)}")
        self.assertEqual(body, expected[300:800])


if __name__ == "__main__":
    unittest.main()

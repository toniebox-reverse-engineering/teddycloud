#!/usr/bin/env python3
"""
Selected tracks of a TAF are exported as a zip of Ogg files (several tracks)
or as a single Ogg (one track), on both download routes the web UI uses:

  /content/<path>?ogg=true&tracks=...           file browser
  /content/download/<ruid>?...&tracks=...       tonie card, tag with a lib:// source (#350)

The TAF is encoded by the server from generated white noise (needs ffmpeg),
the zip is built with the external zip binary.

Run via: make test_py TESTS=track_export
"""

import http.client
import io
import json
import os
import unittest
import wave
import zipfile

from test_hardening import BASE, BASE_DIR, Base

TRACK_SECONDS = [2, 2, 2]
RATE = 4000  # low rate: the test upload helper only handles small bodies, the server resamples
TAF = "__trackexport.taf"
TAG_DIR, TAG_FILE = "A64E581D", "500304E0"


def white_noise_wav(seconds):
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(1)
        w.setframerate(RATE)
        w.writeframes(os.urandom(RATE * seconds))
    return buf.getvalue()


def get(path):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=30)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.getheader("Content-Type", ""), resp.read()
    finally:
        conn.close()


class TrackExport(Base):
    def setUp(self):
        super().setUp()
        sources = []
        for i, seconds in enumerate(TRACK_SECONDS):
            name = f"__trackexport{i}.wav"
            self.put_library(name, white_noise_wav(seconds))
            sources.append(name)
        status, text = self.encode(sources, TAF)
        self.assertEqual(status, 200, text)

        # a tag whose audio lives in the library, as set up by "assign to tag" in the web UI
        self.tag_json = BASE_DIR / "data" / "content" / "default" / TAG_DIR / f"{TAG_FILE}.json"
        self.tag_json.parent.mkdir(parents=True, exist_ok=True)
        self.tag_json.write_text(json.dumps({"source": f"lib://{TAF}", "nocloud": True}))

    def tearDown(self):
        self.tag_json.unlink(missing_ok=True)
        super().tearDown()

    def assert_zip_of_tracks(self, path, count):
        status, content_type, body = get(path)
        self.assertEqual(status, 200, body[:200])
        self.assertEqual(content_type, "application/zip")
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            self.assertIsNone(z.testzip())
            names = z.namelist()
            self.assertEqual(len(names), count, names)
            for name in names:
                self.assertTrue(z.read(name).startswith(b"OggS"), name)

    def assert_single_ogg(self, path):
        status, _, body = get(path)
        self.assertEqual(status, 200, body[:200])
        self.assertTrue(body.startswith(b"OggS"))
        # one track only, not the whole TAF
        _, _, whole = get(f"/content/{TAF}?special=library&ogg=true")
        self.assertLess(len(body), len(whole))

    def test_content_path(self):
        self.assert_zip_of_tracks(f"/content/{TAF}?special=library&ogg=true&tracks=2%2C3", 2)
        self.assert_single_ogg(f"/content/{TAF}?special=library&ogg=true&tracks=2")

    def test_content_download_tag(self):
        url = f"/content/download/{TAG_DIR}/{TAG_FILE}?skip_header=true&ogg=true"
        self.assert_zip_of_tracks(url + "&tracks=2%2C3", 2)
        self.assert_single_ogg(url + "&tracks=2")

    def test_content_download_tag_invalid_track(self):
        try:
            status, _, _ = get(f"/content/download/{TAG_DIR}/{TAG_FILE}?skip_header=true&ogg=true&tracks=9")
        except OSError:
            return  # no error response yet, the connection is dropped (same as on /content/)
        self.assertNotEqual(status, 200)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""
Selected tracks of a TAF are exported as a zip of Ogg files (several tracks)
or as a single Ogg (one track), on both download routes the web UI uses:

  /content/<path>?ogg=true&tracks=...           file browser
  /content/download/<ruid>?...&tracks=...       tonie card, tag with a lib:// source (#350)

The TAF is encoded by the server from generated white noise (needs ffmpeg),
the zip is written by the server itself (zip_writer.c).

Run via: make test_py TESTS=track_export
"""

import http.client
import io
import json
import os
import unittest
import wave
import zipfile

from test_hardening import BASE, BASE_DIR, Base, request

TRACK_SECONDS = [2, 2, 2]
RATE = 4000  # low rate: the test upload helper only handles small bodies, the server resamples
TAF = "__trackexport.taf"
TAG_DIR, TAG_FILE = "A64E581D", "500304E0"
CUSTOM_MODEL = "TC_TEST_TRACK_EXPORT"
COLLIDING_MODEL = "TC_TEST_TRACK_EXPORT_COLLIDING"


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
        body = json.dumps({"models": [CUSTOM_MODEL, COLLIDING_MODEL]})
        request("POST", "/api/toniesCustomJsonDelete", body, {"Content-Type": "application/json"})
        super().tearDown()

    def name_tracks(self, titles, colliding_titles=None, colliding_first=True):
        """Give the TAF track titles, like a tonies.custom.json entry does for a real tonie.
        colliding_titles go to another tonie with the same audio id but another hash."""
        status, text = request("GET", "/api/fileIndexV2?path=/&special=library")
        self.assertEqual(status, 200, text)
        header = next(f["tafHeader"] for f in json.loads(text)["files"] if f["name"] == TAF)
        entry = {
            "model": CUSTOM_MODEL,
            "series": "Track export test",
            "title": "Track export test",
            "audio_id": [header["audioId"]],
            "hash": [header["sha1Hash"].upper()],
            "tracks": titles,
        }
        entries = [entry]
        if colliding_titles:
            entries.insert(0 if colliding_first else 1, dict(entry, model=COLLIDING_MODEL, hash=["0" * 40], tracks=colliding_titles))
        status, text = request("POST", "/api/toniesCustomJsonUpsert", json.dumps(entries), {"Content-Type": "application/json"})
        self.assertEqual(status, 200, text)

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

    def test_content_invalid_track(self):
        for query in ("tracks=9", "tracks=0", "tracks=abc", "tracks=,"):
            status, _, _ = get(f"/content/{TAF}?special=library&ogg=true&{query}")
            self.assertEqual(status, 400, query)

    def test_zip_entry_names_are_utf8(self):
        # typographic quotes as in #552, a path separator, and a title longer than the name buffer
        self.name_tracks(["Käse/Mäuse – Überraschung", "3. Satz: „Allegro”", "ä" * 60 + " Ende"])
        status, content_type, body = get(f"/content/{TAF}?special=library&ogg=true&tracks=1%2C2%2C3")
        self.assertEqual(status, 200, body[:200])
        self.assertEqual(content_type, "application/zip")
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            self.assertIsNone(z.testzip())
            infos = z.infolist()
            # general purpose bit 11: the names are UTF-8 whatever the locale of the server
            self.assertTrue(all(i.flag_bits & 0x800 for i in infos))
            names = [i.filename for i in infos]
        self.assertEqual(names[0], "01 Käse_Mäuse – Überraschung.ogg")
        self.assertEqual(names[1], "02 3. Satz: „Allegro”.ogg")
        # cut at a character boundary, never in the middle of a UTF-8 sequence
        self.assertEqual(names[2], "03 " + "ä" * 47 + ".ogg")

    def test_track_names_of_the_tonie_with_the_same_hash(self):
        # tonies encoded in the same second share the audio id, only the hash tells them apart;
        # a lookup by audio id alone finds whichever comes first, so both orders are tested
        for colliding_first in (True, False):
            with self.subTest(colliding_first=colliding_first):
                # an upsert updates existing entries in place, so the order only changes after a delete
                models = json.dumps({"models": [CUSTOM_MODEL, COLLIDING_MODEL]})
                request("POST", "/api/toniesCustomJsonDelete", models, {"Content-Type": "application/json"})
                self.name_tracks(["Own one", "Own two", "Own three"], ["Other one", "Other two", "Other three"], colliding_first)
                status, _, body = get(f"/content/{TAF}?special=library&ogg=true&tracks=1%2C2")
                self.assertEqual(status, 200, body[:200])
                with zipfile.ZipFile(io.BytesIO(body)) as z:
                    self.assertEqual(z.namelist(), ["01 Own one.ogg", "02 Own two.ogg"])

    def test_content_download_tag_invalid_track(self):
        for query in ("tracks=9", "tracks=0", "tracks=abc", "tracks=,"):
            status, _, _ = get(f"/content/download/{TAG_DIR}/{TAG_FILE}?skip_header=true&ogg=true&{query}")
            self.assertEqual(status, 400, query)


if __name__ == "__main__":
    unittest.main()

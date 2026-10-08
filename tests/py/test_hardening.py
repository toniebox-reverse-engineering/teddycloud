#!/usr/bin/env python3
"""
Robustness regression tests: malformed input must not crash the server and
secrets must not leak. Every test checks that the server still answers
afterwards.

A crash kills the server for all following tests, so the Makefile starts a
fresh server per test class:

    make test_py TESTS=hardening

Single class against a running server:

    TEDDYCLOUD_BASE_URL=http://127.0.0.1:80 python3 tests/py/test_hardening.py Cache499
"""

import http.client
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import quote, urlparse

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
REPO = Path(__file__).resolve().parents[2]
BIN = REPO / "bin" / "teddycloud"
# base directory of the server under test (with_server.sh exports the sandbox)
BASE_DIR = Path(os.environ.get("TC_SANDBOX", REPO))
BOUNDARY = "----hardening"
# Known, not yet understood: an upload built by multipart() never gets a response
# once the body reaches 64 KB (16 KB works). curl uploads 88 KB to the same
# endpoint fine, so it depends on how the body is sent. Stay below this size.
MAX_MULTIPART_BODY = 16000


def request(method, path, body=None, headers=None, timeout=10):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=timeout)
    try:
        conn.request(method, path, body, headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def multipart(parts, boundary=BOUNDARY):
    """parts: list of (filename, bytes). Returns (body, headers).
    Bodies are limited to MAX_MULTIPART_BODY, see the note there."""
    body = b""
    for name, data in parts:
        body += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + data + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    if len(body) > MAX_MULTIPART_BODY:
        raise ValueError(
            f"multipart body is {len(body)} bytes, larger uploads than {MAX_MULTIPART_BODY} bytes hang (see MAX_MULTIPART_BODY)"
        )
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


class Base(unittest.TestCase):
    def setUp(self):
        self.library_files = []

    def tearDown(self):
        alive = self.server_alive()
        if alive:
            for name in self.library_files:
                request("POST", "/api/fileDelete?special=library", name)
        self.assertTrue(alive, "server is not answering after the test (crashed?)")

    @staticmethod
    def server_alive():
        for _ in range(10):
            try:
                if request("GET", "/web/", timeout=3)[0] == 200:
                    return True
            except OSError:
                pass
            time.sleep(0.3)
        return False

    def put_library(self, name, data=b"not audio\n"):
        body, headers = multipart([(name, data)])
        status, text = request("POST", "/api/fileUpload?special=library&path=/", body, headers)
        self.assertEqual(status, 200, text)
        self.library_files.append(name)

    def encode(self, sources, target):
        form = "&".join(["target=" + quote(target)] + ["source=" + quote(s) for s in sources])
        self.library_files.append(target)  # removed in tearDown, ignored if it was never created
        return request(
            "POST", "/api/fileEncode?special=library", form, {"Content-Type": "application/x-www-form-urlencoded"}, timeout=60
        )


class Cache499(Base):
    """GET /cache/00000000 matched the list sentinel (cached_url == NULL)."""

    def test_hash_zero(self):
        status, _ = request("GET", "/cache/00000000")
        self.assertEqual(status, 404)


class Multipart502(Base):
    """A multipart request without boundary made the data length underflow."""

    def test_empty_boundary(self):
        body = b'--\r\nContent-Disposition: form-data; name="file"; filename="x.bin"\r\n\r\ndata\r\n--\r\n'
        try:
            request("POST", "/api/esp32/uploadFirmware", body, {"Content-Type": "multipart/form-data; boundary="})
        except OSError:
            pass  # a dropped connection is fine, tearDown checks that the server survived


class Firmware503(Base):
    """Firmware upload without any file part used the still NULL filename."""

    def test_no_file_part(self):
        body = f"--{BOUNDARY}--\r\n".encode()
        status, _ = request("POST", "/api/esp32/uploadFirmware", body, {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"})
        self.assertEqual(status, 400)


class Encode501(Base):
    """A failing first source made ffmpeg_stream pclose() the same pipe twice."""

    def test_two_undecodable_sources(self):
        self.put_library("__hardening_a.txt")
        self.put_library("__hardening_b.txt")
        status, _ = self.encode(["__hardening_a.txt", "__hardening_b.txt"], "__hardening_out.taf")
        self.assertEqual(status, 500)


class Tap495(Base):
    """A TAP playlist with more than 255 entries wrapped the uint8_t load index, leaving
    entries uninitialised that tap_free() then freed."""

    RUID = "0000049500000495"
    CONTENT_DIR = RUID[:8]
    CONTENT_JSON = f"{RUID[:8]}/{RUID[8:]}.json"

    def set_content_json(self, form):
        return request(
            "POST", f"/content/json/set/{self.RUID}", form, {"Content-Type": "application/x-www-form-urlencoded"}
        )

    def test_playlist_with_300_entries(self):
        if request("GET", f"/content/json/get/{self.RUID}")[0] == 200:
            self.skipTest(f"content JSON for {self.RUID} already exists, not touching it")
        playlist = {
            "type": "tap",
            "audio_id": 495,
            "filepath": "lib://__hardening.taf",
            "name": "hardening",
            "files": [{"filepath": f"lib://{i}.mp3", "name": ""} for i in range(300)],
        }
        self.put_library("__hardening.tap", json.dumps(playlist).encode())
        try:
            self.assertEqual(self.set_content_json("source=" + quote("lib://__hardening.tap"))[0], 200)
            # set loads the existing content JSON first, so this call parses and frees the playlist
            self.set_content_json("hide=true")
        except OSError:
            pass  # a dropped connection is fine, tearDown checks that the server survived
        finally:
            if self.server_alive():
                request("POST", "/api/fileDelete", self.CONTENT_JSON)
                request("POST", "/api/dirDelete", self.CONTENT_DIR)  # rmdir, only removes it if empty


class Crawler508(Base):
    """With onBlacklistDomain enabled (the default) an else-if skipped the crawler check."""

    def test_crawler_locks_access(self):
        for name, value in (
            ("security_mit.onBlacklistDomain", "true"),
            ("security_mit.onCrawler", "true"),
            ("security_mit.lockAccess", "true"),
            ("security_mit.httpsOnly", "false"),
        ):
            self.assertEqual(request("POST", f"/api/settings/set/{name}", value)[0], 200)
        _, text = request("GET", "/web/", headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"})
        self.assertTrue("locked to mitigate security risks" in text, "crawler User-Agent was not detected")


class KeyPermissions512(Base):
    """Generated private keys were left readable for other local users (default umask)."""

    def test_generated_key_is_owner_only(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(
                [BIN, "--base_path", str(BASE_DIR), "--generate-client-cert", "0123456789ab", "--destination", d],
                check=True,
                capture_output=True,
                cwd=BASE_DIR,  # the CA to sign with is read from certs/server below the cwd
                preexec_fn=lambda: os.umask(0o022),  # what most systems use
            )
            mode = os.stat(os.path.join(d, "private.der")).st_mode & 0o777
            self.assertEqual(mode & 0o077, 0, f"private.der has mode {mode:o}")


class Traversal513(Base):
    """A relative path starting with ".." survived sanitizePath() and escaped the base directory."""

    OUTSIDE = BASE_DIR / "data" / "__hardening513.txt"  # next to data/library

    def test_dotdot_path_stays_in_root(self):
        self.OUTSIDE.write_text("must survive")
        try:
            request("POST", "/api/fileDelete?special=library", "../__hardening513.txt")
            self.assertTrue(self.OUTSIDE.exists(), "fileDelete removed a file outside the library directory")
        finally:
            self.OUTSIDE.unlink(missing_ok=True)


class Ota(Base):
    """Local V3 OTA delivery: /v3/ota/<type>/<hash> serves <firmware>/ota/<type>/<hash>.bin.
    OTA hashes with ".." can't be tested over HTTP, the URI is canonicalised before the handler runs."""

    FIRMWARE = BASE_DIR / "data" / "firmware"

    def setUp(self):
        super().setUp()
        self.files = []
        for name, value in (("cloud.enabled", "false"), ("cloud.localOta", "true")):
            self.assertEqual(request("POST", f"/api/settings/set/{name}", value)[0], 200)

    def tearDown(self):
        for f in self.files:
            f.unlink(missing_ok=True)
        for d in ("ota/1", "ota"):
            try:
                (self.FIRMWARE / d).rmdir()  # only removes the directories the test created, if empty
            except OSError:
                pass
        super().tearDown()

    def put_firmware(self, relative, data):
        f = self.FIRMWARE / relative
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)
        self.files.append(f)


class Range515(Ota):
    """A Range start behind the end of the file made Content-Length underflow to ~4 GB."""

    def test_range_start_past_end(self):
        self.put_firmware("ota/1/abcdef.bin", b"0123456789")
        status, text = request("GET", "/v3/ota/1/abcdef", headers={"Range": "bytes=100-"}, timeout=5)
        self.assertEqual((status, text), (200, "0123456789"))


class Extract522(Base):
    """extractCerts used the filename and MAC as path components without validation."""

    def test_traversal_mac_is_rejected(self):
        # "../../../../" is 12 characters and resolves to an existing directory, so an
        # unfixed server fails later on the missing firmware file instead of creating anything
        status, _ = request(
            "POST", "/api/esp32/extractCerts?filename=" + quote("x_../../../../") + "&overwrite=false"
        )
        self.assertEqual(status, 404)

    def test_patch_firmware_rejects_traversal(self):
        for filename in ("x_../../../../", "../../etc/x_0123456789ab", "a/b_0123456789ab", "x_zzzzzzzzzzzz"):
            status, _ = request("POST", "/api/esp32/patchFirmware?filename=" + quote(filename))
            self.assertEqual(status, 404, filename)


class PrivateFetch(Base):
    """A tonie `pic` URL is downloaded into the image cache and served back from /cache/: it must not be
    possible to make the server read internal services (SSRF), unless core.allowPrivateFetch is set."""

    def setUp(self):
        super().setUp()
        import hashlib
        import threading
        import http.server

        self.hits = []
        hits = self.hits

        class Internal(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                hits.append(self.path)
                body = b"INTERNAL-SECRET"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.internal = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Internal)
        threading.Thread(target=self.internal.serve_forever, daemon=True).start()
        self.sha = lambda url: hashlib.sha256(url.encode()).hexdigest().upper()
        self.set("tonie_json.cache_images", "true")
        self.set("core.allowPrivateFetch", "false")  # the server is shared with the other test of this class

    def tearDown(self):
        self.internal.shutdown()
        self.internal.server_close()
        super().tearDown()

    def set(self, name, value):
        self.assertEqual(request("POST", f"/api/settings/set/{name}", value)[0], 200)
        self.assertEqual(request("GET", "/api/triggerWriteConfig")[0], 200)  # a reload would drop it otherwise
        time.sleep(1.5)

    def fetch_via_cache(self, name):
        url = f"http://127.0.0.1:{self.internal.server_address[1]}/{name}.txt"
        audio_id = 999000 + sum(map(ord, name))  # unique per name, duplicates are rejected
        entry = [{"model": "ZZZ_" + name, "series": "S", "audio_id": [audio_id], "hash": [f"{audio_id:040x}"],
                  "title": "t", "tracks": ["a"], "pic": url}]
        self.assertEqual(request("POST", "/api/toniesCustomJsonUpsert", json.dumps(entry), {"Content-Type": "application/json"})[0], 200)
        self.assertEqual(request("GET", "/api/toniesJsonReload")[0], 200)
        time.sleep(1)
        return request("GET", f"/cache/{self.sha(url)}.txt")

    def test_private_address_is_refused_by_default(self):
        status, text = self.fetch_via_cache("blocked")
        self.assertEqual(self.hits, [], "the server connected to a private address")
        self.assertNotIn("INTERNAL-SECRET", text)

    def test_private_address_can_be_allowed(self):
        self.set("core.allowPrivateFetch", "true")
        status, text = self.fetch_via_cache("allowed")
        self.assertEqual((status, text), (200, "INTERNAL-SECRET"))
        self.assertEqual(self.hits, ["/allowed.txt"])


class Settings528(Base):
    """Settings are looked up by name; every option listed in the index must be found."""

    def test_every_listed_setting_is_found(self):
        status, text = request("GET", "/api/settings/getIndex?internal=t")
        self.assertEqual(status, 200)
        options = json.loads(text)["options"]
        self.assertGreater(len(options), 50)
        missing = []
        for option in options:
            if option.get("type") in ("header", None) or "ID" not in option:
                continue
            status, value = request("GET", "/api/settings/get/" + option["ID"])
            if status != 200:
                missing.append((option["ID"], status))
            elif option.get("type") in ("string", "bool", "int", "uint") and "value" in option:
                self.assertEqual(value, str(option["value"]).lower() if option["type"] == "bool" else str(option["value"]), option["ID"])
        self.assertEqual(missing, [])


class Secrets505(Base):
    """getIndex with nolevel=t returned the LEVEL_SECRET values, i.e. the private keys."""

    def test_index_has_no_private_keys(self):
        status, text = request("GET", "/api/settings/getIndex?internal=t&nolevel=t")
        self.assertEqual(status, 200)
        leaked = [o["ID"] for o in json.loads(text)["options"] if "PRIVATE KEY" in str(o.get("value", ""))]
        self.assertEqual(leaked, [])


if __name__ == "__main__":
    unittest.main()

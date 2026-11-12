"""
A tonie whose source is a random pool (a .tap of type "random") gets one TAF of the pool,
picked anew each time the box requests the content (#388). The pool is a folder, a list of
TAF files, or both.

    make test_py TESTS=tap_random
"""

import hashlib
import http.client
import json
import os
import struct
import sys
from pathlib import Path
from urllib.parse import quote, urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import freshness, profiles, taf  # noqa: E402
from sim.box import Box  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")

AUTH = {"Authorization": profiles.AUTHORIZATION}
# Enough requests that a pool of three missing one of its files is a bug, not chance (3 * (2/3)^30).
REQUESTS = 30


@pytest.fixture(scope="module")
def box():
    b = Box("deadbeef0388", SANDBOX, BASE.hostname, HTTPS_API_PORT)
    yield b
    b.close()


@pytest.fixture
def library():
    path = Path(SANDBOX) / "data" / "library"
    path.mkdir(parents=True, exist_ok=True)
    return path


def put_taf(path, audio_id):
    content = taf.build(audio_id, os.urandom(2 * 4096))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return content


def web(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=10)
    try:
        conn.request(method, path, body, headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def put_pool(library, name, pool):
    tap = library / name
    tap.write_text(json.dumps(dict({"type": "random", "name": "Pool"}, **pool)))
    return f"lib://{name}"


def assign(ruid, source):
    """Assign the source to the tonie the way the web UI does."""
    status, text = web("POST", f"/content/json/set/{ruid}", "source=" + quote(source),
                       {"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 200, text


def content_json(ruid):
    return Path(SANDBOX) / "data" / "content" / "default" / ruid[:8].upper() / f"{ruid[8:].upper()}.json"


def served(box, ruid, times=REQUESTS):
    bodies = []
    for _ in range(times):
        status, _, body = box.request("GET", f"/v2/content/{ruid}", headers=AUTH)
        assert status == 200, body[:200]
        bodies.append(body)
    return bodies


def test_the_pool_is_its_folder_and_its_list(box, library):
    in_folder = {put_taf(library / "__random_pool" / f"{i}.taf", 0x5F000000 + i) for i in range(2)}
    listed = put_taf(library / "__random_elsewhere" / "listed.taf", 0x5F000010)
    put_taf(library / "__random_elsewhere" / "unlisted.taf", 0x5F000011)
    ruid = "0a0b0c01500304e0"
    pool = {"directory": "lib://__random_pool/", "files": [{"filepath": "lib://__random_elsewhere/listed.taf"}]}
    assign(ruid, put_pool(library, "__random_pool.tap", pool))

    assert set(served(box, ruid)) == in_folder | {listed}


def test_only_complete_tafs_are_picked(box, library):
    only = put_taf(library / "__random_mixed" / "only.taf", 0x5F300000)
    (library / "__random_mixed" / "cover.jpg").write_bytes(b"\xff\xd8 not a taf")
    # Subfolders are not part of the pool, not even with a valid TAF in them.
    put_taf(library / "__random_mixed" / "sub" / "deeper.taf", 0x5F300002)
    # A TAF still being written already has its header but is shorter than the header says.
    growing = taf.build(0x5F300001, os.urandom(2 * 4096))
    (library / "__random_mixed" / "growing.taf").write_bytes(growing[:-3000])
    ruid = "0a0b0c04500304e0"
    assign(ruid, put_pool(library, "__random_mixed.tap", {"directory": "lib://__random_mixed/"}))

    assert set(served(box, ruid, times=10)) == {only}


def test_an_empty_pool_is_not_found(box, library):
    (library / "__random_empty").mkdir(exist_ok=True)
    ruid = "0a0b0c05500304e0"
    assign(ruid, put_pool(library, "__random_empty.tap", {"directory": "lib://__random_empty/"}))

    status, _, _ = box.request("GET", f"/v2/content/{ruid}", headers=AUTH)

    assert status == 404


def test_a_pool_is_live_and_marked_at_every_freshness_check(box, library):
    content = put_taf(library / "__random_live" / "a.taf", 0x5F400000)
    ruid = "0a0b0c06500304e0"
    assign(ruid, put_pool(library, "__random_live.tap", {"directory": "lib://__random_live/"}))
    # A model known for the TAF the box played last must not become the pool's model.
    entry = {"model": "TC_TEST_RANDOM_POOL", "series": "Pool", "title": "Pool", "audio_id": [0x5F400000],
             "hash": [hashlib.sha1(content[4096:]).hexdigest().upper()]}
    status, text = web("POST", "/api/toniesCustomJsonUpsert", json.dumps([entry]), {"Content-Type": "application/json"})
    assert status == 200, text
    uid = struct.unpack("<Q", bytes.fromhex(ruid))[0]

    status, _, answer = box.request("POST", "/v1/freshness-check", freshness.request([(uid, 0x5F400000)]))

    assert status == 200
    assert struct.pack("<Q", uid) in answer
    stored = json.loads(content_json(ruid).read_text())
    assert stored["live"] is True
    assert stored["source"] == "lib://__random_live.tap"
    assert stored.get("tonie_model", "") == ""


def test_a_resumed_download_continues_the_taf_it_began_with(box, library):
    pool = {i: put_taf(library / "__random_resume" / f"{i}.taf", 0x5F500000 + i) for i in range(3)}
    ruid = "0a0b0c07500304e0"
    assign(ruid, put_pool(library, "__random_resume.tap", {"directory": "lib://__random_resume/"}))

    for _ in range(REQUESTS):
        first = served(box, ruid, times=1)[0]
        audio_id = next(i for i, content in pool.items() if content == first) + 0x5F500000
        headers = dict(AUTH, Range="bytes=5000-", **{"If-Range": str(audio_id)})
        status, h, body = box.request("GET", f"/v2/content/{ruid}", headers=headers)
        assert (status, h.get("Content-Range")) == (206, f"bytes 5000-{len(first) - 1}/{len(first)}")
        assert body == first[5000:]


def test_a_resume_of_a_taf_that_left_the_pool_gets_a_whole_new_pick(box, library):
    only = put_taf(library / "__random_gone" / "a.taf", 0x5F600000)
    ruid = "0a0b0c08500304e0"
    assign(ruid, put_pool(library, "__random_gone.tap", {"directory": "lib://__random_gone/"}))

    headers = dict(AUTH, Range="bytes=5000-", **{"If-Range": str(0x5F6000FF)})
    status, _, body = box.request("GET", f"/v2/content/{ruid}", headers=headers)

    assert (status, body) == (200, only)


def test_a_resume_is_never_given_another_taf_with_the_same_audio_id(box, library):
    # Audio ids are often encode times in seconds, so two TAFs of a pool can share one.
    twins = {put_taf(library / "__random_twins" / f"{i}.taf", 0x5F650000) for i in range(2)}
    ruid = "0a0b0c0c500304e0"
    assign(ruid, put_pool(library, "__random_twins.tap", {"directory": "lib://__random_twins/"}))

    for _ in range(10):
        headers = dict(AUTH, Range="bytes=5000-", **{"If-Range": str(0x5F650000)})
        status, _, body = box.request("GET", f"/v2/content/{ruid}", headers=headers)
        assert status == 200 and body in twins


def test_v3_chapters_come_from_the_taf_the_meta_announced(box, library):
    pool = {0x5F700000 + i: put_taf(library / "__random_v3" / f"{i}.taf", 0x5F700000 + i) for i in range(3)}
    ruid = "0a0b0c09500304e0"
    assign(ruid, put_pool(library, "__random_v3.tap", {"directory": "lib://__random_v3/"}))

    for _ in range(10):
        status, _, body = box.request("GET", f"/v3/content-meta/{ruid}", headers=AUTH)
        assert status == 200, body[:200]
        meta = json.loads(body)
        chapter = meta["content"][0]["name"]
        status, _, audio = box.request("GET", f"/v3/chapter/{chapter}", headers=AUTH)
        assert status == 200, audio[:200]
        assert audio and audio in pool[meta["version"]]


def test_v3_chapters_of_a_pick_that_shares_its_audio_id(box, library):
    # Two different TAFs with one audio id: the chapters must still come from the one the meta announced.
    twins = [put_taf(library / "__random_v3_twins" / f"{i}.taf", 0x5F750000) for i in range(2)]
    ruid = "0a0b0c0d500304e0"
    assign(ruid, put_pool(library, "__random_v3_twins.tap", {"directory": "lib://__random_v3_twins/"}))

    for _ in range(10):
        status, _, body = box.request("GET", f"/v3/content-meta/{ruid}", headers=AUTH)
        assert status == 200, body[:200]
        chapter = json.loads(body)["content"][0]["name"]
        status, _, audio = box.request("GET", f"/v3/chapter/{chapter}", headers=AUTH)
        assert status == 200, audio[:200]
        assert audio and any(audio in twin for twin in twins)


def test_a_normal_playlist_is_unchanged(box, library):
    encoded = put_taf(library / "__random_plain" / "out.taf", 0x5F900000)
    playlist = {"type": "tap", "audio_id": 0x5F900000, "filepath": "lib://__random_plain/out.taf", "name": "Plain",
                "files": [{"filepath": "lib://__random_plain/a.mp3", "name": "a"}]}
    (library / "__random_plain.tap").write_text(json.dumps(playlist))
    ruid = "0a0b0c0b500304e0"
    assign(ruid, "lib://__random_plain.tap")

    assert set(served(box, ruid, times=5)) == {encoded}
    assert json.loads(content_json(ruid).read_text()).get("live") is not True

"""
What teddyCloud reports as ContentTitle when the box reports the audio id it plays:

- Tonies encoded in the same second share an audio id and differ only in the hash
  (the German Pokemon tonies, toniebox-reverse-engineering/tonies-json#354): the title is
  the one of the tag's own TAF, not of the first tonie with that audio id.
- Audio id 1, the empty content of creative tonies, is told apart only by the tag's model.
- Without a valid tag on the box nothing is read, so no content is created for it.

    make test_py TESTS=audio_id_collision
"""

import hashlib
import http.client
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import rtnl, taf  # noqa: E402
from sim.box import Box, SseListener  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")

AUDIO_ID = 0x6A84A3EE
# tag E00403500EEDCC01 (content directory 01CCED0E/500304E0); the box sends the two 4-byte halves swapped
BOX_UID = 0x0EEDCC01E0040350
TAG_RUID = "01cced0e500304e0"
TAG_PATH = Path(SANDBOX or ".") / "data" / "content" / "default" / "01CCED0E" / "500304E0"
OTHER_MODEL, OWN_MODEL = "TC_TEST_COLLISION_OTHER", "TC_TEST_COLLISION_OWN"


def api(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=10)
    try:
        conn.request(method, path, body, headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def custom_entry(model, title, audio, audio_id=AUDIO_ID):
    return {"model": model, "series": "Collision test", "episodes": title, "title": title,
            "audio_id": [str(audio_id)], "hash": [hashlib.sha1(audio).hexdigest().upper()], "tracks": []}


def upsert(entries):
    status, text = api("POST", "/api/toniesCustomJsonUpsert", json.dumps(entries), {"Content-Type": "application/json"})
    assert status == 200, text


def delete(*models):
    api("POST", "/api/toniesCustomJsonDelete", json.dumps({"models": list(models)}), {"Content-Type": "application/json"})


def title_reported(mac, *frames):
    """ContentTitle sent while a simulated box with this MAC sends the RTNL frames. Each test uses its own MAC:
    the server keeps a box's tag state until it restarts, and a new MAC has no tag yet."""
    box = Box(mac, SANDBOX, BASE.hostname, HTTPS_API_PORT)
    sse = SseListener(BASE.hostname, BASE.port)
    try:
        time.sleep(0.3)  # let the server register the subscription
        box.rtnl(*frames)
        return sse.wait_for("ContentTitle", timeout=10)[-1]
    finally:
        sse.close()
        box.close()


def put_tag_taf(content):
    TAG_PATH.parent.mkdir(parents=True, exist_ok=True)
    TAG_PATH.write_bytes(content)


def remove_tag():
    TAG_PATH.unlink(missing_ok=True)
    TAG_PATH.with_suffix(".json").unlink(missing_ok=True)  # the server creates it when it reads the tag


# a lookup by audio id alone finds whichever tonie comes first, so both orders are tested
@pytest.fixture(params=["other first", "own first"])
def tag_with_colliding_audio_id(request):
    own_audio, other_audio = os.urandom(3 * 4096), os.urandom(3 * 4096)
    entries = [custom_entry(OTHER_MODEL, "Other tonie", other_audio), custom_entry(OWN_MODEL, "Own tonie", own_audio)]
    upsert(entries if request.param == "other first" else entries[::-1])
    put_tag_taf(taf.build(AUDIO_ID, own_audio))
    yield
    remove_tag()
    delete(OTHER_MODEL, OWN_MODEL)


def test_title_of_the_tags_own_taf(tag_with_colliding_audio_id):
    frames = rtnl.frame(rtnl.tag_placed(BOX_UID, sequence=1)), rtnl.frame(rtnl.audio_id(AUDIO_ID, sequence=2))
    assert title_reported("deadbeef0004", *frames) == "Own tonie"


def test_unknown_audio_id_without_a_tag():
    # no tag since the server started, as after a playback stop (log entries can arrive late): tag 0 must not get content
    assert title_reported("deadbeef0005", rtnl.frame(rtnl.audio_id(AUDIO_ID ^ 1, sequence=1))) == "Unknown"
    assert not (Path(SANDBOX) / "data" / "content" / "default" / "00000000").exists()


def test_audio_id_one_without_a_tag():
    # audio id 1 is no tonie's own id, so it alone must not pick one
    upsert([custom_entry(OTHER_MODEL, "Other tonie", b"one", audio_id=1)])
    try:
        assert title_reported("deadbeef0006", rtnl.frame(rtnl.audio_id(1, sequence=1))) == "Unknown"
    finally:
        delete(OTHER_MODEL)


def test_creative_tonie_shows_its_model():
    # audio id 1 is the empty content of creative tonies, and many of them share its hash: only the model
    # the tag is assigned to tells which one is on the box, a hash match must not win
    audio = os.urandom(3 * 4096)
    try:
        upsert([custom_entry(OTHER_MODEL, "Other tonie", audio, audio_id=1), custom_entry(OWN_MODEL, "Own tonie", os.urandom(16), audio_id=1)])
        put_tag_taf(taf.build(1, audio))
        status, text = api("POST", f"/content/json/set/{TAG_RUID}", f"tonie_model={OWN_MODEL}", {"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 200, text
        frames = rtnl.frame(rtnl.tag_placed(BOX_UID, sequence=1)), rtnl.frame(rtnl.audio_id(1, sequence=2))
        assert title_reported("deadbeef0007", *frames) == "Own tonie"
    finally:
        remove_tag()
        delete(OTHER_MODEL, OWN_MODEL)


def test_no_content_for_an_invalid_tag():
    # an invalid tag is no tonie: an audio id reported while it lies on the box must not create content for it
    try:
        put_tag_taf(taf.build(AUDIO_ID, os.urandom(3 * 4096)))
        frames = rtnl.frame(rtnl.tag_placed(BOX_UID, valid=False, sequence=1)), rtnl.frame(rtnl.audio_id(AUDIO_ID ^ 1, sequence=2))
        assert title_reported("deadbeef0008", *frames) == "Unknown"
        assert not TAG_PATH.with_suffix(".json").exists()
    finally:
        remove_tag()

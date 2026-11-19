"""
A downloaded tonie that takes long to go into the cache, as on a slow library drive. Its own file, as its server
needs the test-only TEDDYCLOUD_TEST_CACHE_DELAY_MS (src/content_download.c), set by the Makefile from this line:

# server env: TEDDYCLOUD_TEST_CACHE_DELAY_MS=6000

    make test_py TESTS=cloud_content_slow_cache
"""

import json
import os
import time
from pathlib import Path

import pytest

from test_cloud_content import MB, Tonie, api, box, cloud, content_requests, download, fresh, taf  # noqa: F401 (fixtures)

pytestmark = pytest.mark.skipif(
    os.environ.get("TEDDYCLOUD_TEST_CACHE_DELAY_MS") != "6000" or not os.environ.get("TC_SANDBOX"),
    reason="needs the server from tests/py/with_server.sh with the env above, run it with make test_py",
)


def test_request_while_the_tonie_is_cached_is_served_at_once(box, cloud):
    """Copying a downloaded tonie into the cache and a library on another drive (USB stick, NAS share) takes as long
    as that drive needs. A box asking meanwhile does not wait for it: it gets the complete .tmp."""
    tonie = Tonie(1 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    first = download(box, tonie.ruid)
    time.sleep(0.5)  # the server is done with that request too, caching has begun
    started = time.time()
    r = download(box, tonie.ruid)
    waited = time.time() - started
    not_yet = not tonie.library.exists()
    assert (first.status, first.body == tonie.content) == (200, True)
    assert (r.status, r.body == tonie.content) == (200, True)
    assert not_yet and waited < 3, f"answered after {waited:.1f} s, cached already: {not not_yet}"
    assert tonie.cached() and len(content_requests(cloud, tonie)) == 1


def test_forced_redownload_keeps_what_is_cached_after_its_answer(cloud):
    """A forced redownload of a corrupted tonie restores the tag's old source if nothing was cached. The download
    caches after the last byte went out, here seconds later: the request has to wait for that, or it would restore
    the corrupted file's source, and the download could not replace that file."""
    ruid = "0000000100000340"  # a system tag: fetched from the cloud without a box token
    audio_id = 340340
    data = taf.build(audio_id, os.urandom(64 * 1024))
    library = Path(os.environ["TC_SANDBOX"]) / "data" / "library" / "by" / "audioID" / f"{audio_id}.taf"
    cloud.script = lambda h: cloud.reply(h, 200, data, {"Content-Type": "binary/octet-stream"})

    def tag_info():
        status, body = api("GET", f"/api/getTagInfo?ruid={ruid}&validate=true")
        assert status == 200, body
        return json.loads(body)["tagInfo"]

    def cached(seconds=15):
        deadline = time.time() + seconds
        while time.time() < deadline and not (library.exists() and library.read_bytes() == data):
            time.sleep(0.1)
        return library.exists() and library.read_bytes() == data

    assert api("GET", f"/content/download/{ruid[:8].upper()}/{ruid[8:].upper()}")[0] == 200
    assert cached()
    with open(library, "r+b") as f:  # zeros inside the audio, the header stays intact
        f.seek(taf.HEADER_SIZE + 8192)
        f.write(bytes(16 * 1024))
    info = tag_info()
    assert info["corrupt"]

    assert api("GET", info["redownloadUrl"])[0] == 200
    assert cached(), "the corrupted library file was kept"
    info = tag_info()
    assert info["valid"] and not info["corrupt"] and info["source"] == f"lib://by/audioID/{audio_id}.taf", info

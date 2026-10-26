"""
A corrupted TAF in the library is replaced when the content is fetched from the cloud again
(https://github.com/toniebox-reverse-engineering/teddycloud/issues/338). The corruption keeps the
header intact (a zero-filled region inside the audio, as in issue 346), so the header hash of the
library file and of the fresh download are the same.

    make test_py TESTS=taf_library_replace
"""

import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import taf  # noqa: E402
from sim.upstream import FakeCloud  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")

pytestmark = pytest.mark.skipif(not SANDBOX, reason="needs the sandbox from tests/py/with_server.sh")

RUID = "0000000100000338"  # a system tag: fetched from the cloud without a box token
AUDIO_ID = 338338
DOWNLOAD = f"/content/download/{RUID[:8].upper()}/{RUID[8:].upper()}"
CONTENT = f"/v1/content/{RUID}"


def api(method, path, body=None, timeout=20):
    import http.client

    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=timeout)
    try:
        conn.request(method, path, body)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def setting(name, value):
    assert api("POST", f"/api/settings/set/{name}", str(value).lower())[0] == 200
    assert api("GET", "/api/triggerWriteConfig")[0] == 200
    time.sleep(1.2)  # the overlay follows after the next config reload


def library_file():
    return Path(SANDBOX) / "data" / "library" / "by" / "audioID" / f"{AUDIO_ID}.taf"


def wait_for(predicate, seconds=10):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


@pytest.fixture(scope="module")
def cloud():
    c = FakeCloud(SANDBOX)
    setting("cloud.remote_hostname", "localhost")
    setting("cloud.remote_port", c.port)
    setting("cloud.enabled", "true")
    yield c
    c.close()


@pytest.fixture(scope="module")
def taf_file(cloud):
    data = taf.build(AUDIO_ID, os.urandom(64 * 1024))

    def script(h):
        if h.path == CONTENT:
            cloud.reply(h, 200, data, {"Content-Type": "binary/octet-stream"})
        else:
            cloud.reply(h, 404)

    cloud.script = script
    return data


def corrupt(path):
    """Zero 16 KiB inside the audio, the header (first 4 KiB) stays intact."""
    with open(path, "r+b") as f:
        f.seek(taf.HEADER_SIZE + 8192)
        f.write(bytes(16 * 1024))


def test_corrupted_library_file_is_replaced_on_refetch(cloud, taf_file):
    status, _ = api("GET", DOWNLOAD)
    assert status == 200
    assert wait_for(lambda: library_file().exists() and library_file().read_bytes() == taf_file), "first download was not cached to the library"

    corrupt(library_file())
    assert library_file().read_bytes() != taf_file

    # with full validation the corrupted file is not served, the content is fetched again
    setting("core.full_taf_validation", "true")
    try:
        cloud.requests.clear()
        status, _ = api("GET", DOWNLOAD)
        assert status == 200
        assert [r[1] for r in cloud.requests] == [CONTENT]
        assert wait_for(lambda: library_file().read_bytes() == taf_file), "the corrupted library file was kept"
        status, body = api("GET", f"/api/getTagInfo?ruid={RUID}")
        info = json.loads(body)["tagInfo"]
        assert info["source"] == f"lib://by/audioID/{AUDIO_ID}.taf"
        assert not info["live"] and not info["nocloud"], "the corrupted TAF was treated as a stream source"
    finally:
        setting("core.full_taf_validation", "false")

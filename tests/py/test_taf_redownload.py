"""
Corrupted TAFs are reported in the tag info and can be redownloaded from the cloud
(https://github.com/toniebox-reverse-engineering/teddycloud/issues/338). The corruption keeps the
header intact (a zero-filled region inside the audio, as in issue 346).

    make test_py TESTS=taf_redownload
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

RUID = "0000000100000339"  # a system tag: fetched from the cloud without a box token
AUDIO_ID = 339339
DOWNLOAD = f"/content/download/{RUID[:8].upper()}/{RUID[8:].upper()}"
CONTENT = f"/v1/content/{RUID}"
CUSTOM_SOURCE = "__redownload_custom.taf"


def api(method, path, body=None, timeout=20):
    import http.client

    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=timeout)
    try:
        conn.request(method, path, body)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


_current = {}


def setting(name, value):
    value = str(value).lower()
    if _current.get(name) == value:
        return
    assert api("POST", f"/api/settings/set/{name}", value)[0] == 200
    assert api("GET", "/api/triggerWriteConfig")[0] == 200
    _current[name] = value
    time.sleep(1.2)  # the overlay follows after the next config reload


def tag_info(validate=False):
    status, body = api("GET", f"/api/getTagInfo?ruid={RUID}" + ("&validate=true" if validate else ""))
    assert status == 200, body
    return json.loads(body)["tagInfo"]


def library_file():
    return Path(SANDBOX) / "data" / "library" / "by" / "audioID" / f"{AUDIO_ID}.taf"


def wait_for(predicate, seconds=10):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


def corrupt(path):
    """Zero 16 KiB inside the audio, the header (first 4 KiB) stays intact."""
    with open(path, "r+b") as f:
        f.seek(taf.HEADER_SIZE + 8192)
        f.write(bytes(16 * 1024))


@pytest.fixture(scope="module")
def cloud():
    c = FakeCloud(SANDBOX)
    setting("cloud.remote_hostname", "localhost")
    setting("cloud.remote_port", c.port)
    yield c
    c.close()


@pytest.fixture(scope="module")
def taf_file(cloud):
    data = taf.build(AUDIO_ID, os.urandom(64 * 1024))

    def script(h):
        if h.path.split("?")[0] == CONTENT:  # a plain download passes the local query string (overlay) on
            cloud.reply(h, 200, data, {"Content-Type": "binary/octet-stream"})
        else:
            cloud.reply(h, 404)

    cloud.script = script
    setting("cloud.enabled", "true")
    status, _ = api("GET", DOWNLOAD)
    assert status == 200
    assert wait_for(lambda: library_file().exists() and library_file().read_bytes() == data), "download was not cached to the library"
    return data


@pytest.fixture(autouse=True)
def fresh(cloud):
    cloud.requests.clear()
    setting("cloud.enabled", "true")
    yield


def test_intact_file_is_not_corrupt(taf_file):
    info = tag_info(validate=True)
    assert info["exists"] and info["valid"] and not info["corrupt"]
    assert info["redownloadUrl"].endswith("&force=true")


def test_corrupted_file_is_reported_and_redownloaded(cloud, taf_file):
    corrupt(library_file())
    info = tag_info(validate=True)
    assert info["corrupt"] and not info["valid"]

    status, _ = api("GET", info["redownloadUrl"])
    assert status == 200
    assert [r[1] for r in cloud.requests] == [CONTENT]  # force and overlay stay local
    assert wait_for(lambda: library_file().read_bytes() == taf_file), "the corrupted library file was kept"

    info = tag_info(validate=True)
    assert info["valid"] and not info["corrupt"]
    assert info["source"] == f"lib://by/audioID/{AUDIO_ID}.taf"


def test_forced_download_serves_no_local_file_without_cloud(cloud, taf_file):
    redownload = tag_info()["redownloadUrl"]
    corrupt(library_file())
    corrupted = library_file().read_bytes()
    setting("cloud.enabled", "false")

    status, _ = api("GET", redownload)
    assert status == 404
    assert cloud.requests == []
    assert library_file().read_bytes() == corrupted, "the local file was changed without a download"

    # repair for the next tests
    setting("cloud.enabled", "true")
    assert api("GET", redownload)[0] == 200
    assert wait_for(lambda: library_file().read_bytes() == taf_file)


def test_no_redownload_without_content_cache(cloud, taf_file):
    redownload = tag_info()["redownloadUrl"]
    setting("cloud.cacheContent", "false")
    try:
        assert "redownloadUrl" not in tag_info()
        status, _ = api("GET", redownload)
        assert status == 409
        assert cloud.requests == []
        assert library_file().read_bytes() == taf_file
    finally:
        setting("cloud.cacheContent", "true")


def test_failed_cloud_download_keeps_the_source(cloud, taf_file):
    redownload = tag_info()["redownloadUrl"]
    script = cloud.script
    cloud.script = lambda h: cloud.reply(h, 500)
    try:
        api("GET", redownload)
    finally:
        cloud.script = script
    info = tag_info()
    assert info["exists"] and info["source"] == f"lib://by/audioID/{AUDIO_ID}.taf"
    assert library_file().read_bytes() == taf_file


def test_custom_source_is_not_redownloaded(cloud, taf_file):
    custom = Path(SANDBOX) / "data" / "library" / CUSTOM_SOURCE
    custom.write_bytes(taf.build(AUDIO_ID + 1, os.urandom(16 * 1024)))
    redownload = tag_info()["redownloadUrl"]
    try:
        assert api("POST", f"/content/json/set/{RUID}", f"source=lib://{CUSTOM_SOURCE}")[0] == 200
        info = tag_info()
        assert info["exists"] and "redownloadUrl" not in info

        status, _ = api("GET", redownload)
        assert status == 409
        assert cloud.requests == []
        assert tag_info()["source"] == f"lib://{CUSTOM_SOURCE}"
    finally:
        api("POST", f"/content/json/set/{RUID}", f"source=lib://by/audioID/{AUDIO_ID}.taf")
        custom.unlink()

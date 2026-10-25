"""
Cloud proxy tests against a local fake cloud (tests/sim/upstream.py): forwarding, the
local fallback, and redirect handling with hostile Location headers.

    make test_py TESTS=cloud_proxy
"""

import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import profiles  # noqa: E402
from sim.box import Box  # noqa: E402
from sim.upstream import FakeCloud  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")


def api(method, path, body=None):
    import http.client

    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=10)
    try:
        conn.request(method, path, body)
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


_current = {}


def setting(name, value):
    value = str(value).lower()
    if _current.get(name) == value:
        return
    assert api("POST", f"/api/settings/set/{name}", value)[0] == 200
    # API changes live in memory only: the next reload from disk (every new box saves the overlay file and
    # triggers one) would drop them. The web UI persists with triggerWriteConfig as well.
    assert api("GET", "/api/triggerWriteConfig")[0] == 200
    _current[name] = value
    # The box's overlay follows the global value only after the next reload of the config (main loop: 250 ms
    # poll, file time granularity); the API readback is true earlier, so there is nothing better to poll.
    time.sleep(1.2)


def alive():
    return api("GET", "/web/")[0] == 200


@pytest.fixture(scope="module")
def cloud():
    c = FakeCloud(SANDBOX)
    setting("cloud.remote_hostname", "localhost")
    setting("cloud.remote_port", c.port)
    setting("cloud.enableV1Time", "true")
    yield c
    c.close()


@pytest.fixture(scope="module")
def box(cloud):
    b = Box(None, SANDBOX, BASE.hostname, HTTPS_API_PORT, profile=profiles.CC3200)
    b.request("GET", "/v1/time")  # creates the overlay (cloud still disabled: answered locally)
    time.sleep(1.2)  # the new overlay is saved and reloaded
    yield b
    b.close()


@pytest.fixture(autouse=True)
def fresh(cloud):
    cloud.requests.clear()
    cloud.script = cloud._default
    setting("cloud.enabled", "true")
    yield
    assert alive(), "server is not answering after the test (crashed?)"


def is_local_time(text):
    return re.fullmatch(r"\d{9,}", text.strip()) is not None and abs(int(text) - time.time()) < 3600


def test_time_is_forwarded_to_the_cloud(box, cloud):
    status, _, body = box.request("GET", "/v1/time")
    assert (status, body) == (200, FakeCloud.TIME)
    assert [r[1] for r in cloud.requests] == ["/v1/time"]


@pytest.mark.parametrize("answer", [b"<html>maintenance</html>", b"-1", b" 1700000000", b"0"])
def test_cloud_time_that_is_no_number_is_not_passed_on(box, cloud, answer):
    """A 3.4.0 CC3200 that got "teddycloud" blinked red and switched off."""
    cloud.script = lambda h: cloud.reply(h, 200, answer, {"Content-Type": "text/plain"})
    status, _, body = box.request("GET", "/v1/time")
    assert status == 200 and is_local_time(body.decode()), body


def test_cloud_disabled_stays_local(box, cloud):
    setting("cloud.enabled", "false")
    status, _, body = box.request("GET", "/v1/time")
    assert status == 200 and is_local_time(body.decode())
    assert cloud.requests == []


def test_unreachable_cloud_falls_back_to_local(box, cloud):
    cloud.script = lambda h: h.connection.close()  # drop the connection without an answer
    status, _, body = box.request("GET", "/v1/time")
    assert status == 200 and is_local_time(body.decode())


@pytest.mark.parametrize("location", [
    "https://127.0.0.1/" + "x" * 5000,  # longer than the fixed buffers in the redirect handling
    "https://" + "h" * 400 + "/path",
    "https://127.0.0.1/p?" + "q=" + "y" * 3000,
    "not a url",
    "/relative",
    "",
])
def test_redirect_with_hostile_location_is_survived(box, cloud, location):
    cloud.script = lambda h: cloud.reply(h, 302, b"", {"Location": location})
    status, _, _ = box.request("GET", "/v1/time")
    assert status in (200, 302, 404, 500, 502, 504)
    time.sleep(0.2)


def test_redirect_loop_is_bounded(box, cloud):
    # the redirect target is always port 443 on the host, so this ends in a connect error; it must end
    cloud.script = lambda h: cloud.reply(h, 302, b"", {"Location": "https://127.0.0.1/v1/time"})
    start = time.time()
    box.request("GET", "/v1/time")
    assert time.time() - start < 30
    assert len(cloud.requests) <= 6


def test_settings_reload_while_cloud_requests_run(box, cloud):
    """The main loop reloads the settings on every config change and replaced the strings other threads were
    reading (use-after-free, ASan crash in web_request). Hammer cloud requests while forcing reloads."""
    import threading

    stop = threading.Event()
    results = []

    def requests_loop():
        while not stop.is_set():
            try:
                results.append(box.request("GET", "/v1/time")[2])
            except OSError:
                results.append(None)

    t = threading.Thread(target=requests_loop)
    t.start()
    try:
        for i in range(12):
            assert api("POST", "/api/settings/set/hass.name", f"reload {i}")[0] == 200
            assert api("GET", "/api/triggerWriteConfig")[0] == 200
            time.sleep(0.4)
    finally:
        stop.set()
        t.join(15)
    assert len(results) > 20 and results.count(FakeCloud.TIME) > 10, results


# what Boxine answered to /v1/ota/3 of a CC3200 on 3.3.0 (capture): the firmware image with its SHA-256 as 64
# hex characters appended (the ESP32 gets "<ts>-esp32-toniebox-eu-v5.237.0-app.ota" in the same format)
OTA_HEADERS = {
    "Content-Type": "binary/octet-stream",
    "Content-Disposition": "attachment;filename=1779199517_toniebox-eu_v3.4.0.hashed.bin",
    "ETag": '"0123456789abcdef0123456789abcdef"',
    "Last-Modified": "Wed, 20 May 2026 12:33:19 GMT",
    "Accept-Ranges": "bytes",
}


def test_ota_is_passed_through_as_the_cloud_sends_it(box, cloud):
    import hashlib

    image = os.urandom(163328 - 64)
    ota = image + hashlib.sha256(image).hexdigest().encode()
    setting("cloud.enableV1Ota", "true")
    setting("cloud.cacheOta", "false")
    try:
        cloud.script = lambda h: cloud.reply(h, 200, ota, OTA_HEADERS) if "/v1/ota/3" in h.path else cloud.reply(h, 304)
        assert box.request("GET", "/v1/ota/5?cv=1669853893")[0] == 304
        status, headers, body = box.request("GET", "/v1/ota/3?cv=1777468756")
        assert status == 200 and body == ota
        assert [r[1] for r in cloud.requests] == ["/v1/ota/5?cv=1669853893", "/v1/ota/3?cv=1777468756"]
        assert cloud.requests[1][2]["User-Agent"] == box.user_agent
        assert {k: headers.get(k) for k in OTA_HEADERS} == OTA_HEADERS
    finally:
        setting("cloud.cacheOta", "true")
        setting("cloud.enableV1Ota", "false")


def test_ota_is_cached_and_held_back_by_default(box, cloud):
    """Defaults (cacheOta on, localOta off): the server asks the cloud for anything newer than what it has
    cached (cv=1 with an empty cache), keeps the file and tells the box there is no update. With localOta it
    delivers the cached file."""
    import hashlib

    image = os.urandom(5000)
    ota = image + hashlib.sha256(image).hexdigest().encode()
    setting("cloud.enableV1Ota", "true")
    cloud.script = lambda h: cloud.reply(h, 200, ota, OTA_HEADERS)
    try:
        assert box.request("GET", "/v1/ota/3?cv=1777468756")[0] == 304
        assert [r[1] for r in cloud.requests] == ["/v1/ota/3?cv=1"]
        setting("cloud.enableV1Ota", "false")
        setting("cloud.localOta", "true")
        with box.keep_alive() as c:
            status, headers, body = c.request("GET", "/v1/ota/3?cv=1777468756")
        assert status == 200 and body == ota
    finally:
        setting("cloud.localOta", "false")
        setting("cloud.enableV1Ota", "false")

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
    return re.fullmatch(r"\d{9,}", text.strip()) is not None


def test_time_is_forwarded_to_the_cloud(box, cloud):
    status, _, body = box.request("GET", "/v1/time")
    assert (status, body) == (200, b"CLOUDTIME")
    assert [r[1] for r in cloud.requests] == ["/v1/time"]


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
    assert len(results) > 20 and results.count(b"CLOUDTIME") > 10, results

"""
Official tonies downloaded through the server from a (fake) cloud, as a box asks for them:
/v2/content/<ruid> while the tonie is not cached yet.

    make test_py TESTS=cloud_content
"""

import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import profiles, taf  # noqa: E402
from sim.box import Box  # noqa: E402
from sim.upstream import FakeCloud  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")

# a token that is not all zeros, else the tonie is taken for a custom one (cloud.markCustomTagByPass)
AUTH = {"Authorization": "BD " + "5a" * 32}
MB = 1024 * 1024


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
    assert api("GET", "/api/triggerWriteConfig")[0] == 200  # see test_cloud_proxy.setting
    _current[name] = value
    time.sleep(1.2)


@pytest.fixture(scope="module")
def cloud():
    c = FakeCloud(SANDBOX)
    setting("cloud.remote_hostname", "localhost")
    setting("cloud.remote_port", c.port)
    yield c
    c.close()


def make_box(profile):
    b = Box(None, SANDBOX, BASE.hostname, HTTPS_API_PORT, profile=profile)
    b.request("GET", "/v1/time")  # creates the overlay
    time.sleep(1.2)  # the new overlay is saved and reloaded
    return b


@pytest.fixture(scope="module")
def box(cloud):
    b = make_box(profiles.CC3200)
    yield b
    b.close()


@pytest.fixture(scope="module")
def box2(cloud):
    b = make_box(profiles.ESP32)
    yield b
    b.close()


@pytest.fixture(autouse=True)
def fresh(cloud):
    cloud.requests.clear()
    cloud.drops.clear()
    cloud.completed.clear()
    cloud.script = cloud._default
    setting("cloud.enabled", "true")
    yield
    assert api("GET", "/web/")[0] == 200, "server is not answering after the test (crashed?)"


_ruids = iter(range(1, 1000))


class Tonie:
    """An official tonie that is not cached yet and the TAF the cloud has for it. The rUID ends in 0304e0, else it
    is taken for a custom tag (cloud.markCustomTagByUid)."""

    def __init__(self, size):
        n = next(_ruids)
        self.ruid = f"0a{n:06x}50" + "0304e0"
        self.audio_id = 0x5F000000 + n
        self.content = taf.build(self.audio_id, os.urandom(size - taf.HEADER_SIZE))
        content_dir = Path(SANDBOX) / "data" / "content" / "default" / self.ruid[:8].upper()
        self.path = content_dir / self.ruid[8:].upper()
        self.tmp = content_dir / (self.ruid[8:].upper() + ".tmp")
        self.json = content_dir / (self.ruid[8:].upper() + ".json")
        self.library = Path(SANDBOX) / "data" / "library" / "by" / "audioID" / f"{self.audio_id}.taf"

    def source(self):
        return json.loads(self.json.read_text()).get("source")

    def cached(self, timeout=15):
        """Waits until the tonie is in the library, as cloud.cacheToLibrary (default) puts it."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.library.exists() and self.source() == f"lib://by/audioID/{self.audio_id}.taf":
                return True
            time.sleep(0.1)
        return False

    def nothing_left(self, timeout=5):
        """Waits until there is neither a .tmp nor a cached file of the tonie."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not (self.tmp.exists() or self.path.exists() or self.library.exists()):
                return True
            time.sleep(0.1)
        return False


def content_requests(cloud, tonie):
    return [r for r in cloud.requests if r[1] == f"/v2/content/{tonie.ruid}"]


def completed_at(cloud, timeout=10):
    """When the cloud sent the last byte of the (first) content."""
    deadline = time.time() + timeout
    while not cloud.completed and time.time() < deadline:
        time.sleep(0.05)
    return cloud.completed[0][1]


class Response:
    status = 0
    headers = None  # name -> value (the last of a name)
    header_lines = ()  # (name, value) as sent
    body = b""
    raw = b""  # the body as sent (chunked: with the chunk framing)
    complete = False  # the body ended as its framing says: Content-Length reached, last chunk, or the server closed
    t_first = None  # when the first body byte came in
    t_end = None  # when the server ended the response (or closed the connection)

    @property
    def length(self):
        """Content-Length, None without one"""
        value = self.headers.get("Content-Length")
        return None if value is None else int(value)

    @property
    def chunked(self):
        return self.headers.get("Transfer-Encoding", "").lower() == "chunked"


def dechunk(raw):
    """(body, complete) of a chunked body as far as it is in."""
    body, pos = b"", 0
    while True:
        eol = raw.find(b"\r\n", pos)
        if eol < 0:
            return body, False
        size = int(raw[pos:eol].split(b";")[0], 16)
        start = eol + 2
        if size == 0:
            return body, raw.find(b"\r\n", start) >= 0  # the empty trailer
        if len(raw) < start + size + 2:
            return body + raw[start:start + size], False
        body += raw[start:start + size]
        pos = start + size + 2


def download(box, ruid, headers=None, pause_at=None, pause=0, stop_at=None):
    """GET /v2/content/<ruid> on a new connection, read like a box does. pause_at/pause: stop reading for `pause`
    seconds once `pause_at` body bytes are in (what the server sees of a slow box: its TCP window stays full).
    stop_at: close the connection once that many body bytes are in. The body ends as its framing says (Content-
    Length, chunked, or until the server closes); r.complete is False if the server ended the response early."""
    r = Response()
    s = box.connect(suppress_ragged_eofs=False)  # a response cut short raises, see below
    s.settimeout(15)
    if pause_at is not None:
        # a small window, so the box takes nothing while it pauses (no autotuning)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    try:
        lines = [f"GET /v2/content/{ruid} HTTP/1.1", f"Host: {box.host}", f"User-Agent: {box.user_agent}"]
        lines += [f"{k}: {v}" for k, v in {**AUTH, **(headers or {})}.items()]
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(65536)
            if not chunk:
                raise ConnectionError(f"no response header, got {data!r}")
            data += chunk
        raw_head, _, r.raw = data.partition(b"\r\n\r\n")
        head = raw_head.decode(errors="replace").split("\r\n")
        r.status = int(head[0].split()[1])
        r.header_lines = tuple(tuple(line.split(": ", 1)) for line in head[1:] if ": " in line)
        r.headers = dict(r.header_lines)

        def done():
            if r.chunked:
                r.body, r.complete = dechunk(r.raw)
            else:
                r.body = r.raw
                r.complete = r.length is not None and len(r.raw) >= r.length
            return r.complete

        paused = False
        while not done():
            if r.body and r.t_first is None:
                r.t_first = time.time()
            if stop_at is not None and len(r.body) >= stop_at:
                break
            if pause_at is not None and not paused and len(r.body) >= pause_at:
                paused = True
                time.sleep(pause)
            try:
                chunk = s.recv(65536)
            except (OSError, ValueError):  # a TLS close without close_notify, a reset: the response was cut short
                break
            if not chunk:
                # the end of a body without Content-Length and chunks, with close_notify
                r.complete = r.length is None and not r.chunked
                break
            r.raw += chunk
        if r.body and r.t_first is None:
            r.t_first = time.time()
        r.t_end = time.time()
        return r
    finally:
        s.close()


@pytest.mark.xfail(strict=True, reason="the box gets the cloud's answer passed through at the box's speed")
def test_slow_box_gets_the_whole_tonie(box, cloud):
    """A box that takes the data slower than the cloud sends it. The cloud drops a connection it could not write to
    for a while (nginx send_timeout, about a minute at Boxine; 2 s here). The server read the cloud only as fast as
    the box took the data, so once the socket buffers in between were full the cloud dropped it and the box got an
    incomplete file. Its retry with Range is passed through the same way, and a 206 is not cached: a slow box gets
    the tonie in pieces if at all, and it never reaches the cache."""
    tonie = Tonie(16 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content, idle_timeout=2)
    r = download(box, tonie.ruid, pause_at=256 * 1024, pause=6)
    assert (r.status, r.length) == (200, len(tonie.content))
    got = len(r.body)
    assert got == len(tonie.content), f"incomplete, the cloud dropped the server's connection: {cloud.drops}"
    assert r.body == tonie.content, "corrupt"
    assert cloud.drops == [] and len(content_requests(cloud, tonie)) == 1
    assert tonie.cached() and tonie.library.read_bytes() == tonie.content
    assert not tonie.tmp.exists() and not tonie.path.exists()


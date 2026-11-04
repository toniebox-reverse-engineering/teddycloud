"""
Official tonies downloaded through the server from a (fake) cloud, as a box asks for them:
/v2/content/<ruid> while the tonie is not cached yet. The server downloads it in the background at the
cloud's speed and serves the boxes from the growing file.

    make test_py TESTS=cloud_content
"""

import base64
import gzip
import hashlib
import json
import os
import socket
import sys
import threading
import time
from email.utils import format_datetime, parsedate_to_datetime
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


def test_slow_box_gets_the_whole_tonie(box, cloud):
    """A box that takes the data slower than the cloud sends it. The cloud drops a connection it could not write to
    for a while (nginx send_timeout, about a minute at Boxine; 2 s here). The server read the cloud only as fast as
    the box took the data, so once the socket buffers in between were full the cloud dropped it and the box got an
    incomplete file - on every retry again, as the retry started the download from the beginning."""
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


def test_range_request_is_served_from_the_growing_file(box, cloud):
    """The box continues an aborted download with Range (and If-Range: its audio id). The server answers it with a
    206 from the file that is still being downloaded, the cloud is asked for the whole file once."""
    tonie = Tonie(4 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content, rate=2 * MB)  # the download takes 2 s
    start = 1 * MB
    r = download(box, tonie.ruid, headers={"Range": f"bytes={start}-", "If-Range": str(tonie.audio_id)})
    size = len(tonie.content)
    assert (r.status, r.headers.get("Content-Range")) == (206, f"bytes {start}-{size - 1}/{size}")
    assert r.length == size - start and r.body == tonie.content[start:]
    requests = content_requests(cloud, tonie)
    assert len(requests) == 1 and "Range" not in requests[0][2]
    assert r.t_first < completed_at(cloud), "the box got nothing before the download was complete"
    assert tonie.cached()


def test_range_with_skip_header_is_answered_like_cached_content(box, cloud):
    """skip_header (the web player) serves the audio without the TAF header, a Range then counts in the audio. The
    download and the cached file answer it the same, also for a range in the last 4 KB of the file, for which local
    content was sent from the start of the file."""
    tonie = Tonie(64 * 1024)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    audio = tonie.content[taf.HEADER_SIZE:]
    start = len(audio) - 1000
    expected = (206, f"bytes {start}-{len(audio) - 1}/{len(audio)}", audio[start:])
    downloading = download(box, tonie.ruid + "?skip_header=true", headers={"Range": f"bytes={start}-"})
    assert (downloading.status, downloading.headers.get("Content-Range"), downloading.body) == expected
    assert tonie.cached()
    cached = download(box, tonie.ruid + "?skip_header=true", headers={"Range": f"bytes={start}-"})
    assert (cached.status, cached.headers.get("Content-Range"), cached.body) == expected
    assert len(content_requests(cloud, tonie)) == 1


@pytest.mark.parametrize("framing", ["chunked", "close"])
def test_answer_without_length_is_streamed_as_the_cloud_framed_it(box, cloud, framing):
    """Without Content-Length the box gets the content as it comes in, framed as the cloud did it (chunked, or until
    the connection is closed), as through the pass-through, not only once the download and its validation are done.
    It is cached as any other."""
    tonie = Tonie(4 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content, rate=2 * MB, framing=framing)
    r = download(box, tonie.ruid)
    assert (r.status, r.length, r.chunked) == (200, None, framing == "chunked")
    assert r.complete and r.body == tonie.content
    assert r.t_first < completed_at(cloud), "the box got nothing before the download was complete"
    assert tonie.cached()


def test_answer_ending_with_the_connection_is_complete_only_as_a_valid_taf(box, box2, cloud):
    """An answer without Content-Length and chunks ends with the connection, and a connection that breaks ends it
    too. Taken for complete, a box asking meanwhile got the broken part with a Content-Length that looked right.
    It is complete only once it is a valid TAF; a box asking then gets the whole tonie from a new download."""
    tonie = Tonie(16 * MB)
    # broken off after more than the socket buffers to the slow box hold, so that box still reads when it breaks
    answers = iter([lambda h: cloud.stream(h, tonie.content, framing="close", drop_after=12 * MB),
                    lambda h: cloud.stream(h, tonie.content)])
    cloud.script = lambda h: next(answers)(h)
    results = {}
    slow = threading.Thread(target=lambda: results.update(slow=download(box, tonie.ruid, pause_at=64 * 1024, pause=5)))
    slow.start()
    deadline = time.time() + 10
    while not cloud.drops and time.time() < deadline:
        time.sleep(0.05)
    r = download(box2, tonie.ruid)  # comes while it is checked, or once it failed: it gets a new download either way
    slow.join(30)
    assert not slow.is_alive()
    cut = results["slow"]
    assert (cut.complete, cut.body == tonie.content[:len(cut.body)]) == (False, True), "the slow box could not tell it was cut short"
    assert (r.status, r.complete, r.body == tonie.content) == (200, True, True), f"{r.status} {r.length} {len(r.body)}"
    assert len(content_requests(cloud, tonie)) == 2
    assert tonie.cached()


def test_two_boxes_share_one_download(box, box2, cloud):
    """A second box asking for the tonie while it is downloaded is served from the same download."""
    tonie = Tonie(4 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content, rate=2 * MB)
    results = {}
    first = threading.Thread(target=lambda: results.update(first=download(box, tonie.ruid)))
    first.start()
    deadline = time.time() + 5
    while not content_requests(cloud, tonie) and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.3)
    asked = time.time()
    results["second"] = download(box2, tonie.ruid)
    first.join(20)
    assert not first.is_alive()
    for name in ("first", "second"):
        r = results[name]
        assert (r.status, r.body == tonie.content) == (200, True), name
    assert len(content_requests(cloud, tonie)) == 1
    assert asked < completed_at(cloud), "the second box asked only after the download was complete"
    assert tonie.cached()


def test_tonie_is_cached_while_boxes_keep_reading(box, box2, cloud):
    """Requests that overlap without end (a slow box, its retries, another box, the web player) must not keep a
    complete download out of the cache: it is in the library within seconds of being complete, while boxes still
    read. Those that had the .tmp open finish on it, later ones get the cached file, every one the whole tonie, and
    the .tmp is gone once its last reader is done. The cached file is a hard link to the .tmp, not a copy of it (that
    is for Windows and FAT)."""
    tonie = Tonie(16 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    results = {}

    def slow(name, b, pause):
        results[name] = download(b, tonie.ruid, pause_at=256 * 1024, pause=pause)

    readers = [threading.Thread(target=slow, args=("first", box, 10))]  # reads the .tmp
    readers[0].start()
    done = completed_at(cloud)
    cached = tonie.cached(timeout=10)
    cached_after = time.time() - done
    tmp_while_read = tonie.tmp.exists()
    linked = tmp_while_read and tonie.tmp.stat().st_ino == tonie.library.stat().st_ino
    # one more slow box after the other, each while the one before still reads: never nobody reading
    for i, b in enumerate((box2, box, box2)):
        readers.append(threading.Thread(target=slow, args=(f"overlap {i}", b, 4)))
        readers[-1].start()
        time.sleep(1.5)
    for t in readers:
        t.join(40)
    assert cached and cached_after < 5, f"cached {cached_after:.1f} s after the download was complete"
    assert not any(t.is_alive() for t in readers)
    for name, r in results.items():
        assert (r.status, r.body == tonie.content) == (200, True), name
    assert tmp_while_read, "the .tmp was gone while the first box still read it"
    assert linked, "the cached tonie is a copy of the .tmp"
    deadline = time.time() + 5
    while tonie.tmp.exists() and time.time() < deadline:
        time.sleep(0.1)
    assert not tonie.tmp.exists(), "the .tmp is left behind"
    assert tonie.library.read_bytes() == tonie.content and len(content_requests(cloud, tonie)) == 1


def server_log():
    """What the server logged so far (its stdout, the log file of tests/py/with_server.sh)."""
    log = Path(f"/proc/{os.environ.get('TC_SERVER_PID', 0)}/fd/1")
    if not log.exists():
        pytest.skip("needs the server's /proc entry (Linux, TC_SERVER_PID from tests/py/with_server.sh)")
    return log.read_text(errors="replace")


def test_tonie_nobody_reads_is_renamed_into_the_cache(box, cloud):
    """A download nobody reads when it is complete is renamed into the cache: no second write and no space for a
    second copy, also where there are no hard links (Windows, FAT). The cached tonie is the former .tmp."""
    tonie = Tonie(4 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content, rate=2 * MB)  # 2 s
    copy = tonie.path.with_name(tonie.path.name + ".copy")
    r = download(box, tonie.ruid, stop_at=1)  # starts it and goes
    deadline = time.time() + 5
    while not tonie.tmp.exists() and time.time() < deadline:
        time.sleep(0.02)
    inode = tonie.tmp.stat().st_ino
    copies = 0
    while not tonie.cached(timeout=0.05) and time.time() < deadline + 10:
        copies += copy.exists()
        time.sleep(0.02)
    assert r.status == 200 and tonie.cached()
    assert tonie.library.stat().st_ino == inode and tonie.library.read_bytes() == tonie.content
    assert copies == 0 and not tonie.tmp.exists()
    assert f"Successfully cached {tonie.path} (renamed)" in server_log()


def test_copy_left_by_a_crash_is_removed(box, cloud):
    """Where the .tmp is copied into the cache, a server stopped during the copy leaves a <tonie>.copy behind. The
    next time the tonie is cached it is removed, whichever way that one is cached."""
    tonie = Tonie(256 * 1024)
    copy = tonie.path.with_name(tonie.path.name + ".copy")
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_bytes(b"half a tonie")
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    r = download(box, tonie.ruid)
    assert (r.status, r.body == tonie.content) == (200, True)
    assert tonie.cached() and not copy.exists()


def test_tonie_deleted_from_the_cache_is_downloaded_again(box, box2, cloud):
    """A cached tonie deleted (or outdated) while a box still reads its download: the next box asking does not read
    the old download's file, it gets a new download of its own, which caches the tonie again."""
    tonie = Tonie(4 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    results = {}
    slow = threading.Thread(target=lambda: results.update(slow=download(box, tonie.ruid, pause_at=64 * 1024, pause=5)))
    slow.start()
    assert tonie.cached()
    tonie.library.unlink()
    r = download(box2, tonie.ruid)
    slow.join(20)
    assert not slow.is_alive()
    assert (results["slow"].status, results["slow"].body == tonie.content) == (200, True)
    assert (r.status, r.body == tonie.content) == (200, True)
    assert len(content_requests(cloud, tonie)) == 2 and tonie.cached()


def test_settings_reloads_during_a_long_download(box, cloud):
    """A download outlives a request by far (a slow box keeps it for minutes) and in the end caches the file with
    the box's settings. Settings memory a reload replaces is freed after a grace period (2 s in the tests, see
    tests/py/with_server.sh), so the download must look the settings up when it uses them, not keep them from the
    request. Reloads are forced while the download runs for longer than the grace period, as in
    test_cloud_proxy.test_settings_reload_while_cloud_requests_run. (A slow cloud and not a slow box keeps it
    running here: a box holds the download only once the socket buffers are full, and moving that much data
    through the server recycles the sanitizer's quarantine so fast that freed memory is reused unnoticed.)"""
    tonie = Tonie(1 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content, rate=160 * 1024)  # 6.5 s
    stop = threading.Event()
    done = []  # reloads triggered; an error in the thread is kept here too, an assert there would get lost

    def reloads():
        try:
            while not stop.is_set():
                assert api("POST", "/api/settings/set/hass.name", f"reload {len(done)}")[0] == 200
                assert api("GET", "/api/triggerWriteConfig")[0] == 200
                done.append(True)
                time.sleep(1)
        except Exception as e:  # noqa: BLE001
            done.append(e)

    name = api("GET", "/api/settings/get/hass.name")[1]
    reloader = threading.Thread(target=reloads)
    reloader.start()
    try:
        r = download(box, tonie.ruid)
        cached = tonie.cached()
    finally:
        stop.set()
        reloader.join(15)
        api("POST", "/api/settings/set/hass.name", name)
        api("GET", "/api/triggerWriteConfig")
    # a reload every 1-2 s during the 6.5 s, the first more than the grace period before the file is cached
    assert all(d is True for d in done) and len(done) >= 3, done
    assert (r.status, r.body == tonie.content) == (200, True)
    assert cached and tonie.library.read_bytes() == tonie.content


def test_boxes_that_hang_up_while_waiting_free_their_connections(box, cloud):
    """A request that waits long before it can send (here: a Range near the end of a slow download) notices when its
    box hangs up. Else every box that asked again held one more of the server's 31 box connections for as long as
    the wait, until no box got an answer at all. Also a box that sent another request before it hung up."""
    tonie = Tonie(4 * MB)
    held = threading.Event()  # the download stays short of the Range until the boxes are done
    cloud.script = lambda h: cloud.stream(h, tonie.content, hold=held, hold_at=1 * MB)
    request = (f"GET /v2/content/{tonie.ruid} HTTP/1.1\r\nHost: {box.host}\r\nUser-Agent: {box.user_agent}\r\n"
               f"Authorization: {AUTH['Authorization']}\r\nRange: bytes={len(tonie.content) - 1000}-\r\n\r\n").encode()

    def ask_and_hang_up(pipelined):
        try:
            # 15 s for a free connection, not 5: 80 at once wait their turn, longer on a loaded machine. Held for the
            # wait (until the download is released) they would not get one at all.
            s = box.connect(timeout=15)
        except OSError:  # no connection free, counted below
            failed.append(pipelined)
            return
        try:
            s.sendall(request)
            time.sleep(0.3)  # the request is in
            if pipelined:
                s.sendall(request)  # waits unread behind the first: the hang-up must be seen behind it
        finally:
            s.close()

    failed = []
    try:
        first = threading.Thread(target=lambda: download(box, tonie.ruid, stop_at=64 * 1024))
        first.start()
        first.join(10)
        # more than the 31 connections both ways: hung up right after the request, and behind a second request
        hang_ups = [threading.Thread(target=ask_and_hang_up, args=(i % 2 == 1,)) for i in range(80)]
        for t in hang_ups:
            t.start()
        for t in hang_ups:
            t.join(30)
        time.sleep(2)  # noticed within a second
        started = time.time()
        status = box.request("GET", "/v1/time")[0]
        answered = time.time() - started
        still_downloading = not cloud.completed
    finally:
        held.set()
    assert still_downloading
    assert failed == [], f"{len(failed)} boxes found no free connection"
    assert status == 200 and answered < 3, f"answered after {answered:.1f} s"
    assert tonie.cached(timeout=40)


def test_full_taf_validation_reads_a_download_once(box, cloud):
    """core.full_taf_validation checks the hash of every TAF the server reads. A download is checked in full once,
    right after it came in; reading it in full a second time while it is cached was wasted time on a slow drive.
    Counted with the bytes the server read (rchar of /proc/<pid>/io, sockets too), for a tonie no box reads: the
    cloud's answer and the check, 2 times the tonie (the cached file is a hard link); with the second check 3 times."""
    io = Path(f"/proc/{os.environ.get('TC_SERVER_PID', 0)}/io")
    if not io.exists():
        pytest.skip("needs the server's /proc entry (Linux, TC_SERVER_PID from tests/py/with_server.sh)")

    def read_bytes():
        return int(next(line for line in io.read_text().splitlines() if line.startswith("rchar:")).split()[1])

    tonie = Tonie(16 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    setting("core.full_taf_validation", "true")
    try:
        before = read_bytes()
        r = download(box, tonie.ruid, stop_at=1)  # starts it and goes
        cached = tonie.cached()
        time.sleep(0.5)
        read = read_bytes() - before
    finally:
        setting("core.full_taf_validation", "false")
    assert r.status == 200 and cached
    assert read < 2.5 * len(tonie.content), f"read {read / len(tonie.content):.1f} times the tonie"


def test_box_disconnect_does_not_cancel_the_download(box, cloud):
    """A box that goes away (switched off, tonie taken off) does not stop the download: the tonie still ends up in
    the cache and the next request is answered from there."""
    tonie = Tonie(4 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content, rate=4 * MB)
    r = download(box, tonie.ruid, stop_at=64 * 1024)
    assert r.status == 200 and len(r.body) < len(tonie.content)
    assert tonie.cached(), "the download was cancelled with the box's connection"
    assert tonie.library.read_bytes() == tonie.content and not tonie.tmp.exists()
    r = download(box, tonie.ruid)
    assert (r.status, r.body == tonie.content) == (200, True)
    assert len(content_requests(cloud, tonie)) == 1, "not answered from the cache"


def test_finished_downloads_free_their_threads(box, cloud):
    """Every download runs in a task of its own. A thread nobody joins keeps its stack reserved after it ended
    (8 MB by default on Linux) unless it was created detached, so the server's address space grew with every
    tonie it downloaded."""
    status = Path(f"/proc/{os.environ.get('TC_SERVER_PID', 0)}/status")
    if not status.exists():
        pytest.skip("needs the server's /proc entry (Linux, TC_SERVER_PID from tests/py/with_server.sh)")

    def vm_size():
        line = next(line for line in status.read_text().splitlines() if line.startswith("VmSize:"))
        return int(line.split()[1]) * 1024

    def fetch():
        tonie = Tonie(64 * 1024)
        cloud.script = lambda h: cloud.stream(h, tonie.content)
        r = download(box, tonie.ruid)
        assert (r.status, r.body == tonie.content) == (200, True)
        assert tonie.cached()

    fetch()  # the first one may set up things that stay
    before = vm_size()
    count = 20
    for _ in range(count):
        fetch()
    grown = vm_size() - before
    assert grown < count * 2 * MB, f"address space grew by {grown // MB} MB over {count} downloads"


def test_retry_joins_the_running_download(box, cloud):
    """The box drops its connection and asks for the rest while the download still runs: no second download."""
    tonie = Tonie(4 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content, rate=2 * MB)
    first = download(box, tonie.ruid, stop_at=64 * 1024)
    assert first.status == 200
    got = len(first.body)
    asked = time.time()
    rest = download(box, tonie.ruid, headers={"Range": f"bytes={got}-", "If-Range": str(tonie.audio_id)})
    assert rest.status == 206 and first.body + rest.body == tonie.content
    assert len(content_requests(cloud, tonie)) == 1
    assert asked < completed_at(cloud), "the retry came only after the download was complete"
    assert tonie.cached()


@pytest.mark.parametrize("status", [403, 404, 410, 503])
def test_cloud_error_status_is_passed_on(box, cloud, status):
    """What the cloud answers instead of the content reaches the box as it came (a 404 makes an ESP32 play its local
    copy, a 410 makes the box drop it), with its caching policy; nothing is cached."""
    tonie = Tonie(64 * 1024)
    answer = b'{"detail": "nope"}'
    headers = {"Content-Type": "application/json", "Retry-After": "120", "Cache-Control": "no-store"}
    cloud.script = lambda h: cloud.reply(h, status, answer, headers)
    r = download(box, tonie.ruid)
    assert (r.status, r.body) == (status, answer)
    assert {k: r.headers.get(k) for k in headers} == headers
    assert tonie.nothing_left()
    assert len(content_requests(cloud, tonie)) == 1


def test_cloud_error_too_long_is_given_on_without_its_body(box, cloud):
    """An answer that is not the content and longer than the server keeps reaches the box without its body, and
    without the header lines that describe that body."""
    tonie = Tonie(64 * 1024)
    body = gzip.compress(os.urandom(40 * 1024))
    headers = {"Content-Type": "application/json", "Content-Encoding": "gzip", "X-Kept": "1",
               "Content-MD5": base64.b64encode(hashlib.md5(body).digest()).decode()}
    cloud.script = lambda h: cloud.reply(h, 404, body, headers)
    r = download(box, tonie.ruid)
    assert (r.status, r.body, r.headers.get("X-Kept")) == (404, b"", "1")
    assert not {"content-encoding", "content-md5"} & {k.lower() for k in r.headers}, r.header_lines


def test_cloud_error_reaches_every_box_that_asked_meanwhile(box, box2, cloud):
    """A 503 (the cloud pushes back) answered slowly: every box asking meanwhile gets that one answer, nobody asks the
    cloud again. Before, each of them asked the cloud once more and got whatever the second answer was."""
    tonie = Tonie(64 * 1024)
    answer = b"<html>busy</html>"

    def busy(h):
        time.sleep(1.5)
        cloud.reply(h, 503, answer, {"Content-Type": "text/html", "Retry-After": "60", "X-Request-Id": "a1"})

    cloud.script = busy
    results = []
    boxes = [box, box2, box]
    threads = [threading.Thread(target=lambda b=b: results.append(download(b, tonie.ruid))) for b in boxes]
    for t in threads:
        t.start()
        time.sleep(0.2)
    for t in threads:
        t.join(20)
    assert len(results) == len(boxes)
    for r in results:
        assert (r.status, r.body, r.headers.get("Retry-After"), r.headers.get("X-Request-Id")) == (503, answer, "60", "a1")
        assert abs(parsedate_to_datetime(r.headers["Date"]).timestamp() - time.time()) < 60
    assert len(content_requests(cloud, tonie)) == 1
    assert tonie.nothing_left()


def test_cloud_headers_reach_the_boxes(box, box2, cloud):
    """The cloud's header lines reach every box served from the download, as they did through the pass-through: the
    first one and one joining it. The framing is the server's own, each header line comes once."""
    tonie = Tonie(4 * MB)
    headers = {"Content-Type": "binary/octet-stream", "ETag": '"0123abcd"', "Last-Modified": "Wed, 20 May 2026 12:33:19 GMT",
               "X-Cloud-Test": "kept"}
    # not given on, also when the cloud sends them twice (it sends a Date and a Server of its own too): hop-by-hop,
    # the server's own, or of the one answer and its body
    dropped = [("Date", "Mon, 02 Nov 2026 10:00:00 GMT"), ("Set-Cookie", "lb=a1; Path=/"), ("X-Hop", "1"),
               ("Connection", "close, X-Hop"), ("Accept-Ranges", "bytes"), ("Accept-Ranges", "none"),
               ("Cache-Control", "no-store"), ("Cache-Control", "max-age=0"), ("Pragma", "no-cache"), ("Expires", "0"),
               ("Strict-Transport-Security", "max-age=63072000"), ("Server", "nginx"), ("Alt-Svc", 'h3=":443"'),
               ("Content-MD5", base64.b64encode(hashlib.md5(tonie.content).digest()).decode()),
               ("Content-Digest", "sha-256=:" + base64.b64encode(hashlib.sha256(tonie.content).digest()).decode() + ":")]
    gone = {k.lower() for k, _ in dropped} - {"date", "connection", "accept-ranges"}  # those three the server sends
    cloud.script = lambda h: cloud.stream(h, tonie.content, headers=list(headers.items()) + dropped, rate=2 * MB)
    results = {}
    first = threading.Thread(target=lambda: results.update(first=download(box, tonie.ruid)))
    first.start()
    deadline = time.time() + 5
    while not content_requests(cloud, tonie) and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.3)
    results["joined"] = download(box2, tonie.ruid, headers={"Range": "bytes=1000-"})
    first.join(20)
    assert not first.is_alive()
    for name, r in results.items():
        assert r.status in (200, 206) and r.complete, name
        assert {k: r.headers.get(k) for k in headers} == headers, name
        assert not gone & {k.lower() for k in r.headers}, f"{name}: {r.header_lines}"
        assert (r.headers.get("Accept-Ranges"), r.headers.get("Connection")) == ("bytes", "keep-alive"), name
        date = parsedate_to_datetime(r.headers["Date"])
        assert abs(date.timestamp() - time.time()) < 60, f"{name}: {r.headers['Date']}"
        assert r.headers["Date"] == format_datetime(date, usegmt=True), "not an IMF-fixdate with the right weekday"
        names = [k.lower() for k, _ in r.header_lines]
        assert len(names) == len(set(names)), f"{name}: a header line twice: {r.header_lines}"
    assert len(content_requests(cloud, tonie)) == 1


def test_content_coded_answer_is_passed_through(box, cloud):
    """The download takes the cloud's bytes for the TAF: it checks and caches them, and cuts them for a Range. Content
    the cloud content-coded is not that; the box gets the cloud's answer as it came, through the pass-through, and
    nothing is cached."""
    tonie = Tonie(256 * 1024)
    coded = gzip.compress(tonie.content)
    cloud.script = lambda h: cloud.stream(h, coded, headers={"Content-Type": "binary/octet-stream", "Content-Encoding": "gzip"})
    r = download(box, tonie.ruid)
    assert (r.status, r.headers.get("Content-Encoding"), r.complete, r.body == coded) == (200, "gzip", True, True)
    assert tonie.nothing_left() and len(content_requests(cloud, tonie)) == 2
    # the download asked for the content as it is, this cloud coded it anyway
    assert content_requests(cloud, tonie)[0][2].get("Accept-Encoding") == "identity"


def test_resume_of_another_version_gets_the_whole_file(box, cloud):
    """The box resumes with If-Range: the audio id of the part it has. If the cloud's content is another one now, a
    206 would make a file of two versions: it gets the whole file instead."""
    tonie = Tonie(1 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    r = download(box, tonie.ruid, headers={"Range": "bytes=5000-", "If-Range": str(tonie.audio_id - 1)})
    assert (r.status, "Content-Range" in r.headers, r.body == tonie.content) == (200, False, True)
    assert tonie.cached()


def test_cloud_dropping_mid_download_ends_the_response_incomplete(box, cloud):
    """The cloud drops the connection: the box's response ends early, at once, so it asks for the rest; no broken
    file is left in the cache. Its retry with Range gets the rest from a new download."""
    tonie = Tonie(4 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content, drop_after=1 * MB)
    started = time.time()
    first = download(box, tonie.ruid)
    assert first.status == 200 and first.length == len(tonie.content)
    assert len(first.body) <= 1 * MB
    assert first.t_end - started < 10, "the server kept the connection open after the download failed"
    assert tonie.nothing_left(), "a partial file was left behind"
    assert cloud.drops == [(f"/v2/content/{tonie.ruid}", 1 * MB)]

    cloud.script = lambda h: cloud.stream(h, tonie.content)
    got = len(first.body)
    rest = download(box, tonie.ruid, headers={"Range": f"bytes={got}-"} if got else None)
    assert rest.status == (206 if got else 200)
    assert first.body + rest.body == tonie.content
    assert len(content_requests(cloud, tonie)) == 2
    assert tonie.cached()


def test_unreachable_cloud_ends_the_connection(box, cloud):
    """No answer from the cloud at all: the server closes the box's connection (the box tries again later) instead
    of leaving it waiting for an answer that never comes."""
    tonie = Tonie(64 * 1024)
    cloud.script = lambda h: h.connection.close()
    started = time.time()
    with pytest.raises(OSError) as closed:
        download(box, tonie.ruid)
    assert not isinstance(closed.value, TimeoutError) and time.time() - started < 10, "the connection was left open"
    assert tonie.nothing_left()


def test_invalid_taf_is_passed_on_but_not_cached(box, cloud):
    """What the cloud sends with a 200 reaches the box as it is (as before); only a valid TAF is cached."""
    tonie = Tonie(1 * MB)
    broken = tonie.content[:-1] + bytes([tonie.content[-1] ^ 0xFF])  # the SHA-1 in the header does not match
    cloud.script = lambda h: cloud.stream(h, broken)
    r = download(box, tonie.ruid)
    assert (r.status, r.body == broken) == (200, True)
    assert tonie.nothing_left()


def test_download_that_is_not_cached_takes_no_new_requests(box, box2, cloud):
    """A download that does not go into the cache (here: no valid TAF) stays until its readers are done. A box asking
    after it ended gets the cloud's answer through the pass-through: joining it, requests that keep overlapping would
    get the .tmp for as long as they come, and the cloud would not be asked again."""
    tonie = Tonie(16 * MB)  # more than the socket buffers take, so the slow box keeps reading
    broken = tonie.content[:-1] + bytes([tonie.content[-1] ^ 0xFF])  # the SHA-1 in the header does not match
    cloud.script = lambda h: cloud.stream(h, broken)
    results = {}
    slow = threading.Thread(target=lambda: results.update(slow=download(box, tonie.ruid, pause_at=64 * 1024, pause=6)))
    slow.start()
    completed_at(cloud)
    time.sleep(1)  # checked: no valid TAF, not cached; the slow box still reads
    r = download(box2, tonie.ruid)
    slow.join(20)
    assert not slow.is_alive()
    for name, response in (("slow", results["slow"]), ("later", r)):
        assert (response.status, response.body == broken) == (200, True), name
    assert len(content_requests(cloud, tonie)) == 2
    assert tonie.nothing_left()


def test_leftover_tmp_linked_to_a_cached_tonie_is_not_overwritten(box, cloud):
    """A cached tonie is a hard link to the .tmp of its download until that is deleted. If the server stopped before
    (crash, power loss), the .tmp left behind is that tonie under another name: a new download of the tag must not
    write into it."""
    tonie = Tonie(256 * 1024)
    cached = Path(SANDBOX) / "data" / "library" / "linked.taf"
    cached.write_bytes(b"cached tonie" * 1000)
    tonie.tmp.parent.mkdir(parents=True, exist_ok=True)
    os.link(cached, tonie.tmp)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    try:
        r = download(box, tonie.ruid)
        assert (r.status, r.body == tonie.content) == (200, True)
        assert tonie.cached()
        assert cached.read_bytes() == b"cached tonie" * 1000
    finally:
        cached.unlink()


def test_unwritable_cache_falls_back_to_the_pass_through(box, cloud):
    """The .tmp cannot be written (read-only or full data directory; here a directory is in its way, one that is not
    empty, else it is deleted like a .tmp left behind): the box still gets the content, passed through as before."""
    tonie = Tonie(1 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    tonie.tmp.mkdir(parents=True)
    (tonie.tmp / "in the way").write_bytes(b"")
    try:
        r = download(box, tonie.ruid)
    finally:
        (tonie.tmp / "in the way").unlink()
        tonie.tmp.rmdir()
    assert (r.status, r.body == tonie.content) == (200, True)
    assert tonie.nothing_left(timeout=1)
    assert len(content_requests(cloud, tonie)) <= 2  # the download's request and the pass-through's


def test_download_that_cannot_start_is_passed_through(box, cloud):
    """No task for the download (no threads left): the request, and every one that joined it meanwhile, is passed
    through to the cloud as before instead of having its connection closed. RLIMIT_NPROC of the server makes the
    thread creation fail."""
    import resource

    pid = int(os.environ.get("TC_SERVER_PID", "0"))
    if not pid or not hasattr(resource, "prlimit") or os.geteuid() == 0:  # root is not held to RLIMIT_NPROC
        pytest.skip("needs the server's pid (tests/py/with_server.sh), Linux and a user other than root")
    tonie = Tonie(1 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    soft, hard = resource.prlimit(pid, resource.RLIMIT_NPROC)
    resource.prlimit(pid, resource.RLIMIT_NPROC, (1, hard))
    try:
        r = download(box, tonie.ruid)
    finally:
        resource.prlimit(pid, resource.RLIMIT_NPROC, (soft, hard))
    assert (r.status, r.body == tonie.content) == (200, True)
    assert len(content_requests(cloud, tonie)) == 1, "the pass-through's only"
    assert tonie.nothing_left()


def test_retry_that_cannot_start_a_download_is_passed_through(box, box2, cloud):
    """A request that joined a download which failed before it answered tries a new one; when that cannot be started
    either (no threads left), it is passed through to the cloud like any request that finds no download, instead of
    being left without an answer."""
    import resource

    pid = int(os.environ.get("TC_SERVER_PID", "0"))
    if not pid or not hasattr(resource, "prlimit") or os.geteuid() == 0:  # root is not held to RLIMIT_NPROC
        pytest.skip("needs the server's pid (tests/py/with_server.sh), Linux and a user other than root")
    tonie = Tonie(1 * MB)

    def first_no_answer_then_content(h):
        if len(content_requests(cloud, tonie)) == 1:
            time.sleep(1.5)  # the second box joins meanwhile
            h.connection.close()
        else:
            cloud.stream(h, tonie.content)

    cloud.script = first_no_answer_then_content
    results = {}

    def ask(name, b):
        try:
            results[name] = download(b, tonie.ruid)
        except OSError as e:  # no answer at all
            results[name] = e

    first = threading.Thread(target=ask, args=("first", box))
    first.start()
    deadline = time.time() + 5
    while not content_requests(cloud, tonie) and time.time() < deadline:
        time.sleep(0.05)
    joined = threading.Thread(target=ask, args=("joined", box2))
    joined.start()
    time.sleep(0.5)  # it joined; from now on no download can be started
    soft, hard = resource.prlimit(pid, resource.RLIMIT_NPROC)
    resource.prlimit(pid, resource.RLIMIT_NPROC, (1, hard))
    try:
        first.join(20)
        joined.join(20)
    finally:
        resource.prlimit(pid, resource.RLIMIT_NPROC, (soft, hard))
    r = results["joined"]
    assert not isinstance(r, Exception), f"no answer: {r!r}"
    assert (r.status, r.body == tonie.content) == (200, True)
    assert len(content_requests(cloud, tonie)) == 2, "the failed download's and the pass-through's"


def test_without_cache_content_is_passed_through(box, cloud):
    """cloud.cacheContent off: the content is passed through as the cloud sends it and nothing is written."""
    tonie = Tonie(1 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    setting("cloud.cacheContent", "false")
    try:
        r = download(box, tonie.ruid)
    finally:
        setting("cloud.cacheContent", "true")
    assert (r.status, r.body == tonie.content) == (200, True)
    assert tonie.nothing_left(timeout=1)

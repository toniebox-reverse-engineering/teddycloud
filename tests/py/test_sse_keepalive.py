"""
Box events and the SSE keep-alive share two locks. Taken in opposite order they
deadlock: every later /api/sse request then hangs and holds an HTTP connection.

    make test_py TESTS=sse_keepalive
"""

import http.client
import os
import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import rtnl  # noqa: E402
from sim.box import Box, SseListener  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

# SSE_KEEPALIVE_S in include/handler_sse.h
KEEPALIVE_S = 15
# Each subscriber sends a keep-alive when it connects and every KEEPALIVE_S after.
# The deadlock needs a keep-alive while an event is half written, so the test
# staggers several subscribers to get many keep-alives during the events. It
# stays below SSE_MAX_CHANNELS (8) so that the final check finds a free slot.
SUBSCRIBERS = 6

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")


def sse_answers(timeout=5):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=timeout)
    try:
        conn.request("GET", "/api/sse")
        return conn.getresponse().status == 200
    except (socket.timeout, TimeoutError):
        return False
    finally:
        conn.close()


def send_events(box, stop):
    """Sends volume events in batches until stopped or the server stops reading."""
    stream = box.rtnl(keep_open=True)
    stream.settimeout(2)
    sequence = 0
    try:
        while not stop.is_set():
            batch = []
            for _ in range(5):
                sequence += 1
                batch.append(rtnl.frame(rtnl.volume_changed(5, -20, sequence=sequence)))
            try:
                stream.sendall(b"".join(batch))
            except (socket.timeout, TimeoutError, OSError):
                return
            time.sleep(0.002)
    finally:
        stream.close()


def test_sse_survives_box_events_across_keepalives():
    box = Box("deadbeef0002", SANDBOX, BASE.hostname, HTTPS_API_PORT)
    stop = threading.Event()
    sender = threading.Thread(target=send_events, args=(box, stop), daemon=True)
    listeners = []
    try:
        # subscribe before the events start, so that no subscriber joins mid-event
        for _ in range(SUBSCRIBERS):
            listeners.append(SseListener(BASE.hostname, BASE.port))
            time.sleep(KEEPALIVE_S / SUBSCRIBERS)
        sender.start()
        time.sleep(KEEPALIVE_S + 2)  # every subscriber's next keep-alive falls into the events
        stop.set()
        sender.join(5)

        assert sse_answers(), "a new /api/sse request got no answer: the event stream is deadlocked"
        last = 1_000_000
        box.rtnl(rtnl.frame(rtnl.tag_placed(1, sequence=last)))
        deadline = time.time() + 5
        while not any(n == "rtnl-raw-log2" and isinstance(d, dict) and d.get("sequence") == last for n, d in listeners[0].events):
            assert time.time() < deadline, "the subscribed client stopped receiving box events"
            time.sleep(0.05)
    finally:
        stop.set()
        for listener in listeners:
            listener.close()
        box.close()

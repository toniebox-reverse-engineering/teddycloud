"""
A client subscribing to /api/sse while box events are being written must get
its response header first, not a piece of an event.

    make test_py TESTS=sse_join
"""

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
from sim.box import Box  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

# The window is short and opens once per event, so it takes many subscriptions
# to hit. A slot is free again only after an event write to the closed client
# fails, so subscriptions are limited to the 8 slots turning over; refused and
# 503 attempts are paced and not counted.
SUBSCRIPTIONS = 1000
MAX_S = 60

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")


def first_line_of_sse_response():
    with socket.create_connection((BASE.hostname, BASE.port), timeout=5) as sock:
        sock.sendall(f"GET /api/sse HTTP/1.1\r\nHost: {BASE.hostname}:{BASE.port}\r\n\r\n".encode())
        data = b""
        while b"\r\n" not in data:
            chunk = sock.recv(256)
            if not chunk:
                break
            data += chunk
    return data.split(b"\r\n", 1)[0].decode(errors="replace")


def send_events(box, stop):
    stream = box.rtnl(keep_open=True)
    stream.settimeout(2)
    sequence = 0
    try:
        while not stop.is_set():
            sequence += 1
            try:
                stream.sendall(rtnl.frame(rtnl.volume_changed(5, -20, sequence=sequence)))
            except OSError:
                return
            time.sleep(0.001)
    finally:
        stream.close()


def test_sse_header_comes_first_while_events_flow():
    box = Box("deadbeef0003", SANDBOX, BASE.hostname, HTTPS_API_PORT)
    stop = threading.Event()
    sender = threading.Thread(target=send_events, args=(box, stop), daemon=True)
    sender.start()
    try:
        time.sleep(0.5)  # events are flowing
        bad = []
        subscribed = 0
        deadline = time.time() + MAX_S
        while subscribed < SUBSCRIPTIONS and time.time() < deadline:
            try:
                line = first_line_of_sse_response()
            except (ConnectionRefusedError, socket.timeout, TimeoutError):
                time.sleep(0.05)
                continue
            if line.startswith("HTTP/1.1 200"):
                subscribed += 1
            elif line.startswith("HTTP/1.1 "):
                time.sleep(0.01)  # all SSE slots taken
            else:
                bad.append(line)
    finally:
        stop.set()
        sender.join(5)
        box.close()
    assert not bad, f"{len(bad)} subscribers got event data before the response header: {bad[:5]}"
    assert subscribed >= SUBSCRIPTIONS // 2, f"only {subscribed} subscriptions in {MAX_S} s, the test proves little"

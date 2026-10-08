"""
Toniebox simulator tests: a simulated box connects to the sandboxed server with a
client certificate and talks the HTTPS API and the RTNL log protocol.

    make test_py TESTS=box_sim
"""

import os
import sys
import time
import json
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import rtnl  # noqa: E402
from sim.box import Box, SseListener  # noqa: E402

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


def alive():
    return api("GET", "/web/")[0] == 200


@pytest.fixture(scope="module")
def box():
    b = Box("deadbeef0001", SANDBOX, BASE.hostname, HTTPS_API_PORT)
    yield b
    b.close()


@pytest.fixture
def sse():
    s = SseListener(BASE.hostname, BASE.port)
    time.sleep(0.3)  # let the server register the subscription
    yield s
    s.close()


def test_box_with_cert_is_authenticated(box):
    status, _, body = box.request("GET", "/v1/time")
    assert status == 200, body


def test_box_is_authenticated_on_a_second_connection(box):
    first = box.connect()
    session = first.session
    first.close()
    status, _, _ = box.request("GET", "/v1/time", session=session)
    assert status == 200


def test_request_without_cert_is_rejected(box):
    assert box.request("GET", "/v1/time", use_cert=False)[0] == 401


def test_new_box_is_listed(box):
    box.request("GET", "/v1/time")
    status, text = api("GET", "/api/getBoxes")
    assert status == 200
    assert any(box.mac in b["commonName"].lower() for b in json.loads(text)["boxes"]), text


def test_unknown_box_is_rejected_without_allow_new_box(box):
    assert api("POST", "/api/settings/set/core.allowNewBox", "false")[0] == 200
    try:
        stranger = Box("deadbeef0002", SANDBOX, BASE.hostname, HTTPS_API_PORT)
        try:
            assert stranger.request("GET", "/v1/time")[0] == 401
        finally:
            stranger.close()
    finally:
        api("POST", "/api/settings/set/core.allowNewBox", "true")


def test_rtnl_log2_reaches_sse(box, sse):
    box.rtnl(rtnl.frame(rtnl.tag_placed(0xE0040350AABBCCDD, sequence=42)))
    ev = sse.wait_for("rtnl-raw-log2")[0]
    assert (ev["sequence"], ev["function_group"], ev["function"]) == (42, rtnl.FUGR_TAG, rtnl.FUNC_TAG_VALID_CC3200)


def test_rtnl_batched_frames_are_all_delivered(box, sse):
    box.rtnl(*(rtnl.frame(rtnl.volume_changed(5, -20, sequence=i)) for i in range(1, 6)))
    assert [e["sequence"] for e in sse.wait_for("rtnl-raw-log2", count=5)] == [1, 2, 3, 4, 5]


def test_rtnl_log3(box, sse):
    box.rtnl(rtnl.frame(rtnl.tag_placed(1)), rtnl.frame(rtnl.log3(1700000000, 7)))
    assert sse.wait_for("rtnl-raw-log3")[0]["field2"] == 7


MALFORMED = {
    "zero length": b"\x00\x00\x00\x00" + rtnl.CRLF,
    "length beyond data": b"\x00\x00\x10\x00" + b"\x12\x34" + rtnl.CRLF,
    "not protobuf": rtnl.frame(b"\xff" * 40 + rtnl.CRLF),
    "huge field6": rtnl.frame(rtnl.log2(1, 1, rtnl.FUGR_FIRMWARE, 1, b"A" * 20000, field9=b"B" * 5000 + rtnl.CRLF)),
    "short tag field6": rtnl.frame(rtnl.log2(1, 1, rtnl.FUGR_TAG, rtnl.FUNC_TAG_VALID_CC3200, b"\x01", field9=rtnl.CRLF)),
    "short volume field6": rtnl.frame(rtnl.log2(1, 1, rtnl.FUGR_VOLUME, rtnl.FUNC_VOLUME_CHANGE_CC3200, b"\x01\x02", field9=rtnl.CRLF)),
    "empty field6": rtnl.frame(rtnl.log2(1, 1, rtnl.FUGR_TILT, 15426, b"", field9=rtnl.CRLF)),
}


@pytest.mark.parametrize("name", MALFORMED)
def test_rtnl_malformed_input_does_not_kill_the_server(box, sse, name):
    try:
        box.rtnl(MALFORMED[name])
    except OSError:
        pass  # the server may drop the connection
    time.sleep(0.3)
    assert alive(), f"server died on '{name}'"
    box.rtnl(rtnl.frame(rtnl.tag_placed(1, sequence=99)))
    assert sse.wait_for("rtnl-raw-log2")[-1]["sequence"] in (1, 99)

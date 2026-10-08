"""
Per-hardware box simulation: CC3200, CC3235, ESP32 (both user agent styles) and TB2.

What the server code defines is tested (hardware detection from the user agent, RTNL events
with the hardware's function codes). Behaviour that differs per firmware/hardware and needs a
real capture is a skipped stub per profile, see tests/sim/profiles.py.

    make test_py TESTS=box_profiles
"""

import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import profiles, rtnl  # noqa: E402
from sim.box import Box, SseListener  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")


def api_get(path):
    import http.client

    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=10)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


@pytest.fixture(params=profiles.ALL_PROFILES, ids=lambda p: p.name)
def box(request):
    try:
        b = Box(None, SANDBOX, BASE.hostname, HTTPS_API_PORT, profile=request.param)
    except NotImplementedError as e:
        pytest.skip(f"stub: {e}")
    yield b
    b.close()


def overlay_id(box):
    boxes = json.loads(api_get("/api/getBoxes")[1])["boxes"]
    return next(b["ID"] for b in boxes if box.mac in b["commonName"].lower())


def overlay_setting(box, name):
    status, text = api_get(f"/api/settings/get/{name}?overlay={overlay_id(box)}")
    assert status == 200, text
    return int(text)


def test_hardware_is_detected_from_user_agent(box):
    assert box.request("GET", "/v1/time")[0] == 200
    assert overlay_setting(box, "internal.toniebox_firmware.boxIC") == box.profile.box_ic
    assert overlay_setting(box, "toniebox.boxGeneration") == box.profile.generation


def test_tls_handshake_with_the_profile_parameters(box):
    """The box connects with its own TLS version range, cipher suites and SNI use."""
    status, _, body = box.request("GET", "/v1/time")
    assert status == 200, body
    with box.connect() as s:
        print(box.profile.name, s.version(), s.cipher())


@pytest.mark.parametrize("suite", profiles.LEGACY_RSA_CBC.split(":")[:-1])
def test_legacy_cipher_suites_are_accepted(suite):
    """Each legacy suite on its own (what an old CC3200 stack could pick): the server must not drop them."""
    import dataclasses

    legacy = dataclasses.replace(profiles.CC3200, tls=dataclasses.replace(profiles.CC3200.tls, ciphers=suite + ":@SECLEVEL=0"))
    b = Box(None, SANDBOX, BASE.hostname, HTTPS_API_PORT, profile=legacy)
    try:
        assert b.request("GET", "/v1/time")[0] == 200
        with b.connect() as s:
            assert s.cipher()[0] == suite
    finally:
        b.close()


def test_rtnl_tag_events_use_the_hardware_function_codes(box):
    sse = SseListener(BASE.hostname, BASE.port)
    try:
        import time

        time.sleep(0.3)
        p = box.profile
        box.rtnl(
            rtnl.frame(rtnl.log2(1000, 1, rtnl.FUGR_TAG, p.tag_valid, (0xE0040350AABBCCDD).to_bytes(8, "big"), field9=rtnl.CRLF)),
            rtnl.frame(rtnl.log2(1001, 2, rtnl.FUGR_TAG, p.tag_invalid, (0xE0040350AABBCCDD).to_bytes(8, "big"), field9=rtnl.CRLF)),
        )
        events = sse.wait_for("rtnl-raw-log2", count=2)
        assert [(e["function_group"], e["function"]) for e in events] == [(rtnl.FUGR_TAG, p.tag_valid), (rtnl.FUGR_TAG, p.tag_invalid)]
    finally:
        sse.close()


@pytest.mark.parametrize("behaviour", profiles.STUB_BEHAVIOUR)
def test_hardware_specific_behaviour(box, behaviour):
    if behaviour in box.profile.stubs:
        pytest.skip(f"stub, needs a capture of a {box.profile.name}: {profiles.STUB_BEHAVIOUR[behaviour]}")

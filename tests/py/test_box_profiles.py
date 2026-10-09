"""
Per-hardware box simulation: CC3200, CC3235, ESP32 (both user agent styles) and TB2.

What the server code defines is tested (hardware detection from the user agent, RTNL events
with the hardware's function codes). For CC3200 and ESP32 also what captures of real boxes
show: their TLS handshake, HTTP requests at boot and the way they cut the RTNL stream into
TLS records. Behaviour that still needs a capture is a skipped stub per profile, see
tests/sim/profiles.py.

    make test_py TESTS=box_profiles
"""

import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import freshness, profiles, rtnl, rtnl_captured, taf, tls_hello  # noqa: E402
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


NO_DHE = pytest.mark.xfail(strict=True, reason="the server has no DH parameters; the CC3200 offers enough other suites")


@pytest.mark.parametrize("suite", [pytest.param(s, marks=NO_DHE) if s.startswith("DHE-") else s for s in profiles.CC3200_SUITES.split(":")])
def test_legacy_cipher_suites_are_accepted(suite):
    """Each suite of the CC3200 on its own (its fallbacks if the server dropped the one it picks)."""
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


@pytest.fixture(params=profiles.CAPTURED_PROFILES, ids=lambda p: p.name)
def captured(request):
    b = Box(None, SANDBOX, BASE.hostname, HTTPS_API_PORT, profile=request.param)
    yield b
    b.close()


def test_server_answers_the_real_client_hello(captured):
    """The captured ClientHello as it is: the server picks the suite it picked for the real box, and
    only uses what the box offers."""
    tls = captured.profile.tls
    offered = tls_hello.offers(tls.client_hello)
    flight = tls_hello.server_flight(BASE.hostname, HTTPS_API_PORT, tls.client_hello)
    assert flight.alert is None
    assert (flight.version, flight.cipher) == (0x0303, tls.cipher)
    # renegotiation_info answers the TLS_EMPTY_RENEGOTIATION_INFO_SCSV, which only the ESP32 sends
    assert set(flight.extensions) <= set(offered["extensions"]) | {0xFF01}
    assert flight.ske_curve in offered["groups"]
    assert flight.ske_sigalg in offered["sigalgs"]
    assert tls.cert_verify in flight.cert_request_sigalgs


def test_handshake_with_the_box_signature_algorithms(captured):
    """Full handshake with the box's signature algorithms, the CertificateVerify signed like the box does
    (CC3200: RSA/SHA-1)."""
    assert captured.openssl_request("GET", "/v1/time").startswith(b"HTTP/1.1 200 ")


def test_boot_requests_on_one_connection(captured):
    p = captured.profile
    uids = iter(range(0xE00403500A000001, 0xE00403500B000000))
    with captured.keep_alive() as c:
        for path in p.boot:
            status, _, body = c.request("GET", path)
            assert status == (200 if path == "/v1/time" else 304), path
        for count in p.freshness_batches:
            body = freshness.request([(next(uids), 0x5E000000 + i) for i in range(count)])
            assert len(body) == 16 * count
            status, headers, answer = c.request("POST", "/v1/freshness-check", body)
            assert status == 200
            assert set(freshness.response_fields(answer)) >= {2, 3, 4, 5, 6, 7, 8}
        status, _, _ = c.request("GET", "/v1/claim/0a0bccddee0304e0", headers={"Authorization": profiles.AUTHORIZATION})
        assert status == 200


# record sizes of the RTNL stream of a CC3200 (3.4.0) after its first frame: frames are cut anywhere, also
# within the 4-byte length header
CC3200_RTNL_RECORDS = (3, 1347, 1, 1381, 3, 1372, 789, 3, 59, 1, 96, 202, 2, 690, 2, 48, 314, 27, 3, 539, 1, 30, 2, 75, 1, 34, 2, 597, 3)


def rtnl_records(kind, frames):
    """The stream cut like the box does: "split" = CC3200 (first frame alone, then CC3200_RTNL_RECORDS),
    "batched" = ESP32 (whole frames, up to ~1400 bytes per record)."""
    if kind == "batched":
        records, current = [], b""
        for f in frames:
            if len(current) + len(f) > 1400:
                records.append(current)
                current = b""
            current += f
        return records + [current]
    data, records, pos = b"".join(frames), [frames[0]], len(frames[0])
    for size in CC3200_RTNL_RECORDS:
        records.append(data[pos:pos + size])
        pos += size
    return records + [data[pos:]]


def test_rtnl_stream_cut_like_the_box_does(captured):
    """Every frame shape the box sent in the capture (zero payloads), cut into records like the box does."""
    p = captured.profile
    # the first frame carries a line feed, see test_first_rtnl_record_without_line_feed
    frames = [rtnl.frame(rtnl.log2(5000, 1, rtnl.FUGR_TAG, p.tag_valid, (0xE0040350AABBCCDD).to_bytes(8, "big"), field9=rtnl.CRLF))]
    frames += rtnl_captured.frames(p.rtnl_log2, p.rtnl_log3, first_sequence=2)
    sse = SseListener(BASE.hostname, BASE.port)
    try:
        time.sleep(0.3)
        s = captured.rtnl(keep_open=True)
        for record in rtnl_records(p.rtnl_records, frames):
            s.sendall(record)
        log2 = sse.wait_for("rtnl-raw-log2", count=1 + len(p.rtnl_log2), timeout=10)
        log3 = sse.wait_for("rtnl-raw-log3", count=len(p.rtnl_log3), timeout=10)
        assert [(e["function_group"], e["function"], e["field3"], len(e["field6"]) // 2) for e in log2[1:]] == \
            [(group, function, field3, len6) for field3, group, function, len6, *_ in p.rtnl_log2]
        assert [e["field2"] for e in log3] == [field2 for field2, _ in p.rtnl_log3]
        s.close()
    finally:
        sse.close()


def put_content(box, audio_id=0x5E000001):
    """A TAF for a tonie of this box in the sandbox's content directory. Returns (ruid, file)."""
    ruid = box.mac[4:] + "500304e0"
    content = taf.build(audio_id, os.urandom(3 * 4096))
    path = Path(SANDBOX) / "data" / "content" / "default" / ruid[:8].upper() / ruid[8:].upper()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return ruid, content


def test_content_download_like_the_box(captured):
    """/v2/content without Range on a keep-alive connection, then the claim; the ESP32 claims once more on a
    new connection."""
    ruid, content = put_content(captured)
    auth = {"Authorization": profiles.AUTHORIZATION}
    with captured.keep_alive() as c:
        status, headers, body = c.request("GET", f"/v2/content/{ruid}", headers=auth)
        assert (status, headers.get("Content-Type"), body == content) == (200, "application/octet-stream", True)
        assert c.request("GET", f"/v1/claim/{ruid}", headers=auth)[0] == 200
    with captured.keep_alive() as c:
        assert c.request("GET", f"/v1/claim/{ruid}", headers=auth)[0] == 200


@pytest.mark.parametrize("ending", ["close_notify", "fin"])
def test_connection_ends_like_the_box(captured, ending):
    """The CC3200 ends a connection with close_notify and FIN or with a FIN only, the ESP32 with a FIN only:
    the server closes its side either way and keeps serving."""
    if ending not in captured.profile.endings:
        pytest.skip(f"a {captured.profile.name} does not end a connection with {ending}")
    for _ in range(2):
        c = captured.keep_alive()
        assert c.request("GET", "/v1/claim/0a0bccddee0304e0", headers={"Authorization": profiles.AUTHORIZATION})[0] == 200
        c.finish(ending)


@pytest.mark.xfail(strict=True, reason="the server reads the start of a connection line by line before it tells HTTP "
                   "from RTNL: a first record without a line feed waits for more data. The first record of a CC3200 on "
                   "3.1.0 BF2 has none (3.3.0, 3.4.0 and the ESP32 have a 0x0a in a payload)")
def test_first_rtnl_record_without_line_feed(captured):
    frame = rtnl.frame(rtnl.log2(1000, 1, rtnl.FUGR_TAG, captured.profile.tag_valid, (0xE0040350AABBCCDD).to_bytes(8, "big")))
    assert b"\n" not in frame
    sse = SseListener(BASE.hostname, BASE.port)
    try:
        time.sleep(0.3)
        s = captured.rtnl(frame, keep_open=True)
        sse.wait_for("rtnl-raw-log2", timeout=3)
        s.close()
    finally:
        sse.close()


def needs(box, limit):
    if not getattr(box.profile, limit):
        pytest.skip(f"{limit} not known for a {box.profile.name}")


@pytest.mark.xfail(strict=True, reason="the server answers a claim with 200; the boxes close the connection after it "
                   "(CC3200 3.4.0, ESP32 v5.233.0), after a 204 they keep it open")
def test_claim_status_the_box_expects(captured):
    needs(captured, "claim_status")
    with captured.keep_alive() as c:
        status, _, _ = c.request("GET", "/v1/claim/0a0bccddee0304e0", headers={"Authorization": profiles.AUTHORIZATION})
    assert status == captured.profile.claim_status


def test_response_headers_fit_the_box(captured):
    """No header longer than the box was seen to take (a 3.4.0 CC3200 dropped a /v1/time answer with a
    776-byte header and stayed offline for that boot)."""
    needs(captured, "header_accepted")
    ruid, _ = put_content(captured)
    auth = {"Authorization": profiles.AUTHORIZATION}
    with captured.keep_alive() as c:
        sizes = {}
        for path in captured.profile.boot:
            c.request("GET", path)
            sizes[path] = c.header_size
        c.request("POST", "/v1/freshness-check", freshness.request([(0xE00403500A000001, 1)]))
        sizes["freshness"] = c.header_size
        c.request("GET", f"/v2/content/{ruid}", headers=auth)
        sizes["content"] = c.header_size
        c.request("GET", f"/v2/content/{ruid}", headers=dict(auth, Range="bytes=5000-"))
        sizes["content 206"] = c.header_size
    assert max(sizes.values()) <= captured.profile.header_accepted, sizes


def test_freshness_answer_fits_the_box(captured):
    """No freshness answer longer than the box was seen to take (a 3.4.0 CC3200 dropped a 1121-byte one)."""
    needs(captured, "freshness_answer_accepted")
    count = max(captured.profile.freshness_batches)
    with captured.keep_alive() as c:
        _, _, answer = c.request("POST", "/v1/freshness-check", freshness.request([(0xE00403500C000001 + i, i) for i in range(count)]))
    assert len(answer) <= captured.profile.freshness_answer_accepted


def test_resume_like_the_box(captured):
    """After an aborted download the box asks for the rest with Range and If-Range (the audio id, decimal), from
    a little before the abort (seen: CC3200 512-byte aligned, ESP32 4096-byte aligned)."""
    needs(captured, "resume")
    ruid, content = put_content(captured, audio_id=0x1A8DECAE)
    headers = {"Authorization": profiles.AUTHORIZATION, "Range": "bytes=5000-", "If-Range": str(0x1A8DECAE)}
    with captured.keep_alive() as c:
        status, h, body = c.request("GET", f"/v2/content/{ruid}", headers=headers)
    assert (status, h.get("Content-Range")) == (206, f"bytes 5000-{len(content) - 1}/{len(content)}")
    assert body == content[5000:]


def test_missing_content_is_404(captured):
    """After a 410 the box shows an error and later downloads the whole file again, so a missing file must be
    a 404 - also for the system slots, which the box fetches from /v1/content without Authorization."""
    needs(captured, "drops_copy_on_410")
    with captured.keep_alive() as c:
        assert c.request("GET", "/v1/content/0000000100000000")[0] == 404
    with captured.keep_alive() as c:
        assert c.request("GET", "/v2/content/0a0b0c0d0e0304e0", headers={"Authorization": profiles.AUTHORIZATION})[0] == 404


@pytest.mark.xfail(strict=True, reason="the server sends no answer to /v1/log; the box closes after a few seconds")
def test_log_is_answered(captured):
    """With RTNL down the box posts to /v1/log and closes if there is no answer (after 2.9 s and 7.7 s)."""
    needs(captured, "log_wait")
    with captured.keep_alive() as c:
        c.sock.settimeout(captured.profile.log_wait)
        status, _, _ = c.request("POST", "/v1/log", b"992 (0)")
    assert status == 200


@pytest.mark.parametrize("behaviour", profiles.STUB_BEHAVIOUR)
def test_hardware_specific_behaviour(box, behaviour):
    if behaviour in box.profile.stubs:
        pytest.skip(f"stub, needs a capture of a {box.profile.name}: {profiles.STUB_BEHAVIOUR[behaviour]}")

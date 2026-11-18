"""
Box certificate check (core.boxCertAuth): certificates issued by TeddyCloud are
trusted, other certificates are pinned per box (toniebox.certPin); a box with
another certificate than its pinned one is refused (only logged without
core.boxCertAuth).

    make test_py TESTS=box_cert_check
"""

import http.client
import json
import os
import subprocess
import time
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.box import Box  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")


def api(method, path, body=None):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=10)
    try:
        conn.request(method, path, body)
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def overlay(box):
    boxes = json.loads(api("GET", "/api/getBoxes")[1])["boxes"]
    return next(b["ID"] for b in boxes if box.mac in b["commonName"].lower())


def cert_status(box):
    return api("GET", f"/api/settings/get/internal.boxCertStatus?overlay={overlay(box)}")[1]


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


@pytest.fixture(scope="module")
def teddycloud_box():
    box = Box("deadbeef0010", SANDBOX, BASE.hostname, HTTPS_API_PORT)
    yield box
    box.close()


def box_with_own_cert(directory, mac):
    """A certificate like an original one: issued by a "Boxine Factory SubCA" TeddyCloud does not know."""
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=Boxine Factory SubCA 13",
            "-keyout", directory / "ca.key", "-out", directory / "ca.pem")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN=b'{mac}'", "-keyout", directory / "box.key", "-out", directory / "box.csr")
    openssl("x509", "-req", "-in", directory / "box.csr", "-CA", directory / "ca.pem", "-CAkey", directory / "ca.key",
            "-CAcreateserial", "-days", "30", "-out", directory / "box.pem")
    box = Box(mac, SANDBOX, BASE.hostname, HTTPS_API_PORT)
    box.cert, box.key = directory / "box.pem", directory / "box.key"
    return box


@pytest.fixture(scope="module")
def original_box(tmp_path_factory):
    box = box_with_own_cert(tmp_path_factory.mktemp("original"), "deadbeef0011")
    yield box
    box.close()


@pytest.fixture(scope="module")
def impostor(tmp_path_factory):
    box = box_with_own_cert(tmp_path_factory.mktemp("impostor"), "deadbeef0011")
    yield box
    box.close()


@pytest.fixture
def without_box_cert_auth():
    assert api("POST", "/api/settings/set/core.boxCertAuth", "false")[0] == 200
    yield
    api("POST", "/api/settings/set/core.boxCertAuth", "true")


def test_teddycloud_certificate_is_trusted(teddycloud_box):
    assert teddycloud_box.request("GET", "/v1/time")[0] == 200
    assert cert_status(teddycloud_box) == "trusted"


def test_original_certificate_is_pinned_on_first_contact(original_box):
    assert original_box.request("GET", "/v1/time")[0] == 200
    assert cert_status(original_box) == "pinned"


def test_other_certificate_of_a_pinned_box_is_refused(teddycloud_box, original_box, impostor):
    original_box.request("GET", "/v1/time")
    assert impostor.request("GET", "/v1/time")[0] == 401
    assert cert_status(impostor) == "mismatch"
    assert original_box.request("GET", "/v1/time")[0] == 200
    assert teddycloud_box.request("GET", "/v1/time")[0] == 200


def test_box_with_teddycloud_certificate_is_pinned_too(tmp_path):
    box = Box("deadbeef0014", SANDBOX, BASE.hostname, HTTPS_API_PORT)
    impostor = box_with_own_cert(tmp_path, "deadbeef0014")
    try:
        assert box.request("GET", "/v1/time")[0] == 200
        assert impostor.request("GET", "/v1/time")[0] == 401
        assert box.request("GET", "/v1/time")[0] == 200
    finally:
        box.close()
        impostor.close()


def test_other_certificate_is_only_logged_without_box_cert_auth(original_box, impostor):
    original_box.request("GET", "/v1/time")
    box_overlay = overlay(original_box)
    assert api("POST", f"/api/settings/set/core.boxCertAuth?overlay={box_overlay}", "false")[0] == 200
    try:
        assert impostor.request("GET", "/v1/time")[0] == 200
    finally:
        api("POST", f"/api/settings/set/core.boxCertAuth?overlay={box_overlay}", "true")


def test_reset_pin_takes_the_next_certificate(original_box, impostor):
    original_box.request("GET", "/v1/time")
    assert api("POST", f"/api/settings/reset/toniebox.certPin?overlay={overlay(impostor)}")[0] == 200
    impostor.request("GET", "/v1/time")
    assert cert_status(impostor) == "pinned"
    original_box.request("GET", "/v1/time")
    assert cert_status(original_box) == "mismatch"


def test_known_box_is_pinned_without_allow_new_box(tmp_path):
    box = box_with_own_cert(tmp_path, "deadbeef0012")
    box.request("GET", "/v1/time")
    assert api("POST", f"/api/settings/reset/toniebox.certPin?overlay={overlay(box)}")[0] == 200
    assert api("POST", "/api/settings/set/core.allowNewBox", "false")[0] == 200
    try:
        assert box.request("GET", "/v1/time")[0] == 200
        assert cert_status(box) == "pinned"
    finally:
        api("POST", "/api/settings/set/core.allowNewBox", "true")
        box.close()


def upload_client_der(box, pem):
    der = subprocess.run(["openssl", "x509", "-in", pem, "-outform", "der"], check=True, capture_output=True).stdout
    boundary = "----boxcert"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"client.der\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + der + f"\r\n--{boundary}--\r\n".encode()
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=10)
    try:
        conn.request("POST", f"/api/uploadCert?overlay={overlay(box)}", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        return conn.getresponse().status
    finally:
        conn.close()


def test_uploaded_client_der_is_the_real_certificate(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "first").mkdir()
    real = box_with_own_cert(tmp_path / "real", "deadbeef0013")
    first = box_with_own_cert(tmp_path / "first", "deadbeef0013")
    try:
        first.request("GET", "/v1/time")
        assert cert_status(first) == "pinned"

        assert upload_client_der(real, real.cert) == 200
        assert real.request("GET", "/v1/time")[0] == 200
        assert cert_status(real) == "pinned"
        assert first.request("GET", "/v1/time")[0] == 401
        assert cert_status(first) == "mismatch"
    finally:
        real.close()
        first.close()


def test_box_state_survives_the_save_of_its_pin(tmp_path):
    box = box_with_own_cert(tmp_path, "deadbeef0015")
    try:
        # File times have a resolution of one second: only a save in a later second than the last
        # load looks like a changed file. The server checks every 250 ms, 0.5 s covers two checks.
        time.sleep(1.1)
        assert box.request("GET", "/v1/time")[0] == 200
        time.sleep(0.5)
        assert cert_status(box) == "pinned"
    finally:
        box.close()


def test_client_der_set_as_a_setting_is_the_real_certificate(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "first").mkdir()
    real = box_with_own_cert(tmp_path / "real", "deadbeef0016")
    first = box_with_own_cert(tmp_path / "first", "deadbeef0016")
    openssl("x509", "-in", real.cert, "-outform", "der", "-out", tmp_path / "client.der")
    try:
        first.request("GET", "/v1/time")
        assert cert_status(first) == "pinned"

        setting = f"/api/settings/set/core.client_cert.file.crt?overlay={overlay(first)}"
        assert api("POST", setting, str(tmp_path / "client.der"))[0] == 200
        assert real.request("GET", "/v1/time")[0] == 200
        assert cert_status(real) == "pinned"
        assert first.request("GET", "/v1/time")[0] == 401
        assert cert_status(first) == "mismatch"
    finally:
        api("POST", f"/api/settings/reset/core.client_cert.file.crt?overlay={overlay(first)}")
        real.close()
        first.close()


def test_removed_box_starts_over(tmp_path):
    (tmp_path / "old").mkdir()
    (tmp_path / "new").mkdir()
    old = box_with_own_cert(tmp_path / "old", "deadbeef0017")
    new = box_with_own_cert(tmp_path / "new", "deadbeef0017")
    try:
        old.request("GET", "/v1/time")
        assert cert_status(old) == "pinned"

        assert api("POST", f"/api/settings/removeOverlay?overlay={overlay(old)}")[0] == 200
        assert new.request("GET", "/v1/time")[0] == 200
        assert cert_status(new) == "pinned"
    finally:
        old.close()
        new.close()


def test_new_box_takes_its_client_der_from_its_cert_dir(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "impostor").mkdir()
    real = box_with_own_cert(tmp_path / "real", "deadbeef0018")
    impostor = box_with_own_cert(tmp_path / "impostor", "deadbeef0018")
    cert_dir = Path(SANDBOX) / "certs" / "client" / "deadbeef0018"
    cert_dir.mkdir(parents=True, exist_ok=True)
    openssl("x509", "-in", real.cert, "-outform", "der", "-out", cert_dir / "client.der")
    try:
        assert impostor.request("GET", "/v1/time")[0] == 401
        assert real.request("GET", "/v1/time")[0] == 200
        assert cert_status(real) == "pinned"
    finally:
        real.close()
        impostor.close()


def test_box_dir_setting_takes_effect(teddycloud_box):
    teddycloud_box.request("GET", "/v1/time")
    box_overlay = overlay(teddycloud_box)
    assert api("POST", f"/api/settings/set/core.contentdir?overlay={box_overlay}", "box0010")[0] == 200
    try:
        contentdir = api("GET", f"/api/settings/get/internal.contentdirfull?overlay={box_overlay}")[1]
        assert contentdir.rstrip("/").endswith("box0010")
    finally:
        api("POST", f"/api/settings/reset/core.contentdir?overlay={box_overlay}")


def test_global_setting_right_after_a_save_is_kept(tmp_path):
    (tmp_path / "box").mkdir()
    (tmp_path / "impostor").mkdir()
    box = box_with_own_cert(tmp_path / "box", "deadbeef0019")
    impostor = box_with_own_cert(tmp_path / "impostor", "deadbeef0019")
    before = api("GET", "/api/settings/get/core.boxCertAuth")[1].strip()
    try:
        # The pin is saved in a later second than the last load; the global setting follows at once.
        time.sleep(1.1)
        assert box.request("GET", "/v1/time")[0] == 200
        assert api("POST", "/api/settings/set/core.boxCertAuth", "false")[0] == 200
        time.sleep(0.5)
        assert api("GET", "/api/settings/get/core.boxCertAuth")[1].strip() == "false"
        assert impostor.request("GET", "/v1/time")[0] == 200
    finally:
        api("POST", "/api/settings/set/core.boxCertAuth", before)
        box.close()
        impostor.close()

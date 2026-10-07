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


def test_other_certificate_is_only_logged_without_box_cert_auth(original_box, impostor, without_box_cert_auth):
    original_box.request("GET", "/v1/time")
    assert impostor.request("GET", "/v1/time")[0] == 200


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

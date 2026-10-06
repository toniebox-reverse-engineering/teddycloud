"""
Certificates uploaded for a box land in its own directory, also right after the box
connected for the first time.

    make test_py TESTS=box_cert_upload
"""

import http.client
import json
import os
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


def request(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=10)
    try:
        conn.request(method, path, body, headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def test_upload_for_a_new_box_goes_to_its_own_directory():
    box = Box("deadbeef0030", SANDBOX, BASE.hostname, HTTPS_API_PORT)
    box.request("GET", "/v1/time")
    box.close()
    boxes = json.loads(request("GET", "/api/getBoxes")[1])["boxes"]
    overlay = next(b["ID"] for b in boxes if "deadbeef0030" in b["commonName"].lower())

    global_client = Path(SANDBOX) / "certs" / "client" / "client.der"
    before = global_client.read_bytes() if global_client.exists() else None

    boundary = "----upload"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"client.der\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + b"\x30\x03\x02\x01\x00" + f"\r\n--{boundary}--\r\n".encode()
    status, _ = request("POST", f"/api/uploadCert?overlay={overlay}", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    assert status == 200

    assert (Path(SANDBOX) / "certs" / "client" / "deadbeef0030" / "client.der").exists()
    assert (global_client.read_bytes() if global_client.exists() else None) == before

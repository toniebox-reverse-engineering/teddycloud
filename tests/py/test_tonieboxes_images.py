#!/usr/bin/env python3
"""
The /cache/ URLs of the box images must work before anyone asked for /api/tonieboxesJson,
e.g. in a web UI that got them before a restart of the server.

Run via: make test_py TESTS=tonieboxes_images
"""

import hashlib
import http.client
import json
import os
from pathlib import Path
from urllib.parse import urlparse

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
IMAGE = "http://127.0.0.1:1/box.png"


def request(method, path, body=None):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=30)
    conn.request(method, path, body)
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status, resp.getheader("Location")


def test_box_image_is_served_after_reload():
    config = Path(os.environ["TC_SANDBOX"]) / "config"
    (config / "tonieboxes.json").write_text(json.dumps([{"id": "03-0099", "name": "Test", "img_src": IMAGE}]))
    assert request("POST", "/api/settings/set/tonie_json.cache_images", "true")[0] == 200
    assert request("GET", "/api/toniesJsonReload")[0] == 200

    cached = "/cache/" + hashlib.sha256(IMAGE.encode()).hexdigest().upper() + ".png"
    # the image cannot be downloaded here, so the server sends the browser to the original
    assert request("GET", cached) == (301, IMAGE)

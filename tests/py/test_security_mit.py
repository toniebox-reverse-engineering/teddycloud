"""Automated web-exposure locks must not deny the certificate-protected box API.

Each case gets its own throwaway server: incidents deliberately persist until restart.
Run with: make test_py TESTS=security_mit
"""

import http.client
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.box import Box  # noqa: E402

LOCK = b"TeddyCloud has been locked to mitigate security risks!"
CASES = ("api_probes", "web_incident", "unprotected_api", "overlay_unprotected_api", "hard_lock", "unknown_box")


def web(method, path, body=None, crawler=False):
    base = urlparse(os.environ["TEDDYCLOUD_BASE_URL"])
    conn = http.client.HTTPConnection(base.hostname, base.port, timeout=10)
    try:
        conn.request(method, path, body, {"User-Agent": "Googlebot" if crawler else "test"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def setting(name, value):
    status, body = web("POST", f"/api/settings/set/{name}", value)
    assert status == 200 and LOCK not in body


def run_case(case):
    base = urlparse(os.environ["TEDDYCLOUD_BASE_URL"])
    box = Box("deadbeef0060", os.environ["TC_SANDBOX"], base.hostname,
              int(os.environ["TEDDYCLOUD_HTTPS_API_PORT"]))
    try:
        setting("core.boxCertAuth", "true")
        setting("security_mit.onBlacklistDomain", "true")
        setting("security_mit.onCrawler", "true")
        setting("security_mit.lockAccess", "true")
        assert box.request("GET", "/v1/time")[0] == 200
        setting("core.allowNewBox", "false")

        if case == "api_probes":
            box.user_agent = "Googlebot"
            # No client certificate: refuse before recording any crawler incident.
            assert box.request("GET", "/v1/time", use_cert=False)[0] == 401
            assert b"true" == web("GET", "/api/settings/get/core.boxCertAuth")[1]
            # An accepted certificate with an unusual UA must not trigger a web lock either.
            assert box.request("GET", "/v1/time")[0] == 200
            assert LOCK not in web("GET", "/api/settings/get/core.boxCertAuth")[1]
            # The exemption does not expose management handlers through the API listener.
            assert box.request("GET", "/api/settings/get/core.boxCertAuth")[0] == 404
        elif case == "web_incident":
            assert LOCK in web("GET", "/api/settings/get/core.boxCertAuth", crawler=True)[1]
            assert LOCK in web("GET", "/api/settings/get/core.boxCertAuth")[1]
            assert box.request("GET", "/v1/time")[0] == 200
            assert box.request("GET", "/v1/time", use_cert=False)[0] == 401
        elif case in ("unprotected_api", "overlay_unprotected_api"):
            overlay = f"?overlay={box.mac}" if case == "overlay_unprotected_api" else ""
            setting(f"core.boxCertAuth{overlay}", "false")
            box.user_agent = "Googlebot"
            assert LOCK in box.request("GET", "/v1/time", use_cert=bool(overlay))[2]
            assert LOCK in web("GET", "/api/settings/get/core.boxCertAuth")[1]
        elif case == "hard_lock":
            # Load a persisted hard lock: setting it through the API alone leaves
            # config_changed true, which deliberately postpones manual locking.
            assert web("GET", "/api/triggerWriteConfig")[0] == 200
            config = Path(os.environ["TC_SANDBOX"]) / "config/config.ini"
            text = config.read_text()
            assert "security_mit.hardLock=false" in text
            config.write_text(text.replace("security_mit.hardLock=false", "security_mit.hardLock=true"))
            web("GET", "/api/triggerReloadConfig")
            assert LOCK in box.request("GET", "/v1/time")[2]
            assert LOCK in web("GET", "/api/settings/get/core.boxCertAuth")[1]
        elif case == "unknown_box":
            unknown = Box("deadbeef0061", os.environ["TC_SANDBOX"], base.hostname,
                          int(os.environ["TEDDYCLOUD_HTTPS_API_PORT"]), user_agent="Googlebot")
            try:
                assert unknown.request("GET", "/v1/time")[0] == 401
                assert LOCK not in web("GET", "/api/settings/get/core.boxCertAuth")[1]
                assert box.request("GET", "/v1/time")[0] == 200
            finally:
                unknown.close()
    finally:
        box.close()


@pytest.mark.parametrize("case", CASES)
def test_security_mit(case):
    root = Path(__file__).resolve().parents[2]
    subprocess.run([str(root / "tests/py/with_server.sh"), "0", "0", "0", "60", "--",
                    sys.executable, str(Path(__file__).resolve()), case], check=True, cwd=root)


if __name__ == "__main__":
    run_case(sys.argv[1])

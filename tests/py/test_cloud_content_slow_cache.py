"""
A downloaded tonie that takes long to go into the cache, as on a slow library drive. Its own file, as its server
needs the test-only TEDDYCLOUD_TEST_CACHE_DELAY_MS (src/content_download.c), set by the Makefile from this line:

# server env: TEDDYCLOUD_TEST_CACHE_DELAY_MS=6000

    make test_py TESTS=cloud_content_slow_cache
"""

import os
import time

import pytest

from test_cloud_content import MB, Tonie, box, cloud, content_requests, download, fresh  # noqa: F401 (fixtures)

pytestmark = pytest.mark.skipif(
    os.environ.get("TEDDYCLOUD_TEST_CACHE_DELAY_MS") != "6000" or not os.environ.get("TC_SANDBOX"),
    reason="needs the server from tests/py/with_server.sh with the env above, run it with make test_py",
)


def test_request_while_the_tonie_is_cached_is_served_at_once(box, cloud):
    """Copying a downloaded tonie into the cache and a library on another drive (USB stick, NAS share) takes as long
    as that drive needs. A box asking meanwhile does not wait for it: it gets the complete .tmp."""
    tonie = Tonie(1 * MB)
    cloud.script = lambda h: cloud.stream(h, tonie.content)
    first = download(box, tonie.ruid)
    time.sleep(0.5)  # the server is done with that request too, caching has begun
    started = time.time()
    r = download(box, tonie.ruid)
    waited = time.time() - started
    not_yet = not tonie.library.exists()
    assert (first.status, first.body == tonie.content) == (200, True)
    assert (r.status, r.body == tonie.content) == (200, True)
    assert not_yet and waited < 3, f"answered after {waited:.1f} s, cached already: {not not_yet}"
    assert tonie.cached() and len(content_requests(cloud, tonie)) == 1

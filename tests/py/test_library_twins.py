"""
Two TAFs with the same audio id and different audio (tonies encoded in the same second) both end
up in the library when their tags are migrated, the second under a name that adds its hash (#574).

    make test_py TESTS=library_twins
"""

import hashlib
import http.client
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import taf  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")

pytestmark = pytest.mark.skipif(not SANDBOX, reason="needs the sandbox from tests/py/with_server.sh")

AUDIO_ID = 0x5F574000


def migrate(ruid, libroot=False):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=10)
    try:
        body = f"ruid={ruid}" + ("&libroot=true" if libroot else "")
        conn.request("POST", "/api/migrateContent2Lib", body, {"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def put_tag(ruid, content):
    """A tag whose TAF lies in its content folder, as the box's download leaves it."""
    path = Path(SANDBOX) / "data" / "content" / "default" / ruid[:8].upper() / ruid[8:].upper()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def source_of(ruid):
    path = Path(SANDBOX) / "data" / "content" / "default" / ruid[:8].upper() / f"{ruid[8:].upper()}.json"
    return json.loads(path.read_text()).get("source")


def sha8(content):
    return hashlib.sha1(content[taf.HEADER_SIZE:]).hexdigest()[:8]


def library():
    return Path(SANDBOX) / "data" / "library"


@pytest.mark.parametrize("libroot", [False, True], ids=["by_audio_id", "library_root"])
def test_two_tafs_with_one_audio_id_both_move_to_the_library(libroot):
    offset = 0x10 if libroot else 0
    first = taf.build(AUDIO_ID + offset, os.urandom(2 * 4096))
    second = taf.build(AUDIO_ID + offset, os.urandom(2 * 4096))
    ruids = (f"0a0b5740{offset:02x}0304e0", f"0a0b5741{offset:02x}0304e0")
    tags = [put_tag(ruid, content) for ruid, content in zip(ruids, (first, second))]
    folder, prefix = (library(), "lib://") if libroot else (library() / "by" / "audioID", "lib://by/audioID/")
    plain = f"{AUDIO_ID + offset}.taf"
    suffixed = f"{AUDIO_ID + offset}-{sha8(second)}.taf"

    assert [migrate(ruid, libroot)[0] for ruid in ruids] == [200, 200]

    assert (folder / plain).read_bytes() == first
    assert (folder / suffixed).read_bytes() == second
    assert [source_of(ruid) for ruid in ruids] == [prefix + plain, prefix + suffixed]
    assert not any(tag.exists() for tag in tags)


def test_a_taf_already_in_the_library_under_its_hash_name_is_not_stored_twice():
    first = taf.build(AUDIO_ID + 1, os.urandom(2 * 4096))
    second = taf.build(AUDIO_ID + 1, os.urandom(2 * 4096))
    ruids = ("0a0b574220304e00", "0a0b574221304e00", "0a0b574222304e00")
    for ruid, content in zip(ruids, (first, second, second)):
        put_tag(ruid, content)

    assert [migrate(ruid)[0] for ruid in ruids] == [200, 200, 200]

    folder = library() / "by" / "audioID"
    assert sorted(p.name for p in folder.glob(f"{AUDIO_ID + 1}*.taf")) == sorted(
        [f"{AUDIO_ID + 1}.taf", f"{AUDIO_ID + 1}-{sha8(second)}.taf"])
    assert source_of(ruids[1]) == source_of(ruids[2]) == f"lib://by/audioID/{AUDIO_ID + 1}-{sha8(second)}.taf"

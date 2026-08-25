#!/usr/bin/env python3
"""
API tests for custom tonies JSON endpoints.

Recommended usage:

1) Fully automated via Makefile (build + start server + run tests + stop server):
   make test_api_custom_json_with_server

2) Against an already running TeddyCloud server:
   make test_api_custom_json
   or:
   TEDDYCLOUD_BASE_URL=http://127.0.0.1:80 python3 tests/test_tonies_custom_json_api.py
"""

import json
import os
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


BASE_URL = os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80").rstrip("/")
KEEP_COUNT = 10
BACKUP_PREFIX = "tonies.custom.json."
BACKUP_SUFFIX = ".bak"


class ToniesCustomJsonTestBase(unittest.TestCase):
    @classmethod
    def wait_for_server(cls, timeout_seconds=12.0):
        deadline = time.time() + timeout_seconds
        last_error = None
        while time.time() < deadline:
            try:
                status, _ = cls.request_text("GET", "/web/")
                if status == 200:
                    return
            except Exception as exc:
                last_error = exc
            time.sleep(0.5)

        raise RuntimeError(
            "TeddyCloud API not reachable at "
            f"{BASE_URL}. Start the server first, e.g.:\n"
            "./bin/teddycloud --config-set "
            "\"core.server.http_port=80,core.server.https_web_port=8443\"\n"
            f"Original error: {last_error!r}"
        )

    @classmethod
    def setUpClass(cls):
        cls.base_url = BASE_URL
        cls.wait_for_server()
        config_dir_raw = cls.get_setting("internal.configdirfull")
        cls.config_dir = Path(config_dir_raw)
        if not cls.config_dir.exists() or not cls.config_dir.is_dir():
            raise RuntimeError(f"Config directory does not exist: {config_dir_raw}")

    def setUp(self):
        self._baseline_array = self.get_custom_json()

    def tearDown(self):
        self.post_custom_json(self._baseline_array)

    @classmethod
    def request_text(cls, method, path, body=None, content_type=None, timeout=10):
        headers = {}
        if content_type is not None:
            headers["Content-Type"] = content_type
        if body is not None:
            headers["Expect"] = ""
            headers["Connection"] = "close"

        req = urllib.request.Request(f"{cls.base_url}{path}", data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.getcode(), response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")

    @classmethod
    def get_setting(cls, name):
        status, body = cls.request_text("GET", f"/api/settings/get/{name}")
        if status != 200:
            raise RuntimeError(f"GET /api/settings/get/{name} returned {status}: {body}")
        return body.strip()

    @classmethod
    def get_custom_json(cls):
        status, body = cls.request_text("GET", "/api/toniesCustomJson")
        if status != 200:
            raise RuntimeError(f"GET /api/toniesCustomJson returned {status}: {body}")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"/api/toniesCustomJson did not return JSON: {body}") from exc

        if not isinstance(parsed, list):
            raise RuntimeError(f"/api/toniesCustomJson returned non-array payload: {parsed}")
        return parsed

    @classmethod
    def upsert_custom_json_raw(cls, payload, timeout=10):
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return cls.request_text("POST", "/api/toniesCustomJsonUpsert", body=raw, content_type="application/json", timeout=timeout)

    @classmethod
    def delete_custom_json_raw(cls, models, timeout=10):
        raw = json.dumps({"models": models}, separators=(",", ":")).encode("utf-8")
        return cls.request_text("POST", "/api/toniesCustomJsonDelete", body=raw, content_type="application/json", timeout=timeout)

    @classmethod
    def rename_custom_json_raw(cls, from_model, to_model, timeout=10):
        raw = json.dumps({"fromModel": from_model, "toModel": to_model}, separators=(",", ":")).encode("utf-8")
        return cls.request_text("POST", "/api/toniesCustomJsonRename", body=raw, content_type="application/json", timeout=timeout)

    @classmethod
    def upsert_custom_json(cls, payload, timeout=10):
        status, body = cls.upsert_custom_json_raw(payload, timeout=timeout)
        if status != 200 or body.strip() != "OK":
            raise RuntimeError(f"POST /api/toniesCustomJsonUpsert failed: status={status}, body={body!r}")

    @classmethod
    def post_custom_json(cls, payload):
        existing = cls.get_custom_json()
        models = [entry.get("model") for entry in existing if isinstance(entry, dict) and entry.get("model")]
        if models:
            status, body = cls.delete_custom_json_raw(models)
            if status != 200 or body.strip() != "OK":
                raise RuntimeError(f"POST /api/toniesCustomJsonDelete failed: status={status}, body={body!r}")

        if payload:
            for i in range(0, len(payload), 80):
                chunk = payload[i : i + 80]
                cls.upsert_custom_json(chunk, timeout=30)

    @staticmethod
    def list_backup_files(config_dir):
        return sorted(
            [
                entry.name
                for entry in config_dir.iterdir()
                if entry.is_file() and entry.name.startswith(BACKUP_PREFIX) and entry.name.endswith(BACKUP_SUFFIX)
            ]
        )

    @staticmethod
    def backup_timestamp(filename):
        return filename[len(BACKUP_PREFIX) : -len(BACKUP_SUFFIX)]

    @classmethod
    def wait_for_fresh_backup_timestamp(cls, previous_backups):
        latest_known = cls.backup_timestamp(max(previous_backups)) if previous_backups else time.strftime("%Y%m%d-%H%M%S")
        while time.strftime("%Y%m%d-%H%M%S") <= latest_known:
            time.sleep(0.05)


class ToniesCustomJsonBackupTests(ToniesCustomJsonTestBase):
    @staticmethod
    def build_payload(i):
        audio_id = 100000 + i
        hash_value = f"{audio_id:040x}"
        return [
            {
                "model": f"TC_TEST_MODEL_{i}",
                "series": "TC_TEST_SERIES",
                "audio_id": [audio_id],
                "hash": [hash_value],
                "title": f"Generated {i}",
                "tracks": [f"Track {i}"],
            }
        ]

    def test_backup_creation_and_rotation(self):
        before = self.list_backup_files(self.config_dir)
        self.assertLessEqual(len(before), KEEP_COUNT)

        iterations = max(4, (KEEP_COUNT - len(before)) + 2)
        for i in range(iterations):
            expected_before = before.copy()
            self.wait_for_fresh_backup_timestamp(expected_before)

            self.upsert_custom_json(self.build_payload(i))
            after = self.list_backup_files(self.config_dir)

            expected_new_count = min(len(expected_before) + 1, KEEP_COUNT)
            self.assertEqual(len(after), expected_new_count, f"Iteration {i}: unexpected backup count")

            added = set(after) - set(expected_before)
            self.assertEqual(len(added), 1, f"Iteration {i}: expected exactly one new backup file")

            if len(expected_before) < KEEP_COUNT:
                removed = set(expected_before) - set(after)
                self.assertFalse(removed, f"Iteration {i}: no backup should be removed before keep limit")
            else:
                removed = set(expected_before) - set(after)
                self.assertEqual(len(removed), 1, f"Iteration {i}: expected exactly one removed backup")
                oldest_before = min(expected_before)
                self.assertIn(oldest_before, removed, f"Iteration {i}: oldest backup should be removed")

            before = after


class ToniesCustomJsonApiTests(ToniesCustomJsonTestBase):
    def test_save_many_entries_and_verify_read_and_search(self):
        entry_count = 150
        base_audio_id = 999000
        payload = []
        for i in range(entry_count):
            audio_id = base_audio_id + i
            payload.append(
                {
                    "model": f"ZZZ_BULK_MODEL_{i:04d}",
                    "series": "ZZZ_BULK_SERIES",
                    "audio_id": [audio_id],
                    "hash": [f"{audio_id:040x}"],
                    "title": f"Bulk Title {i}",
                    "tracks": [f"Track {i}"],
                }
            )

        self.post_custom_json([])
        for i in range(0, len(payload), 80):
            status, body = self.upsert_custom_json_raw(payload[i : i + 80], timeout=30)
            self.assertEqual(status, 200, msg=f"Expected bulk upsert to succeed: {body}")
            self.assertEqual(body.strip(), "OK")

        read_back = self.get_custom_json()
        self.assertEqual(len(read_back), entry_count)
        by_model = {entry.get("model"): entry for entry in read_back}

        for idx in sorted({0, entry_count // 2, entry_count - 1}):
            model = f"ZZZ_BULK_MODEL_{idx:04d}"
            self.assertIn(model, by_model)
            entry = by_model[model]
            self.assertEqual(entry.get("audio_id"), [str(base_audio_id + idx)])
            self.assertEqual(entry.get("series"), "ZZZ_BULK_SERIES")

            status, body = self.request_text("GET", f"/api/toniesJsonSearch?searchModel={model}")
            self.assertEqual(status, 200)
            result = json.loads(body)
            self.assertTrue(any(item.get("model") == model for item in result))

        status, body = self.request_text("GET", "/api/toniesJsonReload")
        self.assertEqual(status, 200)
        self.assertEqual(body.strip(), "OK")

        last_model = f"ZZZ_BULK_MODEL_{entry_count - 1:04d}"
        status, body = self.request_text("GET", f"/api/toniesJsonSearch?searchModel={last_model}")
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertTrue(any(item.get("model") == last_model for item in result))

    def test_save_multiple_entries_and_readback_and_reload(self):
        payload = [
            {
                "model": "CUSTOM_001",
                "series": "Custom Series",
                "audio_id": [123456],
                "hash": ["0123456789abcdef0123456789abcdef01234567"],
                "title": "My Title",
                "tracks": ["A", "B"],
            },
            {
                "model": "CUSTOM_002",
                "series": "Another Series",
                "audio_id": ["654321"],
                "hash": ["89abcdef0123456789abcdef0123456789abcdef"],
                "title": "",
                "tracks": [],
            },
        ]

        self.post_custom_json(payload)
        first_read = self.get_custom_json()
        second_read = self.get_custom_json()

        self.assertEqual(first_read, second_read)
        self.assertEqual(len(first_read), 2)

        by_model = {entry["model"]: entry for entry in first_read}
        self.assertIn("CUSTOM_001", by_model)
        self.assertIn("CUSTOM_002", by_model)

        first = by_model["CUSTOM_001"]
        self.assertEqual(first["audio_id"], ["123456"])
        self.assertEqual(first["hash"], ["0123456789ABCDEF0123456789ABCDEF01234567"])
        self.assertEqual(first["tracks"], ["A", "B"])

        second = by_model["CUSTOM_002"]
        self.assertEqual(second["audio_id"], ["654321"])
        self.assertEqual(second["hash"], ["89ABCDEF0123456789ABCDEF0123456789ABCDEF"])

    def test_validation_blocks_wrong_values(self):
        cases = [
            (
                [{"series": "S", "audio_id": [1], "hash": ["a" * 40]}],
                "'model' is required",
            ),
            (
                {"model": "DUMMY_OK", "audio_id": [1], "hash": ["a" * 40]},
                "'series' is required",
            ),
            (
                [{"model": "DUMMY_OK", "series": "S", "audio_id": [1, 2], "hash": ["a" * 40]}],
                "'audio_id' and 'hash' must have same length",
            ),
            (
                [{"model": "DUMMY_OK", "series": "S", "audio_id": ["not-a-number"], "hash": ["a" * 40]}],
                "'audio_id[0]' must be numeric",
            ),
            (
                [{"model": "DUMMY_OK", "series": "S", "audio_id": [1], "hash": ["abc"]}],
                "'hash[0]' must be 40-char hex",
            ),
            (
                [
                    {"model": "M1", "series": "S", "audio_id": [7], "hash": ["a" * 40]},
                    {"model": "M2", "series": "S", "audio_id": [7], "hash": ["a" * 40]},
                ],
                "Duplicate audio_id+hash pair detected",
            ),
        ]

        for payload, expected in cases:
            with self.subTest(expected=expected, payload=payload):
                before = self.get_custom_json()
                status, body = self.upsert_custom_json_raw(payload)
                self.assertEqual(status, 400, msg=f"Expected validation error, got {status}: {body}")
                self.assertIn(expected, body)
                after = self.get_custom_json()
                self.assertEqual(after, before)

    def test_delete_and_rename_endpoints(self):
        initial_payload = [
            {
                "model": "RM_A",
                "series": "Removal Series",
                "audio_id": [200001],
                "hash": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            },
            {
                "model": "RM_B",
                "series": "Removal Series",
                "audio_id": [200002],
                "hash": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            },
        ]
        self.post_custom_json(initial_payload)

        status, body = self.delete_custom_json_raw(["RM_B"])
        self.assertEqual(status, 200, msg=f"Expected delete to succeed: {body}")
        self.assertEqual(body.strip(), "OK")

        unchanged = self.get_custom_json()
        self.assertEqual(len(unchanged), 1)
        self.assertTrue(any(x.get("model") == "RM_A" for x in unchanged))
        self.assertFalse(any(x.get("model") == "RM_B" for x in unchanged))

        status, body = self.rename_custom_json_raw("RM_A", "RM_A_RENAMED")
        self.assertEqual(status, 200, msg=f"Expected rename to succeed: {body}")
        self.assertEqual(body.strip(), "OK")

        changed = self.get_custom_json()
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0].get("model"), "RM_A_RENAMED")


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
The total audio length of a TAF is reported as tafHeader.lengthSeconds by fileIndexV2.

The TAF is encoded by the server from generated white noise (needs ffmpeg).

Run via: make test_py TESTS=taf_length
"""

import io
import json
import os
import unittest
import wave
from urllib.parse import quote

from test_hardening import Base, request

TRACK_SECONDS = [2, 3]
RATE = 4000  # low rate: the test upload helper only handles small bodies, the server resamples


def white_noise_wav(seconds):
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(1)
        w.setframerate(RATE)
        w.writeframes(os.urandom(RATE * seconds))
    return buf.getvalue()


class TafLength(Base):
    def test_length_seconds(self):
        sources = []
        for i, seconds in enumerate(TRACK_SECONDS):
            name = f"__taflength{i}.wav"
            self.put_library(name, white_noise_wav(seconds))
            sources.append(name)
        status, text = self.encode(sources, "__taflength.taf")
        self.assertEqual(status, 200, text)

        status, text = request("GET", "/api/fileIndexV2?special=library&path=" + quote("/"))
        self.assertEqual(status, 200, text)
        entry = next(f for f in json.loads(text)["files"] if f["name"] == "__taflength.taf")
        header = entry["tafHeader"]

        # the encoder may add a few frames, so allow one second of slack
        self.assertAlmostEqual(header["lengthSeconds"], sum(TRACK_SECONDS), delta=1)
        self.assertEqual(len(header["trackSeconds"]), len(TRACK_SECONDS))
        self.assertLess(header["trackSeconds"][-1], header["lengthSeconds"])


if __name__ == "__main__":
    unittest.main()

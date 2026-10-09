"""Freshness check (proto/toniebox.pb.freshness-check.*.proto) without a protobuf package."""

import struct

from .rtnl import _bytes, _tag


def request(tonies):
    """TonieFreshnessCheckRequest; tonies = [(uid, audio_id)]. 16 bytes per tonie, as the boxes send it."""
    return b"".join(_bytes(1, _tag(1, 1) + struct.pack("<Q", uid) + _tag(2, 5) + struct.pack("<I", audio_id))
                    for uid, audio_id in tonies)


def response_fields(data):
    """Field numbers of a TonieFreshnessCheckResponse, in order (enough to check it decodes)."""
    fields, pos = [], 0
    while pos < len(data):
        key = data[pos]
        pos += 1
        number, wire = key >> 3, key & 7
        if wire == 0:
            while data[pos] & 0x80:
                pos += 1
            pos += 1
        elif wire == 1:
            pos += 8
        else:
            raise ValueError(f"unexpected wire type {wire} at {pos - 1}")
        fields.append(number)
    return fields

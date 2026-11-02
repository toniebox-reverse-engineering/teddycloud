"""Minimal Toniebox audio file (proto/toniebox.pb.taf-header.proto): a 4096-byte header (4-byte big-endian
length + protobuf, padded with field 5) and the audio blocks. The audio need not be Ogg for the
server to serve it."""

import hashlib
import struct

from .rtnl import _bytes, _tag, varint

HEADER_SIZE = 4096


def build(audio_id, audio):
    fields = _bytes(1, hashlib.sha1(audio).digest()) + _tag(2, 0) + varint(len(audio)) + _tag(3, 0) + varint(audio_id)
    fields += _bytes(4, varint(0))
    fill = HEADER_SIZE - 4 - len(fields) - 3  # field 5 tag + 2-byte length
    header = fields + _bytes(5, bytes(fill))
    assert len(header) == HEADER_SIZE - 4
    return struct.pack(">I", len(header)) + header + audio

"""Hand-rolled encoder for the Toniebox RTNL log protocol (proto/toniebox.pb.rtnl.proto),
so the tests need no protobuf package. A frame is a 4-byte big-endian length plus the protobuf."""

import struct

# values from include/handler_rtnl.h
FUGR_FIRMWARE = 8
FUGR_TILT = 12
FUGR_TAG = 15
FUGR_VOLUME = 27
FUNC_TAG_VALID_CC3200 = 8627
FUNC_TAG_INVALID_CC3200 = 8646
FUNC_TAG_VALID_ESP32 = 16065
FUNC_VOLUME_CHANGE_CC3200 = 8672
FUNC_VOLUME_CHANGE_ESP32 = 15524


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _tag(field, wire):
    return varint(field << 3 | wire)


def _bytes(field, data):
    return _tag(field, 2) + varint(len(data)) + data


def log2(uptime, sequence, function_group, function, field6=b"", field3=0, field8=None, field9=None):
    """TonieRtnlRPC{log2}"""
    msg = _tag(1, 1) + struct.pack("<Q", uptime)
    msg += _tag(2, 0) + varint(sequence)
    msg += _tag(3, 0) + varint(field3)
    msg += _tag(4, 0) + varint(function_group)
    msg += _tag(5, 0) + varint(function)
    msg += _bytes(6, field6)
    if field8 is not None:
        msg += _tag(8, 5) + struct.pack("<I", field8)
    if field9 is not None:
        msg += _bytes(9, field9)
    return _bytes(2, msg)


def log3(datetime, field2):
    """TonieRtnlRPC{log3}"""
    return _bytes(3, _tag(1, 5) + struct.pack("<I", datetime) + _tag(2, 0) + varint(field2))


def frame(rpc):
    return struct.pack(">I", len(rpc)) + rpc


# The server reads the start of a connection with CRLF line breaking before it detects the binary
# stream, so the first bytes must contain a CRLF. Ending a frame in field9 = CRLF makes sure of it.
CRLF = b"\r\n"


def tag_placed(uid, valid=True, uptime=1000, sequence=1):
    """UID is the 8 bytes the box reports (big endian as read by the server)"""
    func = FUNC_TAG_VALID_CC3200 if valid else FUNC_TAG_INVALID_CC3200
    return log2(uptime, sequence, FUGR_TAG, func, struct.pack(">Q", uid), field9=CRLF)


def volume_changed(level, db, uptime=1000, sequence=1):
    return log2(uptime, sequence, FUGR_VOLUME, FUNC_VOLUME_CHANGE_CC3200, struct.pack("<III", 0, db & 0xFFFFFFFF, level), field9=CRLF)

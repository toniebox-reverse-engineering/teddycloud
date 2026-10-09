"""Sends a box's captured ClientHello as it is and reads the server's first flight
(ServerHello .. ServerHelloDone), so the tests see what the server picks for the real
box: Python's ssl module cannot reproduce the exact cipher list, groups and signature
algorithms of the CC3200 or ESP32 TLS stack."""

import os
import socket
import struct
from dataclasses import dataclass, field

HELLO_RANDOM = slice(11, 43)  # record header (5) + handshake header (4) + version (2)


@dataclass
class ServerFlight:
    version: int = 0
    cipher: int = 0
    session_id: bytes = b""
    extensions: list = field(default_factory=list)  # extension types in the ServerHello
    certificates: int = 0
    ske_curve: int = 0  # ECDHE named group of the ServerKeyExchange
    ske_sigalg: int = 0  # signature algorithm of the ServerKeyExchange
    cert_request_sigalgs: list = field(default_factory=list)  # None if no client certificate is requested
    alert: tuple = None  # (level, description) if the server refused


def client_hello(captured_hex):
    """The captured record (random zeroed) with a fresh random."""
    hello = bytearray.fromhex(captured_hex)
    hello[HELLO_RANDOM] = os.urandom(32)
    return bytes(hello)


def server_flight(host, port, captured_hex, timeout=5):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(client_hello(captured_hex))
        flight = ServerFlight(cert_request_sigalgs=None)
        handshake = b""
        while True:
            header = _read(s, 5)
            content_type, length = header[0], struct.unpack(">H", header[3:5])[0]
            body = _read(s, length)
            if content_type == 21:
                flight.alert = (body[0], body[1])
                return flight
            if content_type != 22:
                raise AssertionError(f"unexpected record type {content_type} before ServerHelloDone")
            handshake += body
            while len(handshake) >= 4:
                msg_len = int.from_bytes(handshake[1:4], "big")
                if len(handshake) < 4 + msg_len:
                    break
                msg_type, msg = handshake[0], handshake[4:4 + msg_len]
                handshake = handshake[4 + msg_len:]
                if msg_type == 14:
                    return flight
                _parse(flight, msg_type, msg)


def _read(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise AssertionError("connection closed during the handshake")
        data += chunk
    return data


def _parse(flight, msg_type, msg):
    if msg_type == 2:  # ServerHello
        flight.version = struct.unpack(">H", msg[0:2])[0]
        sid_len = msg[34]
        flight.session_id = msg[35:35 + sid_len]
        pos = 35 + sid_len
        flight.cipher = struct.unpack(">H", msg[pos:pos + 2])[0]
        pos += 3  # cipher + compression
        if pos < len(msg):
            end = pos + 2 + struct.unpack(">H", msg[pos:pos + 2])[0]
            pos += 2
            while pos < end:
                ext_type, ext_len = struct.unpack(">HH", msg[pos:pos + 4])
                flight.extensions.append(ext_type)
                pos += 4 + ext_len
    elif msg_type == 11:  # Certificate
        pos, end = 3, 3 + int.from_bytes(msg[0:3], "big")
        while pos < end:
            pos += 3 + int.from_bytes(msg[pos:pos + 3], "big")
            flight.certificates += 1
    elif msg_type == 12 and msg[0] == 3:  # ServerKeyExchange, named curve
        flight.ske_curve = struct.unpack(">H", msg[1:3])[0]
        pos = 4 + msg[3]
        flight.ske_sigalg = struct.unpack(">H", msg[pos:pos + 2])[0]
    elif msg_type == 13:  # CertificateRequest
        pos = 1 + msg[0]
        n = struct.unpack(">H", msg[pos:pos + 2])[0]
        flight.cert_request_sigalgs = [struct.unpack(">H", msg[pos + 2 + i:pos + 4 + i])[0] for i in range(0, n, 2)]


def offers(captured_hex):
    """Extension types, signature algorithms and groups the ClientHello offers."""
    hello = bytes.fromhex(captured_hex)[9:]  # after the record and handshake headers
    pos = 34 + 1 + hello[34]  # version, random, session id
    pos += 2 + struct.unpack(">H", hello[pos:pos + 2])[0]  # cipher suites
    pos += 1 + hello[pos]  # compression methods
    end = pos + 2 + struct.unpack(">H", hello[pos:pos + 2])[0]
    pos += 2
    found = {"extensions": [], "sigalgs": [], "groups": []}
    while pos < end:
        ext_type, ext_len = struct.unpack(">HH", hello[pos:pos + 4])
        data = hello[pos + 6:pos + 4 + ext_len]
        found["extensions"].append(ext_type)
        if ext_type in (10, 13):  # supported_groups, signature_algorithms
            found["groups" if ext_type == 10 else "sigalgs"] = [struct.unpack(">H", data[i:i + 2])[0] for i in range(0, len(data), 2)]
        pos += 4 + ext_len
    return found

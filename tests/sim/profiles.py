"""Hardware profiles of the Toniebox generations.

CC3200 and ESP32 are filled in from captures of real boxes on their original firmware
(CC3200 3.1.0 BF2, 3.3.0, 3.4.0; ESP32 v5.233.0), decrypted with the server's
core.sslkeylogfile. CC3235 and TB2 only have what is derivable from the server code (user
agent detection in server.c, RTNL function codes in include/handler_rtnl.h); what needs a
capture is a stub: `stubs` names it, the tests skip with that reason.
"""

from dataclasses import dataclass, field

from . import rtnl, rtnl_captured

# include/settings.h
BOX_CC3200, BOX_CC3235, BOX_ESP32, BOX_TB2 = 1, 2, 3, 4
GENERATION_TB1, GENERATION_TB2 = 1, 2

STUB_BEHAVIOUR = {
    "ota": "OTA check/download (/v1/ota, /v3/ota) as the real firmware sends it",
    "content": "content download incl. headers/ranges of the real firmware",
    "freshness": "freshness check request/response of the real firmware",
    "rtnl_stream": "real RTNL stream: function codes, ordering, framing, what the hardware sends at boot",
    "client_cert": "the box's original client certificate (Boxine CA chain, key type/size, extensions) instead of a generated one; CC3200 vs. CC3235 vs. ESP32 differ",
    "tls": "TLS behaviour of the real stack: cipher suites, SNI use, session resumption, renegotiation",
}

# signature algorithms (TLS SignatureScheme)
RSA_PKCS1_SHA1, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384 = 0x0201, 0x0401, 0x0501


@dataclass(frozen=True)
class TlsProfile:
    """How the box's TLS stack connects.

    client_hello is the captured ClientHello record (random zeroed), sent as it is by
    tests/sim/tls_hello.py. Python's ssl module cannot send it, so max/min_version, ciphers and
    sni only approximate it for the HTTP tests, and `openssl` holds s_client arguments for a full
    handshake with the box's signature algorithms (OpenSSL 3 has no RC4)."""

    max_version: str = "TLSv1_2"  # attribute names of ssl.TLSVersion
    min_version: str = "TLSv1_2"
    ciphers: str = ""  # OpenSSL cipher string, "" = Python default
    sni: str = ""  # server_hostname, "" = none (the boxes send none; the server then picks the TB1 cert)
    client_hello: str = ""
    cipher: int = 0  # suite TeddyCloud picks for client_hello (the same in the capture)
    cert_verify: int = 0  # signature algorithm of the box's CertificateVerify
    openssl: tuple = ()


# 3.1.0 BF2, 3.3.0 and 3.4.0 send the same hello:
# TLS 1.2 only; ECDHE-RSA-AES256-SHA, ECDHE-RSA-RC4-SHA, DHE-RSA-AES256-SHA, AES256-SHA, RC4-SHA, RC4-MD5,
# AES128-SHA256, AES256-SHA256, ECDHE-RSA-AES128-SHA256, ECDHE-ECDSA-AES128-SHA256; only the extensions
# signature_algorithms (SHA-1 and SHA-256) and supported_groups (secp160r1 .. secp521r1); no SNI, no
# session ticket, no renegotiation_info, no extended master secret. Signs its CertificateVerify with
# RSA/SHA-1 and does not resume sessions (session_id always empty, also when the server offers one).
CC3200_HELLO = (
    "16030300630100005f0303" + "00" * 32 + "000014c014c0110039003500050004003c003dc027c02301000022"
    "000d000c000a02010202020304010403000a000e000c001000130015001700180019"
)
# what the CC3200 offers and OpenSSL 3 still has, in the box's order
CC3200_SUITES = "ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:ECDHE-RSA-AES128-SHA256"

# TLS 1.2, 72 suites (GCM, CCM, CBC, ARIA, Camellia), groups x25519, secp256/384/521r1,
# brainpool; signature algorithms SHA-512/384/256 (no SHA-1); ec_point_formats, encrypt_then_mac,
# extended_master_secret, session_ticket (empty); no SNI (the Host header has the name).
# Signs its CertificateVerify with RSA/SHA-384.
ESP32_HELLO = (
    "16030300f7010000f30303" + "00" * 32 + "000092c02cc030009fc0adc09fc024c028006bc00ac0140039c0afc0a3c05dc061c053c049"
    "c04dc045c02bc02f009ec0acc09ec023c0270067c009c0130033c0aec0a2c05cc060c052c048c04cc044009dc09d003d0035"
    "c032c02ac00fc02ec026c005c0a1c05fc063c051c04bc04fc03d009cc09c003c002fc031c029c00ec02dc025c004c0a0c05e"
    "c062c050c04ac04ec03c00ff01000038000a0010000e001d001700180019001a001b001c000d000e000c0603060105030501"
    "04030401000b00020100001600000017000000230000"
)

LEGACY_RSA_CBC = CC3200_SUITES + ":@SECLEVEL=0"


@dataclass(frozen=True)
class BoxProfile:
    name: str
    mac: str  # unique per profile, becomes the overlay CN
    user_agent: str
    box_ic: int  # expected result of the server's UA detection
    generation: int
    # RTNL function codes known for this hardware (log2 function_group/function)
    tag_valid: int = rtnl.FUNC_TAG_VALID_CC3200
    tag_invalid: int = rtnl.FUNC_TAG_INVALID_CC3200
    volume_change: int = rtnl.FUNC_VOLUME_CHANGE_CC3200
    tls: TlsProfile = field(default_factory=TlsProfile)
    # HTTP as the firmware sends it: keep-alive, headers Host and User-Agent (+ extra_headers), Content-Length
    # only with a body, the body in its own TLS record
    extra_headers: tuple = ()  # (name, value); "{mac}" is replaced
    boot: tuple = ()  # GET requests after power on, in order, before the freshness check
    freshness_batches: tuple = ()  # tonies per POST /v1/freshness-check
    rtnl_records: str = ""  # how the RTNL stream is cut into TLS records: "split" or "batched", see tests
    rtnl_log2: tuple = ()  # frame shapes the box sends, see rtnl_captured.py
    rtnl_log3: tuple = ()
    endings: tuple = ()  # how the box ends a connection: "close_notify" (then FIN) and/or "fin" (FIN only)
    # seen by giving a real box wrong answers (0/False = not known)
    claim_status: int = 0  # keeps the connection open after it; after a 200 the box closes it
    header_accepted: int = 0  # largest response header (bytes) the box took; it dropped a 776-byte one
    freshness_answer_accepted: int = 0  # largest freshness answer (bytes) it took; it dropped a 1121-byte one
    resume: bool = False  # continues an aborted download with Range: bytes=N- and If-Range: <audio id>
    drops_copy_on_410: bool = False  # after a 410: error (red), next time a full download
    log_wait: float = 0  # shortest time (s) the box waited for the answer to POST /v1/log before closing
    stubs: tuple = field(default_factory=lambda: tuple(STUB_BEHAVIOUR))
    note: str = ""


# "BD " + 64 zeros on /v1/claim and /v2/content (both boxes)
AUTHORIZATION = "BD " + "0" * 64

CC3200 = BoxProfile(
    "cc3200", "c32000000001", "TB/1779199517 SP/34471936 HW/1048889", BOX_CC3200, GENERATION_TB1,
    tls=TlsProfile(ciphers=LEGACY_RSA_CBC, client_hello=CC3200_HELLO, cipher=0xC014, cert_verify=RSA_PKCS1_SHA1,
                   openssl=("-tls1_2", "-no_ticket", "-cipher", LEGACY_RSA_CBC,
                            "-sigalgs", "RSA+SHA1:DSA+SHA1:ECDSA+SHA1:RSA+SHA256:ECDSA+SHA256",
                            "-client_sigalgs", "RSA+SHA1", "-curves", "P-256:P-384:P-521")),
    # cv = the version the box has: /4 the SP/ value of the user agent, /3 the TB/ value (3.4.0)
    boot=("/v1/time", "/v1/ota/4?cv=34471936", "/v1/ota/5?cv=1669853893", "/v1/ota/2?cv=1622104430",
          "/v1/ota/6?cv=1534781997", "/v1/ota/3?cv=1779199517"),
    freshness_batches=(32,),  # all its tonies in one request (28 and 32 seen)
    rtnl_records="split",
    rtnl_log2=rtnl_captured.CC3200_LOG2,
    rtnl_log3=rtnl_captured.CC3200_LOG3,
    endings=("close_notify", "fin"),
    claim_status=204,
    header_accepted=351,
    freshness_answer_accepted=305,
    resume=True,
    drops_copy_on_410=True,
    log_wait=2.9,
    stubs=("client_cert",),
    note="UA: TB/%firmware-ts% SP/%sp% HW/%hw% (3.1.0 BF2 TB/1620325289, 3.3.0 TB/1777468756, 3.4.0 TB/1779199517). "
         "/v2/content without Range on the boot or a new connection, claim after it. RTNL on its own connection, "
         "box to server only, frames cut into TLS records anywhere (also within the length header). Wrong answers "
         "given to a 3.4.0 box: /v1/time \"teddycloud\": red blinking, off; OTA 404 skips that id, a dropped OTA "
         "connection the rest of the round; system slots are fetched from /v1/content without Authorization; with "
         "RTNL down it posts /v1/log (\"992 (0)\") and closes after 2.9 s or 7.7 s without an answer",
)
CC3235 = BoxProfile(
    "cc3235", "c32350000001", "TB/1691743093 SP/34471936 HW/1200000", BOX_CC3235, GENERATION_TB1,
    note="same UA format as the CC3200, told apart by HW/ > 1100000 (#483). Function codes copied from the "
         "CC3200 until a capture shows differences",
)
ESP32_OLD_UA = BoxProfile(
    "esp32-old-ua", "e32000000001", "red TB/1691743093", BOX_ESP32, GENERATION_TB1,
    tag_valid=rtnl.FUNC_TAG_VALID_ESP32, tag_invalid=15452, volume_change=rtnl.FUNC_VOLUME_CHANGE_ESP32,
    note="UA: %box-color% TB/%firmware-ts%",
)
ESP32 = BoxProfile(
    "esp32", "e32000000002", "toniebox-esp32-eu/v5.233.0", BOX_ESP32, GENERATION_TB1,
    tag_valid=rtnl.FUNC_TAG_VALID_ESP32, tag_invalid=15452, volume_change=rtnl.FUNC_VOLUME_CHANGE_ESP32,
    tls=TlsProfile(ciphers="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384",
                   client_hello=ESP32_HELLO, cipher=0xC030, cert_verify=RSA_PKCS1_SHA384,
                   openssl=("-tls1_2", "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
                            "-sigalgs", "ECDSA+SHA512:RSA+SHA512:ECDSA+SHA384:RSA+SHA384:ECDSA+SHA256:RSA+SHA256",
                            "-client_sigalgs", "RSA+SHA384", "-curves", "X25519:P-256:P-384:P-521")),
    extra_headers=(("X-Toniebox", "{mac}"),),
    # no /v1/time and no /v1/ota/4; /2 is the "pd" app, /3 the "eu" app (file names of Boxine's answers)
    boot=("/v1/ota/5?cv=1669853893", "/v1/ota/2?cv=1715951265", "/v1/ota/6?cv=1534781997", "/v1/ota/3?cv=1715951512"),
    freshness_batches=(60, 18),
    rtnl_records="batched",
    rtnl_log2=rtnl_captured.ESP32_LOG2,
    rtnl_log3=rtnl_captured.ESP32_LOG3,
    endings=("fin",),
    claim_status=204,
    resume=True,
    drops_copy_on_410=True,
    stubs=("client_cert",),
    note="UA: toniebox-esp32-<region>/v<version>. Freshness check for 78 tonies as 60 + 18, repeated later on the "
         "same connection. Closes connections with a plain FIN, no close_notify. "
         "/v2/content without Range on its own connection, claim after it there and once more on a new "
         "connection. RTNL on its own connection, box to server only, several whole frames per TLS record; "
         "other function codes than the CC3200 (firmware infos 16928/19258). Wrong answers given to a v5.233.0 box: "
         "OTA 404 and a dropped OTA connection: it goes on with the next id (on the same or a new connection); a "
         "1220-byte freshness answer: no close; content 404 plays the local copy, 410: red blinking, next time a full download; with RTNL down it "
         "retries after ~3 s and posts /v1/log (\"800 (0)\")",
)
# TB2 is detected by "TB2/" (BOX_TB2, generation TB2) but it uses EC client certificates from the
# server_tb2 CA and another server certificate chain; not simulated yet (see Box).
TB2 = BoxProfile(
    "tb2", "7b2000000001", "TB2/1.0.22-92f57d4", BOX_TB2, GENERATION_TB2,
    note="TLS with the TB2 CA + EC client certificate not simulated yet",
)

TB1_PROFILES = [CC3200, CC3235, ESP32_OLD_UA, ESP32]
ALL_PROFILES = TB1_PROFILES + [TB2]
CAPTURED_PROFILES = [CC3200, ESP32]

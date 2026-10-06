"""Hardware profiles of the Toniebox generations.

Only what is derivable from the server code is filled in (user agent detection in
server.c, RTNL function codes in include/handler_rtnl.h). The boxes differ in more than
that (hardware, firmware, TLS stack, OTA/content/freshness behaviour), so everything that
needs a real capture is a stub: `stubs` names it, the tests skip with that reason.
Fill the stubs in once pcaps of the respective box are available (see tmp/test-plan.md, step 6).
"""

from dataclasses import dataclass, field

from . import rtnl

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


@dataclass(frozen=True)
class TlsProfile:
    """How the box's TLS stack connects. All values are ASSUMPTIONS until a capture confirms them
    (the CC3200 is known to need legacy TLS, the exact suites are not)."""

    max_version: str = "TLSv1_2"  # attribute names of ssl.TLSVersion
    min_version: str = "TLSv1_2"
    ciphers: str = ""  # OpenSSL cipher string, "" = Python default
    sni: str = ""  # server_hostname, "" = none (a box on TB1 sends none; the server then picks the TB1 cert)


# RSA key exchange + CBC, no forward secrecy; needs SECLEVEL=0 on a modern OpenSSL
LEGACY_RSA_CBC = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:@SECLEVEL=0"


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
    stubs: tuple = field(default_factory=lambda: tuple(STUB_BEHAVIOUR))
    note: str = ""


# fw/sp/hw numbers are synthetic; the server only classifies by the HW/ value (> 1100000 = CC3235)
CC3200 = BoxProfile(
    "cc3200", "c32000000001", "TB/1691743093 SP/34471936 HW/1000000", BOX_CC3200, GENERATION_TB1,
    tls=TlsProfile(min_version="TLSv1", ciphers=LEGACY_RSA_CBC),
    note="UA: TB/%firmware-ts% SP/%sp% HW/%hw%; needs legacy TLS (assumed: RSA key exchange, AES-CBC, TLS 1.0-1.2)",
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
    "esp32", "e32000000002", "toniebox-esp32-eu/v5.226.0", BOX_ESP32, GENERATION_TB1,
    tag_valid=rtnl.FUNC_TAG_VALID_ESP32, tag_invalid=15452, volume_change=rtnl.FUNC_VOLUME_CHANGE_ESP32,
    note="UA: toniebox-esp32-<region>/v<version>",
)
# TB2 is detected by "TB2/" (BOX_TB2, generation TB2) but it uses EC client certificates from the
# server_tb2 CA and another server certificate chain; not simulated yet (see Box).
TB2 = BoxProfile(
    "tb2", "7b2000000001", "TB2/1.0.22-92f57d4", BOX_TB2, GENERATION_TB2,
    note="TLS with the TB2 CA + EC client certificate not simulated yet",
)

TB1_PROFILES = [CC3200, CC3235, ESP32_OLD_UA, ESP32]
ALL_PROFILES = TB1_PROFILES + [TB2]

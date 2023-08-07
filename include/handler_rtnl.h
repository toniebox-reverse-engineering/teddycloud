#ifndef _HANDLER_RTNL_H
#define _HANDLER_RTNL_H

#include "debug.h"

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

#include "handler.h"
#include "proto/toniebox.pb.rtnl.pb-c.h"

typedef enum
{
    RTNL2_FUGR_NETWORK_HTTP = 6,
    RTNL2_FUGR_FIRMWARE = 8,
    RTNL2_FUGR_TILT = 12,
    RTNL2_FUGR_TAG = 15,
    RTNL2_FUGR_AUDIO = 22,
    RTNL2_FUGR_VOLUME = 27,
    RTNL2_FUGR_NETWORK_TCP = 37,
} rtnl_log2_function_group;

typedef enum
{
    RTNL2_FUNC_NETWORK_HTTP_PATH = 110,
    RTNL2_FUNC_FIRMWARE_NAME = 703,
    RTNL2_FUNC_FIRMWARE_VERSION = 704,
    RTNL2_FUNC_NETWORK_HTTP_OTA_LONG = 785, // TODO some other values?
    RTNL2_FUNC_NETWORK_HTTP_OTA = 791,
    RTNL2_FUNC_NETWORK_HTTP_FIRMWARE_PATH = 806,
    RTNL2_FUNC_NETWORK_URL = 1009,
    RTNL2_FUNC_AUDIO_1 = 6212, // TODO, content path like audio_play
    RTNL2_FUNC_AUDIO_PLAY = 6480,
    RTNL2_FUNC_TAG_VALID_CC3200 = 8627,
    RTNL2_FUNC_TAG_INVALID_CC3200 = 8646,
    RTNL2_FUNC_VOLUME_CHANGE = 8672, // CC3200?
    RTNL2_FUNC_VOLUME_CHANGE_ESP32 = 15524,
    RTNL2_FUNC_TILT_A_ESP32 = 15426, //?
    RTNL2_FUNC_TILT_B_ESP32 = 15427, //?
    RTNL2_FUNC_TAG_INVALID_ESP32 = 15452,
    RTNL2_FUNC_TAG_VALID_ESP32 = 16065,
} rtnl_log2_function;

typedef enum
{
    RTNL3_TYPE_EAR_BIG = 1,
    RTNL3_TYPE_EAR_SMALL = 2,
    RTNL3_TYPE_KNOCK_FORWARD = 3,
    RTNL3_TYPE_KNOCK_BACKWARD = 4,
    RTNL3_TYPE_TILT_FORWARD = 5,
    RTNL3_TYPE_TILT_BACKWARD = 6,
    RTNL3_TYPE_CHARGER_ON = 7,
    RTNL3_TYPE_CHARGER_OFF = 8,
    RTNL3_TYPE_PLAYBACK_STARTING = 11,
    RTNL3_TYPE_PLAYBACK_STARTED = 12,
    RTNL3_TYPE_PLAYBACK_STOPPED = 13,
} rtnl_log3_type;

error_t handleRtnl(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *ctx);
void rtnlEvent(HttpConnection *connection, TonieRtnlRPC *rpc);
void rtnlEventLog(HttpConnection *connection, TonieRtnlRPC *rpc);
void rtnlEventDump(HttpConnection *connection, TonieRtnlRPC *rpc, settings_t *settings);

#endif
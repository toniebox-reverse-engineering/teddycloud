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
    RTNL_FUGR_NETWORK_HTTP = 6,
    RTNL_FUGR_FIRMWARE = 8,
    RTNL_FUGR_AUDIO = 22,
    RTNL_FUGR_VOLUME = 27,
    RTNL_FUGR_NETWORK_TCP = 37,
} rtnl_function_group;

typedef enum
{
    RTNL_FUNC_NETWORK_HTTP_PATH = 110,
    RTNL_FUNC_FIRMWARE_NAME = 703,
    RTNL_FUNC_FIRMWARE_VERSION = 704,
    RTNL_FUNC_NETWORK_HTTP_OTA_LONG = 785, // TODO some other values?
    RTNL_FUNC_NETWORK_HTTP_OTA = 791,
    RTNL_FUNC_NETWORK_HTTP_FIRMWARE_PATH = 806,
    RTNL_FUNC_NETWORK_URL = 1009,
    RTNL_FUNC_AUDIO_1 = 6212, // TODO, content path like audio_play
    RTNL_FUNC_AUDIO_PLAY = 6480,
    RTNL_FUNC_VOLUME_CHANGE = 8672,
} rtnl_function;

error_t handleRtnl(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *ctx);
void rtnlEvent(HttpConnection *connection, TonieRtnlRPC *rpc);
void rtnlEventLog(HttpConnection *connection, TonieRtnlRPC *rpc);
void rtnlEventDump(HttpConnection *connection, TonieRtnlRPC *rpc, settings_t *settings);

#endif
#ifndef _HANDLER_SSE_H
#define _HANDLER_SSE_H

#include "debug.h"

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

#define SSE_MAX_CHANNELS 16
#define SSE_TIMEOUT_S 60
#define SSE_BASE_URL "/api/sse/con/"
typedef struct
{
    HttpConnection *connection;
    time_t lastConnection;
} SseSubscriptionContext;

error_t sse_sendEvent(const char *eventname, const char *content, bool escapeData);
error_t sse_keepAlive(void);

#endif
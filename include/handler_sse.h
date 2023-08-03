#ifndef _HANDLER_SSE_H
#define _HANDLER_SSE_H

#include "debug.h"

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

#include "handler.h"

#define SSE_MAX_CHANNELS 16
#define SSE_TIMEOUT_S 60
#define SSE_KEEPALIVE_S 15

typedef struct
{
    bool active;
    error_t error;
    HttpConnection *connection;
    time_t lastConnection;
    uint8_t channel;
} SseSubscriptionContext;

error_t handleApiSse(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *ctx);
void sse_init();
error_t sse_sendEvent(const char *eventname, const char *content, bool escapeData);
error_t sse_startEventRaw(const char *eventname);
error_t sse_rawData(const char *content);
error_t sse_endEventRaw(void);
error_t sse_keepAlive(void);

#endif
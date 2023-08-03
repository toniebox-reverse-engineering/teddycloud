
#ifdef WIN32
#else
#include <unistd.h>
#endif

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "handler.h"
#include "handler_reverse.h"
#include "settings.h"
#include "stats.h"
#include "cloud_request.h"
#include "os_port.h"
#include "http/http_client.h"

static void cbrCloudResponsePassthrough(void *src_ctx, HttpClientContext *cloud_ctx);
static void cbrCloudHeaderPassthrough(void *src_ctx, HttpClientContext *cloud_ctx, const char *header, const char *value);
static void cbrCloudBodyPassthrough(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error);
static void cbrCloudServerDiscoPassthrough(void *src_ctx, HttpClientContext *cloud_ctx);

static void cbrCloudResponsePassthrough(void *src_ctx, HttpClientContext *cloud_ctx)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    char line[128];

    // This is fine: https://www.youtube.com/watch?v=0oBx7Jg4m-o
    osSprintf(line, "HTTP/%u.%u %u This is fine\r\n", MSB(cloud_ctx->version), LSB(cloud_ctx->version), cloud_ctx->statusCode);
    httpSend(ctx->connection, line, osStrlen(line), HTTP_FLAG_DELAY);
    ctx->status = PROX_STATUS_CONN;
}

static void cbrCloudHeaderPassthrough(void *src_ctx, HttpClientContext *cloud_ctx, const char *header, const char *value)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    char line[128];

    if (header)
    {
        TRACE_INFO(">> httpServerHeaderCbr: %s = %s\r\n", header, value);
        osSprintf(line, "%s: %s\r\n", header, value);
    }
    else
    {
        TRACE_INFO(">> httpServerHeaderCbr: NULL\r\n");
        osStrcpy(line, "\r\n");
    }

    httpSend(ctx->connection, line, osStrlen(line), HTTP_FLAG_DELAY);
    ctx->status = PROX_STATUS_HEAD;
}

static void cbrCloudBodyPassthrough(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    // TRACE_INFO(">> httpServerBodyCbr: %lu received\r\n", length);
    httpSend(ctx->connection, payload, length, HTTP_FLAG_DELAY);
    ctx->status = PROX_STATUS_BODY;
}

static void cbrCloudServerDiscoPassthrough(void *src_ctx, HttpClientContext *cloud_ctx)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    TRACE_INFO(">> httpServerDiscCbr\r\n");
    httpFlushStream(ctx->connection);
    ctx->status = PROX_STATUS_DONE;
}

error_t handleReverse(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    cbr_ctx_t cbr_ctx = {
        .status = PROX_STATUS_IDLE,
        .connection = connection,
        .client_ctx = client_ctx};

    req_cbr_t cbr = {
        .ctx = &cbr_ctx,
        .response = &cbrCloudResponsePassthrough,
        .header = &cbrCloudHeaderPassthrough,
        .body = &cbrCloudBodyPassthrough,
        .disconnect = &cbrCloudServerDiscoPassthrough};

    stats_update("reverse_requests", 1);

    /* here call cloud request, which has to get extended for cbr for header fields and content packets */
    uint8_t *token = connection->private.authentication_token;

    // TODO POST
    error_t error = cloud_request_get(NULL, 0, &uri[8], queryString, token, &cbr);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("cloud_request_get() failed\r\n");
        return error;
    }

    TRACE_INFO("httpServerRequestCallback: (waiting)\r\n");
    while (cbr_ctx.status != PROX_STATUS_DONE)
    {
        osDelayTask(50);
    }
    error = httpFlushStream(connection);

    TRACE_INFO("httpServerRequestCallback: (done)\r\n");
    return error;
}

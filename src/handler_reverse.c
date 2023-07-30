
#ifdef WIN32
#else
#include <unistd.h>
#endif

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "handler_reverse.h"
#include "settings.h"
#include "stats.h"
#include "cloud_request.h"
#include "os_port.h"

typedef struct
{
    uint32_t status;
    HttpConnection *connection;
} cbr_ctx_t;

static void cbrCloudResponsePassthrough(void *src_ctx, void *cloud_ctx);
static void cbrCloudHeaderPassthrough(void *src_ctx, void *cloud_ctx, const char *header, const char *value);
static void cbrCloudBodyPassthrough(void *src_ctx, void *cloud_ctx, const char *payload, size_t length, error_t error);
static void cbrCloudServerDiscoPassthrough(void *src_ctx, void *cloud_ctx);

static void cbrCloudResponsePassthrough(void *src_ctx, void *cloud_ctx)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    char line[128];

    osSprintf(line, "HTTP/%u.%u %u This is fine\r\n", MSB(ctx->connection->response.version), LSB(ctx->connection->response.version), ctx->connection->response.statusCode);
    httpSend(ctx->connection, line, osStrlen(line), HTTP_FLAG_DELAY);
    ctx->status = PROX_STATUS_CONN;
}

static void cbrCloudHeaderPassthrough(void *src_ctx, void *cloud_ctx, const char *header, const char *value)
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

static void cbrCloudBodyPassthrough(void *src_ctx, void *cloud_ctx, const char *payload, size_t length, error_t error)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    // TRACE_INFO(">> httpServerBodyCbr: %lu received\r\n", length);
    httpSend(ctx->connection, payload, length, HTTP_FLAG_DELAY);
    ctx->status = PROX_STATUS_BODY;
}

static void cbrCloudServerDiscoPassthrough(void *src_ctx, void *cloud_ctx)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    TRACE_INFO(">> httpServerDiscCbr\r\n");
    ctx->status = PROX_STATUS_DONE;
}

error_t handleReverse(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t ctx)
{
    cbr_ctx_t cbr_ctx = {
        .status = PROX_STATUS_IDLE,
        .connection = connection};

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
    error = httpCloseStream(connection);

    TRACE_INFO("httpServerRequestCallback: (done)\r\n");
    return error;
}


#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "handler_reverse.h"
#include "settings.h"
#include "cloud_request.h"

typedef struct
{
    uint32_t status;
    HttpConnection *connection;
} cbr_ctx_t;

static void cbrCloudResponsePassthrough(void *ctx_in);
static void cbrCloudHeaderPassthrough(void *ctx_in, const char *header, const char *value);
static void cbrCloudBodyPassthrough(void *ctx_in, const char *payload, size_t length);
static void cbrCloudServerDiskPasshtorugh(void *ctx_in);

static void cbrCloudResponsePassthrough(void *ctx_in)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)ctx_in;
    char line[128];

    osSprintf(line, "HTTP/%u.%u %u This is fine", MSB(ctx->connection->response.version), LSB(ctx->connection->response.version), ctx->connection->response.statusCode);
    httpSend(ctx->connection, line, osStrlen(line), HTTP_FLAG_DELAY);
    ctx->status = PROX_STATUS_CONN;
}

static void cbrCloudHeaderPassthrough(void *ctx_in, const char *header, const char *value)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)ctx_in;
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

static void cbrCloudBodyPassthrough(void *ctx_in, const char *payload, size_t length)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)ctx_in;

    TRACE_INFO(">> httpServerBodyCbr: %lu received\r\n", length);
    httpSend(ctx->connection, payload, length, HTTP_FLAG_DELAY);
    ctx->status = PROX_STATUS_BODY;
}

static void cbrCloudServerDiskPasshtorugh(void *ctx_in)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)ctx_in;

    TRACE_INFO(">> httpServerDiscCbr\r\n");
    ctx->status = PROX_STATUS_DONE;
}

error_t handleReverse(HttpConnection *connection, const char_t *uri)
{
    cbr_ctx_t ctx = {
        .status = PROX_STATUS_IDLE,
        .connection = connection};

    req_cbr_t cbr = {
        .ctx = &ctx,
        .response = &cbrCloudResponsePassthrough,
        .header = &cbrCloudHeaderPassthrough,
        .body = &cbrCloudBodyPassthrough,
        .disconnect = &cbrCloudServerDiskPasshtorugh};

    /* here call cloud request, which has to get extended for cbr for header fields and content packets */
    uint8_t *token = connection->private.authentication_token;
    error_t error = cloud_request_get(NULL, 0, &uri[8], token, &cbr);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("cloud_request_get() failed");
        return error;
    }

    TRACE_INFO("httpServerRequestCallback: (waiting)\n");
    while (ctx.status != PROX_STATUS_DONE)
    {
        sleep(100);
    }
    error = httpCloseStream(connection);

    TRACE_INFO("httpServerRequestCallback: (done)\n");
    return NO_ERROR;
}

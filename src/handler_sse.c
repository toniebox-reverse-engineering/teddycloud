#include "handler.h"

#include "handler_sse.h"

static SseSubscriptionContext sseSubs[SSE_MAX_CHANNELS];
static uint8_t sseSubscriptionCount = 0;

error_t handleApiSseSub(HttpConnection *connection, const char_t *uri, const char_t *queryString)
{
    uint8_t channel;
    SseSubscriptionContext *sseCtx = NULL;
    for (channel = 0; channel < SSE_MAX_CHANNELS; channel++)
    { // Find first free slot
        sseCtx = &sseSubs[channel];
        if (sseCtx->connection != NULL && sseCtx->lastConnection + SSE_TIMEOUT_S < time(NULL))
        {
            httpCloseStream(connection);
            sseCtx->connection = NULL;
            sseCtx->lastConnection = 0;
            sseSubscriptionCount--;
        }

        if (sseCtx->lastConnection == 0 && sseCtx->connection == NULL)
        {
            break;
        }
    }
    if (sseCtx == NULL)
        return NO_ERROR;

    sseCtx->lastConnection = time(NULL);
    sseSubscriptionCount++;

    char_t *urlPrintf = SSE_BASE_URL "%" PRIu8;
    char_t *url = osAllocMem(osStrlen(urlPrintf));
    TRACE_INFO("Allocated channel %" PRIu8 ", on uri %s\r\n", channel, url);

    osSprintf(url, urlPrintf, channel);
    httpInitResponseHeader(connection);
    connection->response.contentType = "text/plain";
    return httpWriteResponseString(connection, url, true);
}
error_t handleApiSseCon(HttpConnection *connection, const char_t *uri, const char_t *queryString)
{
    uint8_t channel = atoi(&uri[osStrlen(SSE_BASE_URL)]);
    SseSubscriptionContext *sseCtx = &sseSubs[channel];

    httpInitResponseHeader(connection);
    connection->response.contentType = "application/json";
    connection->response.contentLength = CONTENT_LENGTH_UNKNOWN;

    error_t error = httpWriteHeader(connection);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send header\r\n");
        return error;
    }
    sseCtx->connection = connection;
    sseCtx->lastConnection = time(NULL);

    httpWriteString(connection, "data: { \"type\":\"keep-alive\", \"data\":\"\" }\r\n");

    while (sseCtx->connection != NULL)
    {
        if (sseCtx->lastConnection + SSE_TIMEOUT_S < time(NULL))
        {
            httpCloseStream(sseCtx->connection);
            sseCtx->connection = NULL;
            sseCtx->lastConnection = 0;
            sseSubscriptionCount--;
        }
    }

    return error;
}

error_t sse_sendEvent(const char *eventname, const char *content, bool escapeData)
{
    error_t error = NO_ERROR;
    for (uint8_t channel = 0; channel < SSE_MAX_CHANNELS; channel++)
    {
        SseSubscriptionContext *sseCtx = &sseSubs[channel];
        sseCtx->lastConnection = time(NULL);
        HttpConnection *conn = sseCtx->connection;
        if (sseCtx->connection == NULL)
            continue;

        error = httpWriteString(conn, "data: { \"type\":\"");
        if (error != NO_ERROR)
            return error;
        error = httpWriteString(conn, eventname);
        if (error != NO_ERROR)
            return error;
        error = httpWriteString(conn, "\", \"data\":");
        if (error != NO_ERROR)
            return error;
        if (escapeData)
        {
            error = httpWriteString(conn, "\"");
            if (error != NO_ERROR)
                return error;
        }
        error = httpWriteString(conn, content);
        if (error != NO_ERROR)
            return error;
        if (escapeData)
        {
            error = httpWriteString(conn, "\"");
            if (error != NO_ERROR)
                return error;
        }
        error = httpWriteString(conn, " }\r\n");
        if (error != NO_ERROR)
            return error;
    }
    return error;
}

error_t sse_keepAlive(void)
{
    return sse_sendEvent("keep-alive", "", false);
}
#include "handler.h"

#include "handler_sse.h"

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

    TRACE_INFO("Allocated channel %" PRIu8 ", on uri %s", channel, uri);
    char_t *url = SSE_BASE_URL "%" PRIu8;
    osSprintf(url, url, channel);
    return httpWriteResponse(connection, url, false);
}
error_t handleApiSseCon(HttpConnection *connection, const char_t *uri, const char_t *queryString)
{
    uint8_t channel = atoi(&uri[osStrlen(SSE_BASE_URL)]);
    SseSubscriptionContext *sseCtx = &sseSubs[channel];

    httpInitResponseHeader(connection);
    connection->response.contentLength = CONTENT_LENGTH_UNKNOWN;

    error_t error = httpWriteHeader(connection);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send header\r\n");
        return error;
    }
    sseCtx->connection = connection;
    sseCtx->lastConnection = time(NULL);

    httpWriteString(connection, "data: { \"type\":\"keep-alive\", \"data\":\"\" }");

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
        error = httpWriteString(conn, " }");
        if (error != NO_ERROR)
            return error;
    }
    return error;
}

error_t sse_keepAlive(void)
{
    return sse_sendEvent("keep-alive", "", false);
}
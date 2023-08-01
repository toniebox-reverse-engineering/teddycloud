#include "handler.h"

#include "handler_sse.h"

static SseSubscriptionContext sseSubs[SSE_MAX_CHANNELS];
static uint8_t sseSubscriptionCount = 0;

error_t handleApiSse(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *ctx)
{
    uint8_t channel;
    SseSubscriptionContext *sseCtx = NULL;
    osSuspendAllTasks();
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
    osResumeAllTasks();
    if (sseCtx == NULL)
        return NO_ERROR;

    sseCtx->lastConnection = time(NULL);
    sseSubscriptionCount++;

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
            osSuspendAllTasks();
            sseCtx->connection = NULL;
            sseCtx->lastConnection = 0;
            sseSubscriptionCount--;
            osResumeAllTasks();
        }
    }

    return error;
}

error_t sse_startEventRaw(const char *eventname)
{
    error_t error = NO_ERROR;

    error = sse_rawData("data: { \"type\":\"");
    if (error != NO_ERROR)
        return error;

    error = sse_rawData(eventname);
    if (error != NO_ERROR)
        return error;

    error = sse_rawData("\", \"data\":");
    return error;
}
error_t sse_rawData(const char *content)
{
    error_t error = NO_ERROR;
    for (uint8_t channel = 0; channel < SSE_MAX_CHANNELS; channel++)
    {
        SseSubscriptionContext *sseCtx = &sseSubs[channel];
        sseCtx->lastConnection = time(NULL);
        HttpConnection *conn = sseCtx->connection;
        if (sseCtx->connection == NULL)
            continue;

        error = httpWriteString(conn, content);
        if (error != NO_ERROR)
            return error;
    }
    return error;
}
error_t sse_endEventRaw(void)
{
    error_t error = NO_ERROR;
    error = sse_rawData(" }\r\n");
    return error;
}

error_t sse_sendEvent(const char *eventname, const char *content, bool escapeData)
{
    error_t error = NO_ERROR;

    error = sse_startEventRaw(eventname);
    if (error != NO_ERROR)
        return error;
    if (escapeData)
    {
        error = sse_rawData("\"");
        if (error != NO_ERROR)
            return error;
    }
    error = sse_rawData(content);
    if (error != NO_ERROR)
        return error;
    if (escapeData)
    {
        error = sse_rawData("\"");
        if (error != NO_ERROR)
            return error;
    }
    error = sse_endEventRaw();
    return error;
}

error_t sse_keepAlive(void)
{
    return sse_sendEvent("keep-alive", "", false);
}
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
        if (sseCtx->lastConnection == 0 && sseCtx->connection == NULL)
        {
            break;
        }
        else
        {
            sseCtx = NULL;
        }
    }
    if (sseCtx == NULL)
    {
        osResumeAllTasks();
        TRACE_ERROR("All slots full, in total %" PRIu8 " clients", sseSubscriptionCount);
        return NO_ERROR;
    }

    sseCtx->lastConnection = time(NULL);
    sseCtx->connection = connection;
    sseSubscriptionCount++;

    osResumeAllTasks();

    TRACE_INFO("SSE Client connected in slot %" PRIu8 " in total %" PRIu8 " clients\r\n", channel, sseSubscriptionCount);

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/event-stream";
    connection->response.contentLength = CONTENT_LENGTH_UNKNOWN;

    error_t error = httpWriteHeader(connection);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send header\r\n");
        return error;
    }

    httpWriteString(connection, "data: { \"type\":\"keep-alive\", \"data\":\"\" }\r\n");

    while (true)
    {
        if ((sseCtx->lastConnection + SSE_TIMEOUT_S < time(NULL)))
        {
            httpCloseStream(connection);
            osSuspendAllTasks();
            sseCtx->connection = NULL;
            sseCtx->lastConnection = 0;
            sseSubscriptionCount--;
            osResumeAllTasks();
            TRACE_INFO("SSE Client disconnected from slot %" PRIu8 ", %" PRIu8 " clients left\r\n", channel, sseSubscriptionCount);
            break;
        }
        osDelayTask(100);
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
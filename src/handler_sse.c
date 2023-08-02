#include "handler.h"

#include "handler_sse.h"

static SseSubscriptionContext sseSubs[SSE_MAX_CHANNELS];
static uint8_t sseSubscriptionCount = 0;

error_t handleApiSse(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *ctx)
{
    osSuspendAllTasks();

    SseSubscriptionContext *sseCtx = NULL;
    for (uint8_t channel = 0; channel < SSE_MAX_CHANNELS; channel++)
    { // Find first free slot
        sseCtx = &sseSubs[channel];
        if (!sseCtx->active)
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
        httpCloseStream(connection);
        return NO_ERROR;
    }

    sseCtx->lastConnection = time(NULL);
    sseCtx->connection = connection;
    sseCtx->active = TRUE;
    sseCtx->error = NO_ERROR;
    sseSubscriptionCount++;

    osResumeAllTasks();

    TRACE_INFO("SSE Client connected in slot %" PRIu8 " in total %" PRIu8 " clients\r\n", sseCtx->channel, sseSubscriptionCount);

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
        //(connection->socket != NULL && (connection->socket->state == TCP_STATE_CLOSED)) ||
        //(connection->tlsContext != NULL && (connection->tlsContext->state == TLS_STATE_CLOSED)) ||

        if (sseCtx->error != NO_ERROR || sseCtx->active == FALSE || (sseCtx->lastConnection + SSE_TIMEOUT_S < time(NULL)))
        {
            httpCloseStream(connection);
            osSuspendAllTasks();
            sseCtx->active = FALSE;
            error = sseCtx->error;
            sseSubscriptionCount--;
            osResumeAllTasks();
            TRACE_INFO("SSE Client disconnected from slot %" PRIu8 ", %" PRIu8 " clients left\r\n", sseCtx->channel, sseSubscriptionCount);
            if (error != NO_ERROR)
            {
                TRACE_ERROR("SSE Client with error %" PRIu32 "\r\n", error);
            }
            break;
        }
        osDelayTask(100);
    }

    return error;
}

void sse_init()
{
    SseSubscriptionContext *sseCtx = NULL;
    for (uint8_t channel = 0; channel < SSE_MAX_CHANNELS; channel++)
    {
        sseCtx = &sseSubs[channel];
        sseCtx->channel = channel;
        sseCtx->active = FALSE;
    }
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
    // osSuspendAllTasks();
    for (uint8_t channel = 0; channel < SSE_MAX_CHANNELS; channel++)
    {
        SseSubscriptionContext *sseCtx = &sseSubs[channel];
        if (!sseCtx->active)
            continue;
        sseCtx->lastConnection = time(NULL);
        sseCtx->error = httpWriteString(sseCtx->connection, content);
    }
    // osResumeAllTasks();

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
#include "handler.h"

#include "mutex_manager.h"
#include "handler_sse.h"

static SseSubscriptionContext sseSubs[SSE_MAX_CHANNELS];
static uint8_t sseSubscriptionCount = 0;

error_t handleApiSse(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *ctx)
{
    mutex_lock(MUTEX_SSE_CTX);

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
        mutex_unlock(MUTEX_SSE_CTX);
        TRACE_ERROR("All slots full, in total %" PRIu8 " clients", sseSubscriptionCount);
        httpInitResponseHeader(connection);
        connection->response.contentLength = 0;
        connection->response.statusCode = 503; // Service Unavailable
        connection->response.keepAlive = FALSE;
        return httpWriteHeader(connection);
    }

    sseCtx->lastConnection = time(NULL);
    sseCtx->connection = connection;
    sseCtx->active = TRUE;
    sseCtx->error = NO_ERROR;
    sseSubscriptionCount++;

    mutex_unlock(MUTEX_SSE_CTX);

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

    time_t last = 0;
    while (true)
    {
        mutex_lock(MUTEX_SSE_CTX);
        //(connection->socket != NULL && (connection->socket->state == TCP_STATE_CLOSED)) ||
        //(connection->tlsContext != NULL && (connection->tlsContext->state == TLS_STATE_CLOSED)) ||
        if (sseCtx->error != NO_ERROR || sseCtx->active == FALSE || (sseCtx->lastConnection + SSE_TIMEOUT_S < time(NULL)))
        {
            httpFlushStream(connection);
            sseCtx->active = FALSE;
            error = sseCtx->error;
            sseSubscriptionCount--;
            TRACE_INFO("SSE Client disconnected from slot %" PRIu8 ", %" PRIu8 " clients left\r\n", sseCtx->channel, sseSubscriptionCount);
            if (error != NO_ERROR)
            {
                TRACE_ERROR("SSE Client with error %" PRIu32 "\r\n", error);
            }
            mutex_unlock(MUTEX_SSE_CTX);
            break;
        }

        time_t now = time(NULL);
        if (now - last > SSE_KEEPALIVE_S)
        {
            mutex_lock(MUTEX_SSE_EVENT);
            sseCtx->error = httpWriteString(connection, "event: keep-alive\r\ndata: { \"type\":\"keep-alive\", \"data\":\"\" }\r\n");
            mutex_unlock(MUTEX_SSE_EVENT);
            last = now;
            if (sseCtx->error != NO_ERROR)
            {
                mutex_unlock(MUTEX_SSE_CTX);
                continue;
            }
            sseCtx->lastConnection = now;
        }

        mutex_unlock(MUTEX_SSE_CTX);
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
    mutex_lock(MUTEX_SSE_EVENT);

    error_t error = NO_ERROR;

    error = sse_rawData("event: ");
    if (error != NO_ERROR)
        return error;

    error = sse_rawData(eventname);
    if (error != NO_ERROR)
        return error;

    error = sse_rawData("\r\ndata: { \"type\":\"");
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

    mutex_lock(MUTEX_SSE_CTX);
    for (uint8_t channel = 0; channel < SSE_MAX_CHANNELS; channel++)
    {
        SseSubscriptionContext *sseCtx = &sseSubs[channel];
        if (!sseCtx->active)
        {
            continue;
        }
        sseCtx->error = httpWriteString(sseCtx->connection, content);
        if (sseCtx->error == NO_ERROR)
        {
            sseCtx->lastConnection = time(NULL);
        }
    }
    mutex_unlock(MUTEX_SSE_CTX);

    return error;
}

error_t sse_endEventRaw(void)
{
    error_t error = NO_ERROR;
    error = sse_rawData(" }\r\n");
    mutex_unlock(MUTEX_SSE_EVENT);
    return error;
}

error_t sse_sendEvent(const char *eventname, const char *content, bool escapeData)
{
    error_t error = NO_ERROR;
    error = sse_startEventRaw(eventname);

    do
    {
        if (error != NO_ERROR)
            break;

        if (escapeData)
        {
            error = sse_rawData("\"");
            if (error != NO_ERROR)
            {
                break;
            }
        }

        error = sse_rawData(content);
        if (error != NO_ERROR)
        {
            break;
        }

        if (escapeData)
        {
            error = sse_rawData("\"");
            if (error != NO_ERROR)
            {
                break;
            }
        }
    } while (0);

    error = sse_endEventRaw();
    return error;
}

error_t sse_keepAlive(void)
{
    return sse_sendEvent("keep-alive", "", false);
}
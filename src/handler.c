#include "handler.h"

error_t httpWriteResponse(HttpConnection *connection, void *data, bool_t freeMemory)
{
    error_t error = httpWriteHeader(connection);
    if (error != NO_ERROR)
    {
        if (freeMemory)
            osFreeMem(data);
        TRACE_ERROR("Failed to send header\r\n");
        return error;
    }

    error = httpWriteStream(connection, data, connection->response.contentLength);
    if (freeMemory)
        if (freeMemory)
            osFreeMem(data);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send payload: %d\r\n", error);
        return error;
    }

    error = httpCloseStream(connection);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to close: %d\r\n", error);
        return error;
    }

    return NO_ERROR;
}

error_t httpWriteString(HttpConnection *connection, const char_t *content)
{
    return httpWriteStream(connection, content, osStrlen(content));
}
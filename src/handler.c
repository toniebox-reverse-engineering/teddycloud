#include "handler.h"

error_t httpWriteResponseString(HttpConnection *connection, char_t *data, bool_t freeMemory)
{
    return httpWriteResponse(connection, data, osStrlen(data), freeMemory);
}
error_t httpWriteResponse(HttpConnection *connection, void *data, size_t size, bool_t freeMemory)
{
    error_t error = httpWriteHeader(connection);
    if (error != NO_ERROR)
    {
        if (freeMemory)
            osFreeMem(data);
        TRACE_ERROR("Failed to send header\r\n");
        return error;
    }

    error = httpWriteStream(connection, data, size);
    if (freeMemory)
        if (freeMemory)
            osFreeMem(data);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send payload: %d\r\n", error);
        return error;
    }

    error = httpFlushStream(connection);
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

error_t httpFlushStream(HttpConnection *connection)
{
    return httpCloseStream(connection);
}
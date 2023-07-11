
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "handler_api.h"
#include "settings.h"

static int stats_connections = 0;
static int stats_reverse_requests = 0;
static int stats_cloud_requests = 0;
static int stats_cloud_failed = 0;

void stats_update(const char *item, int count)
{
    if (!strcmp(item, "connections"))
    {
        stats_connections += count;
    }
    if (!strcmp(item, "reverse.requests"))
    {
        stats_reverse_requests += count;
    }
    if (!strcmp(item, "cloud.requests"))
    {
        stats_cloud_requests += count;
    }
    if (!strcmp(item, "cloud.failed"))
    {
        stats_cloud_failed += count;
    }
}

error_t handleApiStats(HttpConnection *connection, const char_t *uri)
{
    char json[256];
    sprintf(json, "{\"connections\": %d, \"reverse_requests\": %d, \"cloud_requests\": %d, \"cloud_failed\": %d}",
            stats_connections, stats_reverse_requests, stats_cloud_requests, stats_cloud_failed);

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/json";
    connection->response.contentLength = osStrlen(json);

    error_t error = httpWriteHeader(connection);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send header\r\n");
        return error;
    }

    error = httpWriteStream(connection, json, connection->response.contentLength);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send header\r\n");
        return error;
    }

    error = httpCloseStream(connection);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to close\r\n");
        return error;
    }

    return NO_ERROR;
}

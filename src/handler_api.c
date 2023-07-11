
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "handler_api.h"
#include "settings.h"

typedef struct
{
    const char *name;
    uint32_t counter;
} stat_t;

stat_t statistics[] = {
    {"connections", 0},
    {"reverse_requests", 0},
    {"cloud_requests", 0},
    {"cloud_failed", 0},
    {NULL, 0}};

void stats_update(const char *item, int count)
{
    int pos = 0;
    while (statistics[pos].name)
    {
        if (!strcmp(item, statistics[pos].name))
        {
            statistics[pos].counter += count;
            return;
        }
        pos++;
    }
}

error_t handleApiGetIndex(HttpConnection *connection, const char_t *uri)
{
    char *json = strdup("{\"options\": [");
    int pos = 0;

    json = realloc(json, osStrlen(json) + 10);
    while (true)
    {
        char buf[1024];
        option_map_t *opt = settings_get_id(pos);

        if (!opt)
        {
            break;
        }
        const char *type = "unknown";

        switch (opt->type)
        {
        case TYPE_BOOL:
            type = "bool";
            break;
        case TYPE_INTEGER:
            type = "int";
            break;
        case TYPE_HEX:
            type = "hex";
            break;
        case TYPE_STRING:
            type = "string";
            break;
        case TYPE_FLOAT:
            type = "float";
            break;
        default:
            break;
        }

        if (pos != 0)
        {
            strcat(json, ",");
        }

        sprintf(buf, "{\"ID\": \"%s\", \"shortname\": \"%s\", \"description\": \"%s\", \"type\": \"%s\"}",
                opt->option_name, opt->option_name, opt->description, type);

        json = realloc(json, osStrlen(json) + osStrlen(buf) + 10);
        strcat(json, buf);

        pos++;
    }
    strcat(json, "]}");
    httpInitResponseHeader(connection);
    connection->response.contentType = "text/plain";
    connection->response.contentLength = osStrlen(json);

    error_t error = httpWriteHeader(connection);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send header\r\n");
        return error;
    }

    error = httpWriteStream(connection, json, connection->response.contentLength);
    free(json);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send header\r\n");
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

error_t handleApiGet(HttpConnection *connection, const char_t *uri)
{
    char json[256];

    char *item = &uri[8];

    if (!strcmp(item, "Index"))
    {
        return handleApiGetIndex(connection, uri);
    }

    sprintf(json, "%s", settings_get_bool(item) ? "true" : "false");

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/plain";
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
        TRACE_ERROR("Failed to close: %d\r\n", error);
        return error;
    }

    return NO_ERROR;
}

#define BODY_BUFFER_SIZE 128

error_t handleApiSet(HttpConnection *connection, const char_t *uri)
{
    char response[256];
    sprintf(response, "OK");
    char *item = &uri[8];

    TRACE_INFO("Setting: '%s' to ", item);

    char_t data[BODY_BUFFER_SIZE];
    size_t size;
    if (BODY_BUFFER_SIZE <= connection->request.byteCount)
    {
        TRACE_ERROR("Body size %li bigger than buffer size %i bytes", connection->request.byteCount, BODY_BUFFER_SIZE);
    }
    else
    {
        error_t error = httpReceive(connection, &data, BODY_BUFFER_SIZE, &size, 0x00);
        if (error != NO_ERROR)
        {
            TRACE_ERROR("httpReceive failed!");
            return error;
        }
        data[size] = 0;
        TRACE_INFO("'%s'\r\n", data);

        settings_set_bool(item, !strcmp(data, "true"));
    }

    httpPrepareHeader(connection, "text/plain; charset=utf-8", 0);
    return httpWriteResponse(connection, "", false);
    return NO_ERROR;
}

error_t handleApiStats(HttpConnection *connection, const char_t *uri)
{
    char *json = strdup("{");

    json = realloc(json, osStrlen(json) + 10);
    int pos = 0;
    while (statistics[pos].name)
    {
        char buf[128];

        if (pos != 0)
        {
            strcat(json, ",");
        }
        sprintf(buf, "\"%s\": %d", statistics[pos].name, statistics[pos].counter);

        json = realloc(json, osStrlen(json) + osStrlen(buf) + 10);
        strcat(json, buf);

        pos++;
    }
    strcat(json, "}");

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
    free(json);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send header\r\n");
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


#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "handler_api.h"
#include "handler_cloud.h"
#include "settings.h"
#include "stats.h"
#include "returncodes.h"

error_t handleApiGetIndex(HttpConnection *connection, const char_t *uri)
{
    char *json = strdup("{\"options\": [");
    int pos = 0;
    bool first = true;

    json = realloc(json, osStrlen(json) + 10);
    while (true)
    {
        setting_item_t *opt = settings_get(pos);

        if (!opt)
        {
            break;
        }
        if (opt->internal)
        {
            pos++;
            continue;
        }
        const char *type = "unknown";

        switch (opt->type)
        {
        case TYPE_BOOL:
            type = "bool";
            break;
        case TYPE_UNSIGNED:
            type = "uint";
            break;
        case TYPE_SIGNED:
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

        if (!first)
        {
            strcat(json, ",");
        }
        first = false;

        char buf[1024];
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

error_t handleApiTrigger(HttpConnection *connection, const char_t *uri)
{
    const char *item = &uri[5];
    char response[256];

    sprintf(response, "FAILED");

    if (!strcmp(item, "triggerExit"))
    {
        TRACE_INFO("Triggered Exit\r\n");
        settings_set_bool("internal.exit", TRUE);
        settings_set_signed("internal.returncode", RETURNCODE_USER_QUIT);
        sprintf(response, "OK");
    }
    else if (!strcmp(item, "triggerRestart"))
    {
        TRACE_INFO("Triggered Restart\r\n");
        settings_set_bool("internal.exit", TRUE);
        settings_set_signed("internal.returncode", RETURNCODE_USER_RESTART);
        sprintf(response, "OK");
    }
    else if (!strcmp(item, "triggerReloadConfig"))
    {
        TRACE_INFO("Triggered ReloadConfig\r\n");
        sprintf(response, "OK");
        settings_load();
    }
    else if (!strcmp(item, "triggerWriteConfig"))
    {
        TRACE_INFO("Triggered WriteConfig\r\n");
        sprintf(response, "OK");
        settings_save();
    }

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/plain";
    connection->response.contentLength = osStrlen(response);

    error_t error = httpWriteHeader(connection);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send header\r\n");
        return error;
    }

    error = httpWriteStream(connection, response, connection->response.contentLength);
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
    const char *item = &uri[5 + 3 + 1];

    char json[256];
    strcpy(json, "ERROR");
    setting_item_t *opt = settings_get_by_name(item);

    if (opt)
    {
        switch (opt->type)
        {
        case TYPE_BOOL:
            sprintf(json, "%s", settings_get_bool(item) ? "true" : "false");
            break;
        case TYPE_HEX:
        case TYPE_UNSIGNED:
            sprintf(json, "%d", settings_get_unsigned(item));
            break;
        case TYPE_SIGNED:
            sprintf(json, "%d", settings_get_signed(item));
            break;
        case TYPE_STRING:
            sprintf(json, "%s", settings_get_string(item));
            break;
        case TYPE_FLOAT:
            sprintf(json, "%f", settings_get_float(item));
            break;
        default:
            break;
        }
    }

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

error_t handleApiSet(HttpConnection *connection, const char_t *uri)
{
    char response[256];
    sprintf(response, "ERROR");
    const char *item = &uri[9];

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

        setting_item_t *opt = settings_get_by_name(item);
        if (opt)
        {
            switch (opt->type)
            {
            case TYPE_BOOL:
            {
                if (settings_set_bool(item, !strcasecmp(data, "true")))
                {
                    strcpy(response, "OK");
                }
                break;
            }
            case TYPE_STRING:
            {
                if (settings_set_string(item, data))
                {
                    strcpy(response, "OK");
                }
                break;
            }
            case TYPE_HEX:
            {
                uint32_t value = strtoul(data, NULL, 16);

                if (settings_set_unsigned(item, value))
                {
                    strcpy(response, "OK");
                }
                break;
            }

            case TYPE_UNSIGNED:
            {
                uint32_t value = strtoul(data, NULL, 10);

                if (settings_set_unsigned(item, value))
                {
                    strcpy(response, "OK");
                }
                break;
            }

            case TYPE_SIGNED:
            {
                int32_t value = strtol(data, NULL, 10);

                if (settings_set_signed(item, value))
                {
                    strcpy(response, "OK");
                }
                break;
            }

            case TYPE_FLOAT:
            {
                float value = strtof(data, NULL);

                if (settings_set_float(item, value))
                {
                    strcpy(response, "OK");
                }
                break;
            }

            default:
                break;
            }
        }
        else
        {

            TRACE_ERROR("Setting '%s' is unknown", item);
        }
    }

    httpPrepareHeader(connection, "text/plain; charset=utf-8", 0);
    return httpWriteResponse(connection, response, false);
}

error_t handleApiStats(HttpConnection *connection, const char_t *uri)
{
    char *json = strdup("{\"stats\": [");
    int pos = 0;

    json = realloc(json, osStrlen(json) + 10);
    while (true)
    {
        char buf[1024];
        stat_t *stat = stats_get(pos);

        if (!stat)
        {
            break;
        }

        if (pos != 0)
        {
            strcat(json, ",");
        }

        sprintf(buf, "{\"ID\": \"%s\", \"description\": \"%s\", \"value\": \"%d\" }",
                stat->name, stat->description, stat->value);

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

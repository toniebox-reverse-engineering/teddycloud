
#include "fs_port.h"
#include "os_port.h"
#include "settings.h"
#include "handler.h"
#include "cloud_request.h"
#include "debug.h"
#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_client.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

typedef enum
{
    PROT_HTTP,
    PROT_HTTPS
} web_protocol_t;
#define DEFAULT_HTTP_PORT 80
#define DEFAULT_HTTPS_PORT 443
#define PORT_MAX 65535

bool web_parse_url(const char *url, char **hostname, uint16_t *port, char **uri, web_protocol_t *protocol)
{
    // Check if the URL starts with "http://" or "https://"
    if (strncmp(url, "http://", 7) == 0)
    {
        *protocol = PROT_HTTP;
        url += 7;
    }
    else if (strncmp(url, "https://", 8) == 0)
    {
        *protocol = PROT_HTTPS;
        url += 8;
    }
    else
    {
        TRACE_ERROR("Unknown protocol\r\n");
        return false;
    }

    // Find the start of the port and path
    char *port_start = strchr(url, ':');
    char *path_start = strchr(url, '/');

    if (path_start == NULL)
    {
        TRACE_ERROR("URL must contain a path\r\n");
        return false;
    }

    // Determine the hostname and port
    if (port_start != NULL && port_start < path_start)
    {
        // Port is specified
        size_t hostname_length = port_start - url;
        *hostname = (char *)malloc(hostname_length + 1);
        if (*hostname == NULL)
        {
            TRACE_ERROR("Memory allocation error\r\n");
            return false;
        }
        strncpy(*hostname, url, hostname_length);
        (*hostname)[hostname_length] = '\0';

        // Parse and validate port
        long temp = strtol(port_start + 1, &path_start, 10);
        if ((temp > 0) && (temp <= PORT_MAX))
        {
            *port = (uint16_t)temp;
        }
        else
        {
            TRACE_ERROR("Invalid port number\r\n");
            free(*hostname);
            return false;
        }
    }
    else
    {
        // Port is not specified, use default port based on protocol
        size_t hostname_length = path_start - url;
        *hostname = (char *)malloc(hostname_length + 1);
        if (*hostname == NULL)
        {
            TRACE_ERROR("Memory allocation error\r\n");
            return false;
        }
        strncpy(*hostname, url, hostname_length);
        (*hostname)[hostname_length] = '\0';

        *port = (*protocol == PROT_HTTP) ? DEFAULT_HTTP_PORT : DEFAULT_HTTPS_PORT;
    }

    // Copy the path and query (if any) into the uri
    *uri = strdup(path_start);
    if (*uri == NULL)
    {
        TRACE_ERROR("Memory allocation error\r\n");
        free(*hostname);
        return false;
    }

    return true;
}

void web_dl_cbr(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    const char *filename = (const char *)ctx->customData;
    HttpClientContext *httpClientContext = (HttpClientContext *)cloud_ctx;

    if (httpClientContext->statusCode == 200)
    {
        if (ctx->file == NULL)
        {
            TRACE_DEBUG("Opening file %s\r\n", filename);
            ctx->file = fsOpenFile(filename, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
            if (!ctx->file)
            {
                TRACE_ERROR("Failed to open file %s\r\n", filename);
                return;
            }
        }
        error_t errorWrite = NO_ERROR;
        if (length > 0)
        {
            errorWrite = fsWriteFile(ctx->file, (void *)payload, length);
        }

        if (error == ERROR_END_OF_STREAM)
        {
            fsCloseFile(ctx->file);
        }
        else if (error != NO_ERROR)
        {
            fsCloseFile(ctx->file);
            TRACE_ERROR("body error=%s\r\n", error2text(error));
        }
        if (errorWrite != NO_ERROR)
        {
            fsCloseFile(ctx->file);
            TRACE_ERROR("write error=%s\r\n", error2text(error));
        }
    }
}

error_t web_download(const char *url, const char *filename, uint32_t *statusCode)
{
    TRACE_INFO("Downloading file from '%s' into local file '%s'\r\n", url, filename);

    char *hostname = NULL;
    uint16_t port = 0;
    char *uri = NULL;
    web_protocol_t protocol;

    // Parse the URL
    if (!web_parse_url(url, &hostname, &port, &uri, &protocol))
    {
        TRACE_ERROR("Failed to parse URL\r\n");
        return ERROR_INVALID_PARAMETER;
    }

    cbr_ctx_t ctx = {0};
    ctx.customData = (void *)filename;

    req_cbr_t cbr = {
        .ctx = &ctx,
        .body = &web_dl_cbr,
    };

    bool is_secure = (protocol == PROT_HTTPS);
    error_t error = web_request(hostname, port, is_secure, uri, NULL, "GET", NULL, 0, NULL, &cbr, false, false, statusCode);

    free(hostname);
    free(uri);

    if (error != NO_ERROR)
    {
        TRACE_ERROR("download failed, error=%s\r\n", error2text(error));
        return error;
    }

    if (fsFileExists(filename))
    {
        return NO_ERROR;
    }

    if (*statusCode == 404)
    {
        return ERROR_NOT_FOUND;
    }

    return ERROR_FAILURE;
}


#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "handler.h"
#include "handler_reverse.h"
#include "settings.h"
#include "stats.h"
#include "cloud_request.h"
#include "os_port.h"
#include "http/http_client.h"
#include "cache.h"
#include "hash/sha256.h"
#include "fs_port.h"
#include "server_helpers.h"
#include "version.h"

error_t handleReverseCloudGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    cbr_ctx_t cbr_ctx;
    req_cbr_t cbr = getCloudCbr(connection, uri, queryString, API_NONE, &cbr_ctx, client_ctx);

    stats_update("reverse_requests", 1);

    /* here call cloud request, which has to get extended for cbr for header fields and content packets */
    uint8_t *token = connection->private.authentication_token;

    // TODO POST
    error_t error = cloud_request_get(NULL, 0, &uri[8], queryString, token, &cbr);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("cloud_request_get() failed\r\n");
        return error;
    }

    TRACE_DEBUG("httpServerRequestCallback: (waiting)\r\n");
    while (cbr_ctx.status != PROX_STATUS_DONE)
    {
        osDelayTask(50);
    }
    error = httpFlushStream(connection);

    TRACE_DEBUG("httpServerRequestCallback: (done)\r\n");
    return error;
}

typedef struct
{
    const char *name;
    const char *hostname;
    const char *path;
    int port;
    bool https;
    bool allow_params;
    bool cache;
    uint32_t cache_hours;
    const char *mime_type;
} reverse_target_t;

const reverse_target_t reverse_targets[] = {
    {"macvendor", "api.macvendors.com", "/", 443, true, true, true, 24, "text/plain"},
    {"teddycloud_release", "api.github.com", "/repos/toniebox-reverse-engineering/teddycloud/releases/latest", 443, true, false, true, 24, "application/json"},
    {"teddycloud_develop", "api.github.com", "/repos/toniebox-reverse-engineering/teddycloud/commits/develop", 443, true, false, true, 1, "application/json"},
    {NULL, NULL, NULL, 0, false, false, false, 0, NULL}};

void cbrReverseBodyCache(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    static size_t total_sent = 0;
    error_t send_err;

    if (cloud_ctx->statusCode == 200)
    {
        if (length > 0 && ctx->file != NULL)
        {
            error_t write_err = fsWriteFile(ctx->file, (void *)payload, length);
            if (write_err)
            {
                TRACE_ERROR(">> fsWriteFile Error: %s\r\n", error2text(write_err));
            }
        }
    }
    else
    {
        if (ctx->file != NULL)
        {
            TRACE_WARNING("Non-200 status code (%d)\r\n", cloud_ctx->statusCode);
            fsCloseFile(ctx->file);
            ctx->file = NULL;
        }
    }

    if (error == ERROR_END_OF_STREAM || error != NO_ERROR)
    {
        if (ctx->file != NULL)
        {
            fsCloseFile(ctx->file);
            ctx->file = NULL;
        }
    }

    send_err = httpSend(ctx->connection, payload, length, HTTP_FLAG_DELAY);
    if (send_err)
    {
        TRACE_ERROR(">> httpSend failed at total=%" PRIuSIZE ", chunk=%" PRIuSIZE ": %s\r\n", total_sent, length, error2text(send_err));
    }
    total_sent += length;
    ctx->status = PROX_STATUS_BODY;
}

error_t handleReverseGeneric(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    const char *prefix = "/reverseGeneric/";
    size_t prefixLen = strlen(prefix);

    if (strncmp(uri, prefix, prefixLen) != 0)
    {
        return ERROR_NOT_FOUND;
    }

    const char *targetNamePrefix = uri + prefixLen;
    const reverse_target_t *target = NULL;
    const char *subPath = NULL;

    for (int i = 0; reverse_targets[i].name != NULL; i++)
    {
        size_t nameLen = strlen(reverse_targets[i].name);
        if (strncmp(targetNamePrefix, reverse_targets[i].name, nameLen) == 0)
        {
            char nextChar = targetNamePrefix[nameLen];
            if (nextChar == '\0' || nextChar == '/')
            {
                target = &reverse_targets[i];
                subPath = targetNamePrefix + nameLen;
                break;
            }
        }
    }

    if (target == NULL)
    {
        TRACE_WARNING("Reverse proxy target not found for URI: %s\r\n", uri);
        return ERROR_NOT_FOUND;
    }

    char finalPath[512]; // Increased buffer size to be safe
    strncpy(finalPath, target->path, sizeof(finalPath) - 1);
    finalPath[sizeof(finalPath) - 1] = '\0';

    // Append subPath
    if (subPath && strlen(subPath) > 0)
    {
        // Avoid double slash if target path ends with / and subPath starts with /
        size_t currentLen = strlen(finalPath);
        if (currentLen > 0 && finalPath[currentLen - 1] == '/' && subPath[0] == '/')
        {
             strncat(finalPath, subPath + 1, sizeof(finalPath) - strlen(finalPath) - 1);
        }
        else
        {
             strncat(finalPath, subPath, sizeof(finalPath) - strlen(finalPath) - 1);
        }
    }

    if (target->allow_params && queryString && strlen(queryString) > 0)
    {
        // For macvendors, key is part of path
        // For standard params, might need '?' or '&' but requirements say "params parameter should be appended to the base url"
        // and "macvendor" example implies /<mac>
        // Let's safe-cat it.
        strncat(finalPath, queryString, sizeof(finalPath) - strlen(finalPath) - 1);
    }

    TRACE_INFO("Reverse proxying to: %s%s\r\n", target->hostname, finalPath);

    char *cachePath = NULL;
    char *cachedUrl = NULL;

    if (target->cache)
    {
        uint8_t sha256_calc[SHA256_DIGEST_SIZE];
        char sha256_calc_str[2 * SHA256_DIGEST_SIZE + 1];

        Sha256Context ctx;
        sha256Init(&ctx);
        sha256Update(&ctx, finalPath, strlen(finalPath));
        sha256Final(&ctx, sha256_calc);

        for (int pos = 0; pos < SHA256_DIGEST_SIZE; pos++)
        {
            osSprintf(&sha256_calc_str[2 * pos], "%02X", sha256_calc[pos]);
        }

        char prefix[128];
        osSprintf(prefix, "reverse.%s.%s.", target->name, sha256_calc_str);

        const char *cacheDir = client_ctx->settings->internal.cachedirfull;
        FsDir *dir = fsOpenDir(cacheDir);
        if (dir)
        {
            FsDirEntry entry;
            while (fsReadDir(dir, &entry) == NO_ERROR)
            {
                if (strncmp(entry.name, prefix, strlen(prefix)) == 0)
                {
                    // Found a candidate
                    const char *tsStr = entry.name + strlen(prefix);
                    time_t fileTs = (time_t)strtoul(tsStr, NULL, 10);
                    time_t now = time(NULL);

                    if (fileTs + (target->cache_hours * 3600) > now)
                    {
                        // Valid
                        cachePath = custom_asprintf("%s/%s", cacheDir, entry.name);
                        cachedUrl = custom_asprintf("/reverse/%s", entry.name); 
                        TRACE_INFO("Serving from cache: %s (expires in %ld seconds)\r\n", cachePath, (long)(fileTs + (target->cache_hours * 3600) - now));
                        
                        uint32_t fileSize = 0;
                        fsGetFileSize(cachePath, &fileSize);
                        
                        FsFile *file = fsOpenFile(cachePath, FS_FILE_MODE_READ);
                        if (file)
                        {
                            const char *mime = target->mime_type ? target->mime_type : "application/octet-stream";
                            httpPrepareHeader(connection, mime, fileSize);
                            httpWriteHeader(connection);
                            
                            uint8_t buf[1024];
                            size_t read_len;
                            while(1)
                            {
                                error_t err = fsReadFile(file, buf, sizeof(buf), &read_len);
                                if (read_len > 0)
                                {
                                    httpWriteStream(connection, buf, read_len);
                                }
                                if (err != NO_ERROR || read_len < sizeof(buf)) break;
                            }
                            fsCloseFile(file);
                            httpCloseStream(connection);
                            fsCloseDir(dir);
                            osFreeMem(cachePath);
                            osFreeMem(cachedUrl);
                            return NO_ERROR;
                        }
                    }
                    else
                    {
                        // Expired
                        char *expiredPath = custom_asprintf("%s/%s", cacheDir, entry.name);
                        TRACE_INFO("Cache expired: %s\r\n", expiredPath);
                        fsDeleteFile(expiredPath);
                        osFreeMem(expiredPath);
                    }
                }
            }
            fsCloseDir(dir);
        }

        // If we are here, no valid cache found
        time_t now = time(NULL);
        cachePath = custom_asprintf("%s/%s%ld", cacheDir, prefix, (long)now);
        cachedUrl = custom_asprintf("/reverse/%s%ld", prefix, (long)now);
    }

    cbr_ctx_t cbr_ctx;
    req_cbr_t cbr = getGenericCbr(connection, uri, queryString, API_NONE, &cbr_ctx, client_ctx);

    char *userAgent = custom_asprintf("teddyCloud/%s", BUILD_VERSION);
    cbr_ctx.user_agent = userAgent;

    if (cachePath)
    {
        cbr_ctx.file = fsOpenFile(cachePath, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
        if (cbr_ctx.file)
        {
             cbr.body = &cbrReverseBodyCache;
             TRACE_INFO("Caching response to: %s\r\n", cachePath);
        }
        else
        {
             TRACE_ERROR("Failed to open cache file for writing: %s\r\n", cachePath);
             osFreeMem(cachePath);
             cachePath = NULL;
        }
    }
    
    error_t error = web_request(target->hostname, target->port, target->https, finalPath, NULL, "GET", NULL, 0, NULL, &cbr, false, false, NULL);

    if (cachePath)
    {
        osFreeMem(cachePath);
    }
    if (cachedUrl)
    {
        osFreeMem(cachedUrl);
    }
    if (userAgent)
    {
        osFreeMem(userAgent);
    }

    if (error != NO_ERROR)
    {
        TRACE_ERROR("web_request() failed for reverse proxy\r\n");
        return error;
    }

    TRACE_DEBUG("handleReverseGeneric: (waiting)\r\n");
    while (cbr_ctx.status != PROX_STATUS_DONE)
    {
        osDelayTask(50);
    }
    error = httpFlushStream(connection);

    TRACE_DEBUG("handleReverseGeneric: (done)\r\n");
    return error;
}
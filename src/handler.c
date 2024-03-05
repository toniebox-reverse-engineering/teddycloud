#include "handler.h"
#include "server_helpers.h"

void fillBaseCtx(HttpConnection *connection, const char_t *uri, const char_t *queryString, cloudapi_t api, cbr_ctx_t *ctx, client_ctx_t *client_ctx)
{
    ctx->uri = uri;
    ctx->queryString = queryString;
    ctx->api = api;
    ctx->buffer = NULL;
    ctx->bufferPos = 0;
    ctx->bufferLen = 0;
    ctx->status = PROX_STATUS_IDLE;
    ctx->connection = connection;
    ctx->client_ctx = client_ctx;
}
req_cbr_t getCloudCbr(HttpConnection *connection, const char_t *uri, const char_t *queryString, cloudapi_t api, cbr_ctx_t *ctx, client_ctx_t *client_ctx)
{
    fillBaseCtx(connection, uri, queryString, api, ctx, client_ctx);

    req_cbr_t cbr = {
        .ctx = ctx,
        .response = &cbrCloudResponsePassthrough,
        .header = &cbrCloudHeaderPassthrough,
        .body = &cbrCloudBodyPassthrough,
        .disconnect = &cbrCloudServerDiscoPassthrough};

    return cbr;
}

void cbrCloudResponsePassthrough(void *src_ctx, HttpClientContext *cloud_ctx)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    char line[128];

    // This is fine: https://www.youtube.com/watch?v=0oBx7Jg4m-o
    osSprintf(line, "HTTP/%u.%u %u This is fine\r\n", MSB(cloud_ctx->version), LSB(cloud_ctx->version), cloud_ctx->statusCode);
    httpSend(ctx->connection, line, osStrlen(line), HTTP_FLAG_DELAY);
    ctx->status = PROX_STATUS_CONN;
}

void cbrCloudHeaderPassthrough(void *src_ctx, HttpClientContext *cloud_ctx, const char *header, const char *value)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;

    switch (ctx->api)
    {
    case V1_FRESHNESS_CHECK:
        if (!header || osStrcmp(header, "Content-Length") == 0) // Skip empty line at the and + contentlen
        {
            break;
        }
    default:
        char line[128];
        if (header)
        {
            TRACE_INFO(">> cbrCloudHeaderPassthrough: %s = %s\r\n", header, value);
            osSprintf(line, "%s: %s\r\n", header, value);
        }
        else
        {
            TRACE_INFO(">> cbrCloudHeaderPassthrough: NULL\r\n");
            osStrcpy(line, "\r\n");
        }

        httpSend(ctx->connection, line, osStrlen(line), HTTP_FLAG_DELAY);
        break;
    }
    ctx->status = PROX_STATUS_HEAD;
}

bool fillCbrBodyCache(cbr_ctx_t *ctx, HttpClientContext *httpClientContext, const char *payload, size_t length)
{
    if (ctx->bufferPos == 0)
    {
        ctx->bufferLen = httpClientContext->bodyLen; // ctx->connection->response.contentLength;
        ctx->buffer = osAllocMem(ctx->bufferLen);
    }
    osMemcpy(&ctx->buffer[ctx->bufferPos], payload, length);
    ctx->bufferPos += length;
    return (ctx->bufferPos == ctx->bufferLen);
}

void cbrCloudBodyPassthrough(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    HttpClientContext *httpClientContext = (HttpClientContext *)cloud_ctx;

    // TRACE_INFO(">> cbrCloudBodyPassthrough: %lu received\r\n", length);
    switch (ctx->api)
    {
    case V2_CONTENT:
        if (ctx->client_ctx->settings->cloud.cacheContent && httpClientContext->statusCode == 200)
        {
            // TRACE_INFO(">> cbrCloudBodyPassthrough: %lu received\r\n", length);
            // TRACE_INFO(">> %s\r\n", ctx->uri);
            if (ctx->status == PROX_STATUS_HEAD)
            {
                /* URI is always "/v2/content/xxxxxxxxxx0304E0" where the x's are hex digits. length has to be fixed */
                TRACE_INFO(">> Start caching uri=%s\r\n", ctx->uri);
                // TODO detect partial downloads
                if (strlen(ctx->uri) < 28)
                {
                    TRACE_ERROR(">> ctx->uri is too short\r\n");
                    return;
                }
                char *tmpPath = custom_asprintf("%s.tmp", ctx->tonieInfo->contentPath);

                char *dir = strdup(ctx->tonieInfo->contentPath);
                dir[osStrlen(dir) - 8] = '\0';
                fsCreateDir(dir);

                ctx->file = fsOpenFile(tmpPath, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);

                if (ctx->file == NULL)
                {
                    TRACE_ERROR(">> Could not open file %s\r\n", tmpPath);
                }
                free(tmpPath);
                free(dir);
            }
            if (length > 0 && ctx->file != NULL)
            {
                error_t error = fsWriteFile(ctx->file, (void *)payload, length);
                if (error)
                    TRACE_ERROR(">> fsWriteFile Error: %u\r\n", error);
            }
            if (error == ERROR_END_OF_STREAM)
            {
                fsCloseFile(ctx->file);
                char *tmpPath = custom_asprintf("%s.tmp", ctx->tonieInfo->contentPath);

                fsDeleteFile(ctx->tonieInfo->contentPath);
                fsRenameFile(tmpPath, ctx->tonieInfo->contentPath);
                if (fsFileExists(ctx->tonieInfo->contentPath))
                {
                    TRACE_INFO(">> Successfully cached %s\r\n", ctx->tonieInfo->contentPath);
                }
                else
                {
                    TRACE_ERROR(">> Error caching %s\r\n", ctx->tonieInfo->contentPath);
                }
                free(tmpPath);
            }
        }
        httpSend(ctx->connection, payload, length, HTTP_FLAG_DELAY);
        break;
    case V1_FRESHNESS_CHECK:
        if (ctx->client_ctx->settings->toniebox.overrideCloud && length > 0 && fillCbrBodyCache(ctx, httpClientContext, payload, length))
        {
            TonieFreshnessCheckResponse *freshResp = (TonieFreshnessCheckResponse *)ctx->customData;
            TonieFreshnessCheckResponse *freshRespCloud = tonie_freshness_check_response__unpack(NULL, ctx->bufferLen, (const uint8_t *)ctx->buffer);
            if (ctx->client_ctx->settings->toniebox.overrideCloud)
            {
                setTonieboxSettings(freshResp, ctx->client_ctx->settings);
            }
            else
            {
                freshResp->max_vol_spk = freshRespCloud->max_vol_spk;
                freshResp->max_vol_hdp = freshRespCloud->max_vol_hdp;
                freshResp->slap_en = freshRespCloud->slap_en;
                freshResp->slap_dir = freshRespCloud->slap_dir;
                freshResp->led = freshRespCloud->led;
                freshResp->field2 = freshRespCloud->field2;
                freshResp->field6 = freshRespCloud->field6;
            }

            for (size_t i = 0; i < freshRespCloud->n_tonie_marked; i++)
            {
                bool found = false;
                for (size_t j = 0; j < freshResp->n_tonie_marked; j++)
                {
                    if (freshRespCloud->tonie_marked[i] == freshResp->tonie_marked[j])
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    // handleCloudFreshnessCheck allocated space for all in freshResp.tonie_marked
                    if (ctx->customDataLen > freshResp->n_tonie_marked)
                    {
                        freshResp->tonie_marked[freshResp->n_tonie_marked++] = freshRespCloud->tonie_marked[i];
                        TRACE_INFO("Marked UID %016" PRIX64 " as updated from cloud\r\n", freshRespCloud->tonie_marked[i]);
                    }
                    else
                    {
                        TRACE_WARNING("Could not add UID %016" PRIX64 " to freshnessCheck response, as not enough slots allocated!\r\n", freshRespCloud->tonie_marked[i]);
                    }
                }
            }
            tonie_freshness_check_response__free_unpacked(freshRespCloud, NULL);

            size_t packSize = tonie_freshness_check_response__get_packed_size(freshResp);
            if (ctx->bufferLen < packSize)
            {
                osFreeMem(ctx->buffer);
                ctx->bufferLen = packSize;
                ctx->buffer = osAllocMem(ctx->bufferLen);
            }
            tonie_freshness_check_response__pack(freshResp, (uint8_t *)ctx->buffer);

            char line[128];
            osSnprintf(line, 128, "Content-Length: %" PRIuSIZE "\r\n\r\n", ctx->bufferLen);
            httpSend(ctx->connection, line, osStrlen(line), HTTP_FLAG_DELAY);

            httpSend(ctx->connection, ctx->buffer, ctx->bufferLen, HTTP_FLAG_DELAY);
            osFreeMem(ctx->buffer);
        }
        else
        {
            httpSend(ctx->connection, payload, length, HTTP_FLAG_DELAY);
        }
        break;
    default:
        httpSend(ctx->connection, payload, length, HTTP_FLAG_DELAY);
        break;
    }
    ctx->status = PROX_STATUS_BODY;
}

void cbrCloudServerDiscoPassthrough(void *src_ctx, HttpClientContext *cloud_ctx)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    TRACE_INFO(">> cbrCloudServerDiscoPassthrough\r\n");
    httpFlushStream(ctx->connection);
    ctx->status = PROX_STATUS_DONE;
}

char *strupr(char input[])
{
    for (uint16_t i = 0; input[i]; i++)
    {
        input[i] = toupper(input[i]);
    }
    return input;
}

void getContentPathFromCharRUID(char ruid[17], char **pcontentPath, settings_t *settings)
{
    char filePath[18];
    osSprintf(filePath, "%.8s/%.8s", ruid, &ruid[8]);
    strupr(filePath);

    *pcontentPath = custom_asprintf("%s/%s", settings->internal.contentdirfull, filePath);
}

void getContentPathFromUID(uint64_t uid, char **pcontentPath, settings_t *settings)
{
    uint16_t cuid[9];
    osSprintf((char *)cuid, "%016" PRIX64 "", uid);
    uint16_t cruid[9];
    for (uint8_t i = 0; i < 8; i++)
    {
        cruid[i] = cuid[7 - i];
    }
    cruid[8] = 0;
    getContentPathFromCharRUID((char *)cruid, pcontentPath, settings);
}

void setTonieboxSettings(TonieFreshnessCheckResponse *freshResp, settings_t *settings)
{
    freshResp->max_vol_spk = settings->toniebox.max_vol_spk;
    freshResp->max_vol_hdp = settings->toniebox.max_vol_hdp;
    freshResp->slap_en = settings->toniebox.slap_enabled;
    freshResp->slap_dir = settings->toniebox.slap_back_left;
    freshResp->led = settings->toniebox.led;
}

bool_t isValidTaf(const char *contentPath)
{
    bool_t valid = false;
    FsFile *file = fsOpenFile(contentPath, FS_FILE_MODE_READ);
    if (file)
    {
        uint8_t headerBuffer[TAF_HEADER_SIZE];
        size_t read_length;
        fsReadFile(file, headerBuffer, 4, &read_length);
        if (read_length == 4)
        {
            uint32_t protobufSize = (uint32_t)((headerBuffer[0] << 24) | (headerBuffer[1] << 16) | (headerBuffer[2] << 8) | headerBuffer[3]);
            if (protobufSize <= TAF_HEADER_SIZE)
            {
                fsReadFile(file, headerBuffer, protobufSize, &read_length);
                if (read_length == protobufSize)
                {
                    TonieboxAudioFileHeader *tafHeader = toniebox_audio_file_header__unpack(NULL, protobufSize, (const uint8_t *)headerBuffer);
                    if (tafHeader)
                    {
                        if (tafHeader->sha1_hash.len == 20)
                        {
                            valid = true;
                        }
                        toniebox_audio_file_header__free_unpacked(tafHeader, NULL);
                    }
                }
            }
        }
        fsCloseFile(file);
    }
    return valid;
}

tonie_info_t *getTonieInfoFromUid(uint64_t uid, settings_t *settings)
{
    char *contentPath;
    getContentPathFromUID(uid, &contentPath, settings);
    tonie_info_t *tonieInfo = getTonieInfo(contentPath, settings);
    osFreeMem(contentPath);
    return tonieInfo;
}
tonie_info_t *getTonieInfoFromRuid(char ruid[17], settings_t *settings)
{
    char *contentPath;
    getContentPathFromCharRUID(ruid, &contentPath, settings);
    tonie_info_t *tonieInfo = getTonieInfo(contentPath, settings);
    osFreeMem(contentPath);
    return tonieInfo;
}
tonie_info_t *getTonieInfo(const char *contentPath, settings_t *settings)
{
    tonie_info_t *tonieInfo;
    tonieInfo = osAllocMem(sizeof(tonie_info_t));

    tonieInfo->valid = false;
    tonieInfo->updated = false;
    tonieInfo->stream = false;
    tonieInfo->tafHeader = NULL;
    tonieInfo->contentPath = strdup(contentPath);
    tonieInfo->exists = false;
    osMemset(&tonieInfo->json, 0, sizeof(contentJson_t));

    if (osStrstr(contentPath, ".json") == NULL)
    {
        if (osStrstr(contentPath, settings->internal.contentdirfull) == contentPath &&
            (contentPath[osStrlen(settings->internal.contentdirfull)] == '/' || contentPath[osStrlen(settings->internal.contentdirfull)] == '\\') &&
            osStrlen(contentPath) - 18 == osStrlen(settings->internal.contentdirfull))
        {
            // TODO: Nice checking if valid tonie path
            load_content_json_settings(contentPath, &tonieInfo->json, true, settings);
        }

        if (tonieInfo->json._source_is_taf)
        {
            osFreeMem(tonieInfo->contentPath);
            tonieInfo->contentPath = strdup(tonieInfo->json._source_resolved);
        }
        tonieInfo->exists = fsFileExists(tonieInfo->contentPath);

        FsFile *file = fsOpenFile(tonieInfo->contentPath, FS_FILE_MODE_READ);
        if (file)
        {
            uint8_t headerBuffer[TAF_HEADER_SIZE];
            size_t read_length;
            fsReadFile(file, headerBuffer, 4, &read_length);
            if (read_length == 4)
            {
                uint32_t protobufSize = (uint32_t)((headerBuffer[0] << 24) | (headerBuffer[1] << 16) | (headerBuffer[2] << 8) | headerBuffer[3]);
                if (protobufSize <= TAF_HEADER_SIZE)
                {
                    fsReadFile(file, headerBuffer, protobufSize, &read_length);
                    if (read_length == protobufSize)
                    {
                        tonieInfo->tafHeader = toniebox_audio_file_header__unpack(NULL, protobufSize, (const uint8_t *)headerBuffer);
                        if (tonieInfo->tafHeader)
                        {
                            if (tonieInfo->tafHeader->sha1_hash.len == 20)
                            {
                                tonieInfo->valid = true;
                                if (tonieInfo->tafHeader->num_bytes == TONIE_LENGTH_MAX)
                                {
                                    tonieInfo->stream = true;
                                }
                                else if (!tonieInfo->json._source_is_taf)
                                {
                                    content_json_update_model(&tonieInfo->json, tonieInfo->tafHeader->audio_id, tonieInfo->tafHeader->sha1_hash.data);
                                }
                            }
                            else
                            {
                                TRACE_WARNING("Invalid TAF-header on %s, sha1_hash.len=%" PRIuSIZE " != 20\r\n", tonieInfo->contentPath, tonieInfo->tafHeader->sha1_hash.len);
                            }
                        }
                    }
                    else
                    {
                        TRACE_WARNING("Invalid TAF-header on %s, read_length=%" PRIuSIZE " != protobufSize=%" PRIu32 "\r\n", tonieInfo->contentPath, read_length, protobufSize);
                    }
                }
                else
                {
                    TRACE_WARNING("Invalid TAF-header on %s, protobufSize=%" PRIu32 " >= TAF_HEADER_SIZE=%u\r\n", tonieInfo->contentPath, protobufSize, TAF_HEADER_SIZE);
                }
            }
            else if (read_length == 0)
            {
                // TODO don't send invalid TAF files via API
                TRACE_VERBOSE("Invalid TAF-header, file %s is empty!", tonieInfo->contentPath);
            }
            else
            {
                TRACE_WARNING("Invalid TAF-header on %s, Could not read 4 bytes, read_length=%" PRIuSIZE "\r\n", tonieInfo->contentPath, read_length);
            }
            fsCloseFile(file);
        }
    }
    return tonieInfo;
}

void freeTonieInfo(tonie_info_t *tonieInfo)
{
    if (tonieInfo->json._updated)
    {
        save_content_json(tonieInfo->contentPath, &tonieInfo->json);
    }

    if (tonieInfo->tafHeader)
    {
        toniebox_audio_file_header__free_unpacked(tonieInfo->tafHeader, NULL);
        tonieInfo->tafHeader = NULL;
    }
    if (tonieInfo->contentPath)
    {
        osFreeMem(tonieInfo->contentPath);
        tonieInfo->contentPath = NULL;
    }

    if (tonieInfo->valid)
    {
        free_content_json(&tonieInfo->json);
    }
    free(tonieInfo);
}

void httpPrepareHeader(HttpConnection *connection, const void *contentType, size_t contentLength)
{
    httpInitResponseHeader(connection);
    connection->response.keepAlive = true;
    connection->response.chunkedEncoding = false;
    connection->response.contentType = contentType;
    connection->response.contentLength = contentLength;
}
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
        osFreeMem(data);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send payload: %d\r\n", error);
        return error;
    }

    // can fail, when stream is already closed
    httpFlushStream(connection);
    /*
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to close: %d\r\n", error);
        return error;
    }
    */

    return error;
}

error_t httpWriteString(HttpConnection *connection, const char_t *content)
{
    return httpWriteStream(connection, content, osStrlen(content));
}

error_t httpFlushStream(HttpConnection *connection)
{
    return httpCloseStream(connection);
}

void setLastUid(uint64_t uid, settings_t *settings)
{
    uint16_t cuid[9];
    osSprintf((char *)cuid, "%016" PRIX64 "", uid);
    uint16_t cruid[9];
    for (uint8_t i = 0; i < 8; i++)
    {
        cruid[i] = cuid[7 - i];
    }
    cruid[8] = 0;

    setLastRuid((char *)cruid, settings);
}
void setLastRuid(char ruid[17], settings_t *settings)
{
    char *last_ruid = settings->internal.last_ruid;
    osStrcpy(last_ruid, ruid);
    for (size_t i = 0; last_ruid[i] != '\0'; i++)
    {
        last_ruid[i] = tolower(last_ruid[i]);
    }
    if (get_settings() != settings)
    {
        osStrcpy(get_settings()->internal.last_ruid, last_ruid);
    }
}
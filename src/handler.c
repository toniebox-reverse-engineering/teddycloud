#include "handler.h"
#include "server_helpers.h"
#include "toniesJson.h"

req_cbr_t getCloudCbr(HttpConnection *connection, const char_t *uri, const char_t *queryString, cloudapi_t api, cbr_ctx_t *ctx, client_ctx_t *client_ctx)
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
                char ruid[17];
                osStrncpy(ruid, &ctx->uri[12], sizeof(ruid));
                ruid[16] = 0;
                getContentPathFromCharRUID(ruid, &ctx->tonieInfo.contentPath, ctx->client_ctx->settings);
                ctx->tonieInfo = getTonieInfo(ctx->tonieInfo.contentPath, ctx->client_ctx->settings);

                char *tmpPath = custom_asprintf("%s.tmp", ctx->tonieInfo.contentPath);

                char *dir = strdup(ctx->tonieInfo.contentPath);
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
                char *tmpPath = custom_asprintf("%s.tmp", ctx->tonieInfo.contentPath);

                fsDeleteFile(ctx->tonieInfo.contentPath);
                fsRenameFile(tmpPath, ctx->tonieInfo.contentPath);
                if (fsFileExists(ctx->tonieInfo.contentPath))
                {
                    TRACE_INFO(">> Successfully cached %s\r\n", ctx->tonieInfo.contentPath);
                }
                else
                {
                    TRACE_ERROR(">> Error caching %s\r\n", ctx->tonieInfo.contentPath);
                }
                free(tmpPath);
            }
            if (error != NO_ERROR)
            {
                freeTonieInfo(&ctx->tonieInfo);
            }
        }
        httpSend(ctx->connection, payload, length, HTTP_FLAG_DELAY);
        break;
    case V1_FRESHNESS_CHECK:
        if (ctx->client_ctx->settings->toniebox.overrideCloud && length > 0 && fillCbrBodyCache(ctx, httpClientContext, payload, length))
        {
            TonieFreshnessCheckResponse *freshResp = tonie_freshness_check_response__unpack(NULL, ctx->bufferLen, (const uint8_t *)ctx->buffer);
            setTonieboxSettings(freshResp, ctx->client_ctx->settings);
            size_t packSize = tonie_freshness_check_response__get_packed_size(freshResp);

            // TODO: Check if size is stable and this is obsolete
            // TODO Add live tonies here, too : freshResp.tonie_marked
            if (ctx->bufferLen < packSize)
            {
                TRACE_WARNING(">> cbrCloudBodyPassthrough V1_FRESHNESS_CHECK: %zu / %zu\r\n", ctx->bufferLen, packSize);
                osFreeMem(ctx->buffer);
                ctx->bufferLen = packSize;
                ctx->buffer = osAllocMem(ctx->bufferLen);
            }
            tonie_freshness_check_response__pack(freshResp, (uint8_t *)ctx->buffer);
            tonie_freshness_check_response__free_unpacked(freshResp, NULL);
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

tonie_info_t getTonieInfo(const char *contentPath, settings_t *settings)
{
    tonie_info_t tonieInfo;

    tonieInfo.valid = false;
    tonieInfo.updated = false;
    tonieInfo.stream = false;
    tonieInfo.tafHeader = NULL;
    tonieInfo.contentPath = strdup(contentPath);
    tonieInfo.exists = fsFileExists(contentPath);

    tonieInfo.contentConfig.live = false;
    tonieInfo.contentConfig.nocloud = false;
    tonieInfo.contentConfig.source = NULL;
    tonieInfo.contentConfig.skip_seconds = 0;
    tonieInfo.contentConfig.cache = false;
    tonieInfo.contentConfig._updated = false;
    tonieInfo.contentConfig._stream = false;
    tonieInfo.contentConfig._streamFile = custom_asprintf("%s.stream", contentPath);
    tonieInfo.contentConfig.cloud_ruid = NULL;
    tonieInfo.contentConfig.cloud_auth = NULL;
    tonieInfo.contentConfig.cloud_auth_len = 0;

    if (osStrstr(contentPath, ".json") == NULL)
    {
        if (osStrstr(contentPath, settings->internal.contentdirfull) == contentPath &&
            (contentPath[osStrlen(settings->internal.contentdirfull)] == '/' || contentPath[osStrlen(settings->internal.contentdirfull)] == '\\') &&
            osStrlen(contentPath) - 18 == osStrlen(settings->internal.contentdirfull))
        {
            // TODO: Nice checking if valid tonie path
            load_content_json(contentPath, &tonieInfo.contentConfig);
        }

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
                        tonieInfo.tafHeader = toniebox_audio_file_header__unpack(NULL, protobufSize, (const uint8_t *)headerBuffer);
                        if (tonieInfo.tafHeader)
                        {
                            tonieInfo.valid = true;
                            toniesJson_item_t *toniesJson = tonies_byAudioId(tonieInfo.tafHeader->audio_id);
                            if (toniesJson != NULL)
                            {
                                if (osStrcmp(tonieInfo.contentConfig.tonie_model, toniesJson->model) != 0)
                                {
                                    if (tonieInfo.contentConfig.tonie_model != NULL)
                                    {
                                        osFreeMem(tonieInfo.contentConfig.tonie_model);
                                    }
                                    tonieInfo.contentConfig.tonie_model = strdup(toniesJson->model);
                                    tonieInfo.contentConfig._updated = true;
                                }
                            }
                            else if (tonieInfo.contentConfig.tonie_model != NULL)
                            {
                                // TODO add to tonies.custom.json + report
                            }

                            if (tonieInfo.tafHeader->num_bytes == TONIE_LENGTH_MAX)
                            {
                                tonieInfo.stream = true;
                            }
                        }
                    }
                    else
                    {
                        TRACE_WARNING("Invalid TAF-header on %s, read_length=%" PRIuSIZE " != protobufSize=%" PRIu32 "\r\n", contentPath, read_length, protobufSize);
                    }
                }
                else
                {
                    TRACE_WARNING("Invalid TAF-header on %s, protobufSize=%" PRIu32 " >= TAF_HEADER_SIZE=%u\r\n", contentPath, protobufSize, TAF_HEADER_SIZE);
                }
            }
            else if (read_length == 0)
            {
                // TODO don't send invalid TAF files via API
                TRACE_VERBOSE("Invalid TAF-header, file %s is empty!", contentPath);
            }
            else
            {
                TRACE_WARNING("Invalid TAF-header on %s, Could not read 4 bytes, read_length=%" PRIuSIZE "\r\n", contentPath, read_length);
            }
            fsCloseFile(file);
        }
    }
    return tonieInfo;
}

void freeTonieInfo(tonie_info_t *tonieInfo)
{
    if (tonieInfo->contentConfig._updated)
    {
        save_content_json(tonieInfo->contentPath, &tonieInfo->contentConfig);
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
        free_content_json(&tonieInfo->contentConfig);
    }
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
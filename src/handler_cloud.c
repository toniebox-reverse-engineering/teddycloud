#include <time.h>
#include <stdbool.h>
#include <string.h>

#include "settings.h"

#include "handler.h"
#include "handler_api.h"
#include "handler_cloud.h"
#include "http/http_client.h"

#include "cloud_request.h"
#include "proto/toniebox.pb.freshness-check.fc-request.pb-c.h"
#include "proto/toniebox.pb.freshness-check.fc-response.pb-c.h"

#define PROX_STATUS_IDLE 0
#define PROX_STATUS_CONN 1
#define PROX_STATUS_HEAD 2
#define PROX_STATUS_BODY 3
#define PROX_STATUS_DONE 4

typedef enum
{
    NONE = 0,
    V1_TIME,
    V1_OTA,
    V1_CLAIM,
    V2_CONTENT,
    V1_FRESHNESS_CHECK,
    V1_LOG,
    V1_CLOUDRESET
} cloudapi_t;

typedef enum
{
    OTA_FIRMWARE_PD = 2,
    OTA_FIRMWARE_EU = 3,
    OTA_SERVICEPACK_CC3200 = 4,
    OTA_HTML_CONFIG = 5,
    OTA_SFX_BIN = 6,
} cloudapi_ota_t;

typedef struct
{
    const char_t *uri;
    const char_t *queryString;
    cloudapi_t api;
    char_t *buffer;
    size_t bufferPos;
    size_t bufferLen;
    uint32_t status;
    FsFile *file;
    tonie_info_t tonieInfo;
    HttpConnection *connection;
    client_ctx_t *client_ctx;
} cbr_ctx_t;

static void setTonieboxSettings(TonieFreshnessCheckResponse *freshResp, settings_t *settings);
static void setTonieboxSettings(TonieFreshnessCheckResponse *freshResp, settings_t *settings)
{
    freshResp->max_vol_spk = settings->toniebox.max_vol_spk;
    freshResp->max_vol_hdp = settings->toniebox.max_vol_hdp;
    freshResp->slap_en = settings->toniebox.slap_enabled;
    freshResp->slap_dir = settings->toniebox.slap_back_left;
    freshResp->led = settings->toniebox.led;
}

static void cbrCloudResponsePassthrough(void *src_ctx, void *cloud_ctx);
static void cbrCloudHeaderPassthrough(void *src_ctx, void *cloud_ctx, const char *header, const char *value);
static void cbrCloudBodyPassthrough(void *src_ctx, void *cloud_ctx, const char *payload, size_t length, error_t error);
static void cbrCloudServerDiscoPassthrough(void *src_ctx, void *cloud_ctx);

static char *strupr(char input[]);

static void cbrCloudResponsePassthrough(void *src_ctx, void *cloud_ctx)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    char line[128];

    // This is fine: https://www.youtube.com/watch?v=0oBx7Jg4m-o
    osSprintf(line, "HTTP/%u.%u %u This is fine\r\n", MSB(ctx->connection->response.version), LSB(ctx->connection->response.version), ctx->connection->response.statusCode);
    httpSend(ctx->connection, line, osStrlen(line), HTTP_FLAG_DELAY);
    ctx->status = PROX_STATUS_CONN;
}

static void cbrCloudHeaderPassthrough(void *src_ctx, void *cloud_ctx, const char *header, const char *value)
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

static bool fillCbrBodyCache(cbr_ctx_t *ctx, HttpClientContext *httpClientContext, const char *payload, size_t length)
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

static void cbrCloudBodyPassthrough(void *src_ctx, void *cloud_ctx, const char *payload, size_t length, error_t error)
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
                char tmpPath[34];
                ctx->tonieInfo = getTonieInfo(ctx->tonieInfo.contentPath);
                osMemcpy(tmpPath, ctx->tonieInfo.contentPath, 30);
                tmpPath[29] = 0;
                osStrcat(tmpPath, ".tmp");
                tmpPath[20] = 0;
                fsCreateDir(tmpPath);
                tmpPath[20] = '/';
                ctx->file = fsOpenFile(tmpPath, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
            }
            if (length > 0)
            {
                error_t error = fsWriteFile(ctx->file, (void *)payload, length);
                if (error)
                    TRACE_ERROR(">> fsWriteFile Error: %u\r\n", error);
            }
            if (error == ERROR_END_OF_STREAM)
            {
                fsCloseFile(ctx->file);
                char tmpPath[34];
                osMemcpy(tmpPath, ctx->tonieInfo.contentPath, 30);
                tmpPath[29] = 0;
                osStrcat(tmpPath, ".tmp");
                fsDeleteFile(ctx->tonieInfo.contentPath);
                fsRenameFile(tmpPath, ctx->tonieInfo.contentPath);
                TRACE_INFO(">> Successfully cached %s\r\n", ctx->tonieInfo.contentPath);
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

static void cbrCloudServerDiscoPassthrough(void *src_ctx, void *cloud_ctx)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    TRACE_INFO(">> cbrCloudServerDiscoPassthrough\r\n");
    ctx->status = PROX_STATUS_DONE;
}

static req_cbr_t getCloudCbr(HttpConnection *connection, const char_t *uri, const char_t *queryString, cloudapi_t api, cbr_ctx_t *ctx, client_ctx_t *client_ctx);

static req_cbr_t getCloudCbr(HttpConnection *connection, const char_t *uri, const char_t *queryString, cloudapi_t api, cbr_ctx_t *ctx, client_ctx_t *client_ctx)
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

void getContentPathFromCharRUID(char ruid[17], char **pcontentPath, settings_t *settings)
{
    *pcontentPath = osAllocMem(256);
    char filePath[18];
    osSprintf(filePath, "%.8s/%.8s", ruid, &ruid[8]);
    strupr(filePath);

    osSprintf(*pcontentPath, "%s/%s", settings->internal.contentdirfull, filePath);
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

tonie_info_t getTonieInfo(const char *contentPath)
{
    tonie_info_t tonieInfo;
    int maxLen = strlen(contentPath) + 32;
    char *checkFile = (char *)osAllocMem(maxLen + 1);

    checkFile[maxLen] = 0;
    tonieInfo.valid = false;
    tonieInfo.tafHeader = NULL;
    tonieInfo.contentPath = strdup(contentPath);
    snprintf(checkFile, maxLen, "%s", contentPath);
    tonieInfo.exists = fsFileExists(checkFile);
    snprintf(checkFile, maxLen, "%s.nocloud", contentPath);
    tonieInfo.nocloud = fsFileExists(checkFile);
    snprintf(checkFile, maxLen, "%s.live", contentPath);
    tonieInfo.live = fsFileExists(checkFile);
    osFreeMem(checkFile);

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
                        tonieInfo.valid = true;
                }
                else
                {
                    TRACE_WARNING("Invalid TAF-header, read_length=%" PRIuSIZE " != protobufSize=%" PRIu32 "\r\n", read_length, protobufSize);
                }
            }
            else
            {
                TRACE_WARNING("Invalid TAF-header, protobufSize=%" PRIu32 " >= TAF_HEADER_SIZE=%u\r\n", protobufSize, TAF_HEADER_SIZE);
            }
        }
        else
        {
            TRACE_WARNING("Invalid TAF-header, Could not read 4 bytes, read_length=%" PRIuSIZE "\r\n", read_length);
        }
        fsCloseFile(file);
    }
    return tonieInfo;
}

void freeTonieInfo(tonie_info_t *tonieInfo)
{
    toniebox_audio_file_header__free_unpacked(tonieInfo->tafHeader, NULL);
    free(tonieInfo->contentPath);
    tonieInfo->contentPath = NULL;
    tonieInfo->tafHeader = NULL;
}

void httpPrepareHeader(HttpConnection *connection, const void *contentType, size_t contentLength)
{
    httpInitResponseHeader(connection);
    connection->response.keepAlive = true;
    connection->response.chunkedEncoding = false;
    connection->response.contentType = contentType;
    connection->response.contentLength = contentLength;
}

error_t handleCloudTime(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    TRACE_INFO(" >> respond with current time\r\n");

    char response[32];

    if (!settings_get_bool("cloud.enabled") || !settings_get_bool("cloud.enableV1Time"))
    {
        osSprintf(response, "%" PRIuTIME, time(NULL));
    }
    else
    {
        cbr_ctx_t ctx;
        req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V1_TIME, &ctx, client_ctx);
        if (!cloud_request_get(NULL, 0, uri, queryString, NULL, &cbr))
        {
            return NO_ERROR;
        }
        else
        {
            osSprintf(response, "%" PRIuTIME, time(NULL));
        }
    }

    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(response));
    return httpWriteResponseString(connection, response, false);
}

error_t handleCloudOTA(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    error_t ret = NO_ERROR;
    char *query = strdup(connection->request.queryString);
    char *localUri = strdup(uri);
    char *savelocalUri = localUri;
    char *filename = strtok_r(&localUri[8], "?", &savelocalUri);
    char *cv = strpbrk(query, "cv=");
    char *timestampTxt = cv ? strtok_r(&cv[3], "&", &cv) : NULL;

    uint8_t fileId = atoi(filename);
    (void)fileId;
    time_t timestamp = timestampTxt ? atoi(timestampTxt) : 0;

    char date_buffer[32] = "";
    struct tm tm_info;
    if (localtime_r(&timestamp, &tm_info) != 0)
    {
        strftime(date_buffer, sizeof(date_buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
    }

    TRACE_INFO(" >> OTA-Request for %u with timestamp %" PRIuTIME " (%s)\r\n", fileId, timestamp, date_buffer);

    if (settings_get_bool("cloud.enabled") && settings_get_bool("cloud.enableV1Ota"))
    {
        cbr_ctx_t ctx;
        req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V1_OTA, &ctx, client_ctx);
        cloud_request_get(NULL, 0, uri, queryString, NULL, &cbr);
    }
    else
    {
        httpPrepareHeader(connection, NULL, 0);
        connection->response.statusCode = 304; // No new firmware
        ret = httpWriteResponse(connection, NULL, 0, false);
    }

    free(query);
    free(localUri);

    return ret;
}

bool checkCustomTonie(char *ruid, uint8_t *token, settings_t *settings)
{
    if (settings->cloud.markCustomTagByPass)
    {
        bool tokenIsZero = TRUE;
        for (uint8_t i = 0; i < 32; i++)
        {
            if (token[i] != 0)
            {
                tokenIsZero = FALSE;
                break;
            }
        }
        if (tokenIsZero)
        {
            TRACE_INFO("Found possible custom tonie by password\r\n");
            return true;
        }
    }
    if (settings->cloud.markCustomTagByUid &&
        (ruid[15] != '0' || ruid[14] != 'e' || ruid[13] != '4' || ruid[12] != '0' || ruid[11] != '3' || ruid[10] != '0'))
    {
        TRACE_INFO("Found possible custom tonie by uid\r\n");
        return true;
    }
    return false;
}
void markCustomTonie(tonie_info_t *tonieInfo)
{
    int maxLen = 255;
    char subDir[256];
    char contentPathDot[256];

    snprintf(subDir, maxLen, "%s", tonieInfo->contentPath);
    subDir[osStrlen(subDir) - 8] = '\0';
    snprintf(contentPathDot, maxLen, "%s.nocloud", tonieInfo->contentPath);

    fsCreateDir(subDir);

    FsFile *file = fsOpenFile(contentPathDot, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE);
    fsCloseFile(file);
    TRACE_INFO("Marked custom tonie with file %s\r\n", contentPathDot);
}

error_t handleCloudLog(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (settings_get_bool("cloud.enabled") && settings_get_bool("cloud.enableV1Log"))
    {
        cbr_ctx_t ctx;
        req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V1_LOG, &ctx, client_ctx);
        cloud_request_get(NULL, 0, uri, queryString, NULL, &cbr);
    }
    return NO_ERROR;
}

error_t handleCloudClaim(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char ruid[17];
    uint8_t *token = connection->private.authentication_token;

    osStrncpy(ruid, &uri[10], sizeof(ruid));
    ruid[16] = 0;

    if (osStrlen(ruid) != 16)
    {
        TRACE_WARNING(" >>  invalid URI\r\n");
    }
    TRACE_INFO(" >> client requested rUID %s\r\n", ruid);
    TRACE_INFO(" >> client authenticated with %02X%02X%02X%02X...\r\n", token[0], token[1], token[2], token[3]);

    tonie_info_t tonieInfo;
    getContentPathFromCharRUID(ruid, &tonieInfo.contentPath, client_ctx->settings);
    tonieInfo = getTonieInfo(tonieInfo.contentPath);

    if (!tonieInfo.nocloud && checkCustomTonie(ruid, token, client_ctx->settings))
    {
        tonieInfo.nocloud = true;
        markCustomTonie(&tonieInfo);
    }

    if (settings_get_bool("cloud.enabled") && settings_get_bool("cloud.enableV1Claim") && !tonieInfo.nocloud)
    {
        cbr_ctx_t ctx;
        req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V1_CLAIM, &ctx, client_ctx);
        cloud_request_get(NULL, 0, uri, queryString, token, &cbr);
    }
    freeTonieInfo(&tonieInfo);

    return NO_ERROR;
}

char *strupr(char input[])
{
    for (uint16_t i = 0; input[i]; i++)
    {
        input[i] = toupper(input[i]);
    }
    return input;
}

error_t handleCloudContent(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx, bool_t noPassword)
{
    char ruid[17];
    error_t error = NO_ERROR;
    uint8_t *token = connection->private.authentication_token;

    osStrncpy(ruid, &uri[12], sizeof(ruid));
    ruid[16] = 0;

    if (connection->request.Range.start != 0)
    {
        TRACE_INFO(" >> client requested partial download\r\n");
    }

    if (osStrlen(ruid) != 16)
    {
        TRACE_WARNING(" >>  invalid URI\r\n");
    }
    TRACE_INFO(" >> client requested rUID %s\r\n", ruid);
    TRACE_INFO(" >> client authenticated with %02X%02X%02X%02X...\r\n", token[0], token[1], token[2], token[3]);

    tonie_info_t tonieInfo;
    getContentPathFromCharRUID(ruid, &tonieInfo.contentPath, client_ctx->settings);
    tonieInfo = getTonieInfo(tonieInfo.contentPath);

    if (!tonieInfo.nocloud && !noPassword && checkCustomTonie(ruid, token, client_ctx->settings))
    {
        tonieInfo.nocloud = true;
        markCustomTonie(&tonieInfo);
    }

    if (tonieInfo.exists)
    {
        connection->response.keepAlive = true;
        error_t error = httpSendResponse(connection, &tonieInfo.contentPath[4]);
        if (error)
        {
            TRACE_ERROR(" >> file %s not available or not send, error=%u...\r\n", tonieInfo.contentPath, error);
        }
    }
    else
    {
        if (!settings_get_bool("cloud.enabled") || !settings_get_bool("cloud.enableV2Content") || tonieInfo.nocloud)
        {
            if (tonieInfo.nocloud)
            {
                TRACE_INFO("Content marked as no cloud and no content locally available\r\n");
            }
            else
            {
                TRACE_INFO("No local content available and cloud access disabled\r\n");
            }
            httpPrepareHeader(connection, NULL, 0);
            connection->response.statusCode = 404;
            error = httpWriteResponse(connection, NULL, 0, false);
        }
        else
        {
            connection->response.keepAlive = true;
            cbr_ctx_t ctx;
            req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V2_CONTENT, &ctx, client_ctx);
            cloud_request_get(NULL, 0, uri, queryString, token, &cbr);
        }
    }
    freeTonieInfo(&tonieInfo);
    return error;
}
error_t handleCloudContentV1(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    return handleCloudContent(connection, uri, queryString, client_ctx, TRUE);
}
error_t handleCloudContentV2(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (connection->request.auth.found && connection->request.auth.mode == HTTP_AUTH_MODE_DIGEST)
    {
        return handleCloudContent(connection, uri, queryString, client_ctx, FALSE);
    }
    else
    {
        TRACE_WARNING("Missing auth for content v2: %s", uri);
    }
    return NO_ERROR;
}

error_t handleCloudFreshnessCheck(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    uint8_t data[BODY_BUFFER_SIZE];
    size_t size;
    if (BODY_BUFFER_SIZE <= connection->request.byteCount)
    {
        TRACE_ERROR("Body size %zu bigger than buffer size %i bytes", connection->request.byteCount, BODY_BUFFER_SIZE);
    }
    else
    {
        error_t error = httpReceive(connection, &data, BODY_BUFFER_SIZE, &size, 0x00);
        if (error != NO_ERROR)
        {
            TRACE_ERROR("httpReceive failed!");
            return error;
        }
        TRACE_INFO("Content (%zu of %zu)\n", size, connection->request.byteCount);
        TonieFreshnessCheckRequest *freshReq = tonie_freshness_check_request__unpack(NULL, size, (const uint8_t *)data);
        if (freshReq == NULL)
        {
            TRACE_ERROR("Unpacking freshness request failed!\r\n");
        }
        else
        {
            TRACE_INFO("Found %zu tonies:\n", freshReq->n_tonie_infos);
            TonieFreshnessCheckResponse freshResp = TONIE_FRESHNESS_CHECK_RESPONSE__INIT;
            freshResp.n_tonie_marked = 0;
            freshResp.tonie_marked = malloc(sizeof(uint64_t) * freshReq->n_tonie_infos);

            TonieFreshnessCheckRequest freshReqCloud = TONIE_FRESHNESS_CHECK_REQUEST__INIT;
            freshReqCloud.n_tonie_infos = 0;
            freshReqCloud.tonie_infos = malloc(sizeof(TonieFCInfo *) * freshReq->n_tonie_infos);

            for (uint16_t i = 0; i < freshReq->n_tonie_infos; i++)
            {
                struct tm tm_info;
                char date_buffer[32];
                bool_t custom = false;
                time_t unix_time = freshReq->tonie_infos[i]->audio_id;

                if (unix_time < 0x0e000000)
                {
                    osSprintf(date_buffer, "special");
                }
                else
                {
                    /* custom tonies from TeddyBench have the audio id reduced by a constant */
                    if (unix_time < 0x50000000)
                    {
                        unix_time += 0x50000000;
                        custom = true;
                    }
                    if (localtime_r(&unix_time, &tm_info) == 0)
                    {
                        osSprintf(date_buffer, "(localtime failed)");
                    }
                    else
                    {
                        strftime(date_buffer, sizeof(date_buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
                    }
                }
                tonie_info_t tonieInfo;
                getContentPathFromUID(freshReq->tonie_infos[i]->uid, &tonieInfo.contentPath, client_ctx->settings);
                tonieInfo = getTonieInfo(tonieInfo.contentPath);

                tonieInfo.updated = tonieInfo.valid && (freshReq->tonie_infos[i]->audio_id < tonieInfo.tafHeader->audio_id);

                if (!tonieInfo.nocloud)
                {
                    freshReqCloud.tonie_infos[freshReqCloud.n_tonie_infos++] = freshReq->tonie_infos[i];
                }

                (void)custom;
                TRACE_INFO("  uid: %016" PRIX64 ", nocloud: %d, live: %d, updated: %d, audioid: %08X (%s%s)\n",
                           freshReq->tonie_infos[i]->uid,
                           tonieInfo.nocloud,
                           tonieInfo.live,
                           tonieInfo.updated,
                           freshReq->tonie_infos[i]->audio_id,
                           date_buffer,
                           custom ? ", custom" : "");
                if (tonieInfo.live || tonieInfo.updated)
                {
                    freshResp.tonie_marked[freshResp.n_tonie_marked++] = freshReq->tonie_infos[i]->uid;
                }
                freeTonieInfo(&tonieInfo);
            }

            if (settings_get_bool("cloud.enabled") && settings_get_bool("cloud.enableV1FreshnessCheck"))
            {
                size_t dataLen = tonie_freshness_check_request__get_packed_size(&freshReqCloud);
                tonie_freshness_check_request__pack(&freshReqCloud, (uint8_t *)data);
                tonie_freshness_check_request__free_unpacked(freshReq, NULL);

                osFreeMem(freshReqCloud.tonie_infos);
                osFreeMem(freshResp.tonie_marked);

                cbr_ctx_t ctx;
                req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V1_FRESHNESS_CHECK, &ctx, client_ctx);
                if (!cloud_request_post(NULL, 0, "/v1/freshness-check", queryString, data, dataLen, NULL, &cbr))
                {
                    return NO_ERROR;
                }
            }
            else
            {
                tonie_freshness_check_request__free_unpacked(freshReq, NULL);
            }
            setTonieboxSettings(&freshResp, client_ctx->settings);

            size_t dataLen = tonie_freshness_check_response__get_packed_size(&freshResp);
            tonie_freshness_check_response__pack(&freshResp, (uint8_t *)data);
            osFreeMem(freshReqCloud.tonie_infos);
            osFreeMem(freshResp.tonie_marked);
            TRACE_INFO("Freshness check response: size=%zu, content=%s\n", dataLen, data);

            httpPrepareHeader(connection, "application/octet-stream; charset=utf-8", dataLen);
            return httpWriteResponse(connection, data, dataLen, false);
            // tonie_freshness_check_response__free_unpacked(&freshResp, NULL);
        }
        return NO_ERROR;
    }
    return NO_ERROR;
}

error_t handleCloudReset(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    // EMPTY POST REQUEST?
    if (settings_get_bool("cloud.enabled") && settings_get_bool("cloud.enableV1CloudReset"))
    {
        cbr_ctx_t ctx;
        req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V1_CLOUDRESET, &ctx, client_ctx);
        cloud_request_post(NULL, 0, uri, queryString, NULL, 0, NULL, &cbr);
    }
    else
    {
        httpPrepareHeader(connection, "application/json; charset=utf-8", 2);
        connection->response.keepAlive = false;
        return httpWriteResponseString(connection, "{}", false);
    }
    return NO_ERROR;
}
#include <time.h>
#include <stdbool.h>
#include <string.h>

#include "settings.h"
#include "fs_ext.h"

#include "handler.h"
#include "handler_api.h"
#include "handler_cloud.h"
#include "http/http_client.h"

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
    char *query = strdup(queryString);
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
    subDir[osStrlen(subDir) - 9] = '\0';
    fsCreateDir(subDir);
    snprintf(contentPathDot, maxLen, "%s.nocloud", tonieInfo->contentPath);

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

    settings_t *settings = get_settings();
    if (!tonieInfo.exists && osStrlen(settings->internal.assign_unknown) > 0)
    {
        char *path = settings->internal.assign_unknown;
        if (fsFileExists(path))
        {
            tonie_info_t tonieInfoAssign = getTonieInfo(path);
            if (tonieInfoAssign.valid)
            {
                char *dir = strdup(tonieInfo.contentPath);
                dir[osStrlen(dir) - 8] = '\0';
                fsCreateDir(dir);
                osFreeMem(dir);

                if ((error = fsCopyFile(path, tonieInfo.contentPath, false)) == NO_ERROR)
                {
                    char *oldFile = strdup(tonieInfo.contentPath);
                    freeTonieInfo(&tonieInfo);
                    tonieInfo = getTonieInfo(oldFile);
                    free(oldFile);
                    if (tonieInfo.valid)
                    {
                        TRACE_INFO("Assigned unknown set to %s\r\n", path);
                        settings_set_string("internal.assign_unknown", "");
                    }
                    else
                    {
                        TRACE_ERROR("TAF header of assign unknown invalid, delete it again: %s\r\n", tonieInfo.contentPath)
                        fsDeleteFile(tonieInfo.contentPath);
                    }
                }
                else
                {
                    freeTonieInfo(&tonieInfoAssign);
                    TRACE_ERROR("Could not copy %s to %s, error=%" PRIu32 "\r\n", path, tonieInfo.contentPath, error)
                }
            }
            else
            {
                freeTonieInfo(&tonieInfoAssign);
                TRACE_ERROR("TAF header of assign unknown invalid: %s\r\n", path)
            }
        }
        else
        {
            TRACE_ERROR("Assign unknown path not available: %s\r\n", path)
        }
        error = NO_ERROR;
    }

    if (tonieInfo.exists && tonieInfo.valid)
    {
        TRACE_INFO("Serve local content from %s\r\n", tonieInfo.contentPath);
        connection->response.keepAlive = true;
        error_t error = httpSendResponse(connection, &tonieInfo.contentPath[osStrlen(client_ctx->settings->internal.datadirfull)]);
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
            TRACE_INFO("Serve cloud content from %s\r\n", uri);
            connection->response.keepAlive = true;
            cbr_ctx_t ctx;
            req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V2_CONTENT, &ctx, client_ctx);
            cloud_request_get(NULL, 0, uri, queryString, token, &cbr);
            error = NO_ERROR;
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

#define TEDDY_BENCH_AUDIO_ID_DEDUCT 0x50000000
void checkAudioIdForCustom(bool_t *isCustom, char date_buffer[32], time_t audioId);
void checkAudioIdForCustom(bool_t *isCustom, char date_buffer[32], time_t audioId)
{
    struct tm tm_info;
    time_t unix_time = audioId;

    *isCustom = false;
    if (unix_time < 0x0e000000)
    {
        osSprintf(date_buffer, "special");
    }
    else
    {
        /* custom tonies from TeddyBench have the audio id reduced by a constant */
        if (unix_time < TEDDY_BENCH_AUDIO_ID_DEDUCT)
        {
            unix_time += TEDDY_BENCH_AUDIO_ID_DEDUCT;
            *isCustom = true;
        }
        if (localtime_r(&unix_time, &tm_info) == 0)
        {
            osSprintf(date_buffer, "(localtime failed)");
        }
        else
        {
            strftime(date_buffer, 32, "%Y-%m-%d %H:%M:%S", &tm_info);
        }
    }
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
                tonie_info_t tonieInfo;
                getContentPathFromUID(freshReq->tonie_infos[i]->uid, &tonieInfo.contentPath, client_ctx->settings);
                tonieInfo = getTonieInfo(tonieInfo.contentPath);

                char date_buffer_box[32];
                bool_t custom_box;
                char date_buffer_server[32];
                bool_t custom_server = FALSE;

                checkAudioIdForCustom(&custom_box, date_buffer_box, freshReq->tonie_infos[i]->audio_id);

                uint32_t boxAudioId = freshReq->tonie_infos[i]->audio_id;
                if (custom_box)
                    boxAudioId += TEDDY_BENCH_AUDIO_ID_DEDUCT;

                if (tonieInfo.valid)
                {
                    uint32_t serverAudioId = tonieInfo.tafHeader->audio_id;
                    checkAudioIdForCustom(&custom_server, date_buffer_server, serverAudioId);

                    if (custom_server)
                        serverAudioId += TEDDY_BENCH_AUDIO_ID_DEDUCT;

                    tonieInfo.updated = boxAudioId < serverAudioId;
                    if (client_ctx->settings->cloud.prioCustomContent)
                    {
                        if (custom_box && !custom_server)
                            tonieInfo.updated = false;
                        if (!custom_box && custom_server)
                            tonieInfo.updated = true;
                    }
                }

                if (!tonieInfo.nocloud)
                {
                    freshReqCloud.tonie_infos[freshReqCloud.n_tonie_infos++] = freshReq->tonie_infos[i];
                }

                (void)custom_box;
                (void)custom_server;
                TRACE_INFO("  uid: %016" PRIX64 ", nocloud: %d, live: %d, updated: %d, audioid: %08X (%s%s)",
                           freshReq->tonie_infos[i]->uid,
                           tonieInfo.nocloud,
                           tonieInfo.live,
                           tonieInfo.updated,
                           freshReq->tonie_infos[i]->audio_id,
                           date_buffer_box,
                           custom_box ? ", custom" : "");

                if (tonieInfo.valid)
                {
                    TRACE_INFO_RESUME(", audioid-server: %08X (%s%s)",
                                      tonieInfo.tafHeader->audio_id,
                                      date_buffer_server,
                                      custom_server ? ", custom" : "");
                }

                TRACE_INFO_RESUME("\r\n");

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
        connection->response.keepAlive = true;
        return httpWriteResponseString(connection, "{}", false);
    }
    return NO_ERROR;
}

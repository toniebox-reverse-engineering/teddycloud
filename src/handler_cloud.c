#include <time.h>
#include <stdbool.h>
#include <string.h>

#include "settings.h"
#include "fs_ext.h"

#include "handler.h"
#include "handler_api.h"
#include "handler_cloud.h"
#include "http/http_client.h"

#include "mqtt.h"
#include "server_helpers.h"

#include "toniefile.h"
#include "toniesJson.h"

void convertTokenBytesToString(uint8_t *token, char *msg, bool_t logFullAuth)
{
    char buffer[4];

    msg[0] = '\0';
    for (int i = 0; i < AUTH_TOKEN_LENGTH; i++)
    {
        if (i > 3 && !logFullAuth)
        {
            osStrcat(msg, "...");
            break;
        }
        osSnprintf(buffer, sizeof(buffer), "%02X", token[i]);
        osStrcat(msg, buffer);
    }
}

error_t handleCloudTime(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    TRACE_INFO(" >> respond with current time\r\n");

    char current_time[64];
    time_format_current(current_time);
    mqtt_sendBoxEvent("LastCloudTime", current_time, client_ctx);

    char response[32];

    if (!client_ctx->settings->cloud.enabled || !client_ctx->settings->cloud.enableV1Time)
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

    settings_internal_toniebox_firmware_t *toniebox_fw = &client_ctx->settings->internal.toniebox_firmware;
    switch (fileId)
    {
    case 2:
        toniebox_fw->otaVersionPd = timestamp;
        break;
    case 3:
        toniebox_fw->otaVersionEu = timestamp;
        break;
    case 4:
        toniebox_fw->otaVersionServicePack = timestamp;
        break;
    case 5:
        toniebox_fw->otaVersionHtml = timestamp;
        break;
    case 6:
        toniebox_fw->otaVersionSfx = timestamp;
        break;
    }

    char current_time[64];
    time_format_current(current_time);
    mqtt_sendBoxEvent("LastCloudOtaTime", current_time, client_ctx);

    if (client_ctx->settings->cloud.enabled && client_ctx->settings->cloud.enableV1Ota)
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
    if (ruid[15] != '0' || ruid[14] != 'e' || ruid[13] != '4' || ruid[12] != '0' || ruid[11] != '3' || ruid[10] != '0')
    {
        TRACE_INFO("Found possible custom tonie by uid\r\n");
        return true;
    }
    return false;
}

void markCustomTonie(tonie_info_t *tonieInfo)
{
    tonieInfo->json.nocloud = true;
    tonieInfo->json._updated = true;
    TRACE_INFO("Marked custom tonie %s\r\n", tonieInfo->contentPath);
}

void markLiveTonie(tonie_info_t *tonieInfo)
{
    tonieInfo->json.live = true;
    tonieInfo->json._updated = true;
    TRACE_INFO("Marked custom tonie %s\r\n", tonieInfo->contentPath);
}

void dumpRuidAuth(contentJson_t *content_json, char *ruid, uint8_t *authentication)
{
    if (!content_json->cloud_override && osStrlen(content_json->cloud_ruid) == 0)
    {
        osFreeMem(content_json->cloud_auth);
        content_json->cloud_auth_len = AUTH_TOKEN_LENGTH;
        content_json->cloud_auth = osAllocMem(content_json->cloud_auth_len);
        osMemcpy(content_json->cloud_auth, authentication, content_json->cloud_auth_len);

        osFreeMem(content_json->cloud_ruid);
        content_json->cloud_ruid = strdup(ruid);
        content_json->_updated = true;
        TRACE_INFO("Dumped rUID %s and auth into content.json\r\n", content_json->cloud_ruid);
    }
}

error_t handleCloudLog(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (client_ctx->settings->cloud.enabled && client_ctx->settings->cloud.enableV1Log)
    {
        cbr_ctx_t ctx;
        req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V1_LOG, &ctx, client_ctx);
        cloud_request_get(NULL, 0, uri, queryString, NULL, &cbr);
    }
    return NO_ERROR;
}

error_t handleCloudClaim(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    error_t ret = NO_ERROR;
    char ruid[17];
    uint8_t *token = connection->private.authentication_token;

#define RUID_URI_CLAIM_BEGIN 10
    osStrncpy(ruid, &uri[RUID_URI_CLAIM_BEGIN], sizeof(ruid));
    ruid[16] = 0;

    if (osStrlen(ruid) != 16)
    {
        TRACE_WARNING(" >>  invalid URI\r\n");
    }
    char msg[AUTH_TOKEN_LENGTH * 2 + 1] = {0};
    convertTokenBytesToString(token, msg, client_ctx->settings->log.logFullAuth);
    TRACE_INFO(" >> client claim requested rUID %s, auth %s\r\n", ruid, msg);

    char current_time[64];
    time_format_current(current_time);
    mqtt_sendBoxEvent("LastCloudClaimTime", current_time, client_ctx);

    tonie_info_t *tonieInfo;
    tonieInfo = getTonieInfoFromRuid(ruid, client_ctx->settings);

    /* allow to override HTTP status code if needed */
    bool served = false;
    httpPrepareHeader(connection, NULL, 0);
    connection->response.statusCode = 200;

    if (client_ctx->settings->cloud.dumpRuidAuthContentJson)
    {
        dumpRuidAuth(&tonieInfo->json, ruid, token);
    }

    if (!tonieInfo->json.nocloud || tonieInfo->json.cloud_override)
    {
        if (checkCustomTonie(ruid, token, client_ctx->settings) && !tonieInfo->json.cloud_override)
        {
            TRACE_INFO(" >> custom tonie detected, nothing forwarded\r\n");
            markCustomTonie(tonieInfo);
        }
        else if (client_ctx->settings->cloud.enabled && client_ctx->settings->cloud.enableV1Claim)
        {
            if (tonieInfo->json.cloud_override)
            {
                token = tonieInfo->json.cloud_auth;
                convertTokenBytesToString(token, msg, client_ctx->settings->log.logFullAuth);
                osMemcpy((char_t *)&uri[RUID_URI_CLAIM_BEGIN], tonieInfo->json.cloud_ruid, osStrlen(tonieInfo->json.cloud_ruid));
                TRACE_INFO("Serve cloud claim from alternative rUID %s, auth %s\r\n", tonieInfo->json.cloud_ruid, msg);
            }
            cbr_ctx_t ctx;
            req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V1_CLAIM, &ctx, client_ctx);
            cloud_request_get(NULL, 0, uri, queryString, token, &cbr);
            served = true;
        }
        else
        {
            TRACE_INFO(" >> cloud claim disabled\r\n");
        }
    }
    else
    {
        TRACE_INFO(" >> nocloud content, nothing forwarded\r\n");
    }

    freeTonieInfo(tonieInfo);

    if (!served)
    {
        ret = httpWriteResponse(connection, NULL, 0, false);
    }

    return ret;
}

error_t handleCloudContent(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx, bool_t noPassword)
{
#define RUID_URI_CONTENT_BEGIN 12
    char ruid[17];
    error_t error = NO_ERROR;
    uint8_t *token = connection->private.authentication_token;

    osStrncpy(ruid, &uri[RUID_URI_CONTENT_BEGIN], sizeof(ruid));
    ruid[16] = 0;

    if (connection->request.Range.start != 0)
    {
        TRACE_INFO(" >> client requested partial download\r\n");
    }

    char current_time[64];
    time_format_current(current_time);
    mqtt_sendBoxEvent("LastCloudContentTime", current_time, client_ctx);

    if (osStrlen(ruid) != 16)
    {
        TRACE_WARNING(" >>  invalid URI\r\n");
    }
    char msg[AUTH_TOKEN_LENGTH * 2 + 1] = {0};
    convertTokenBytesToString(token, msg, client_ctx->settings->log.logFullAuth);
    TRACE_INFO(" >> client requested content for rUID %s, auth %s\r\n", ruid, msg);

    tonie_info_t *tonieInfo;
    tonieInfo = getTonieInfoFromRuid(ruid, client_ctx->settings);

    if (!tonieInfo->json.nocloud && !noPassword && checkCustomTonie(ruid, token, client_ctx->settings) && !tonieInfo->json.cloud_override)
    {
        TRACE_INFO(" >> custom tonie detected, nothing forwarded\r\n");
        markCustomTonie(tonieInfo);
    }

    settings_t *settings = client_ctx->settings;

    if (client_ctx->settings->cloud.dumpRuidAuthContentJson)
    {
        dumpRuidAuth(&tonieInfo->json, ruid, token);
    }

    bool setLive = false;
    const char *assignFile = NULL;

    if (osStrlen(settings->internal.assign_unknown) > 0)
    {
        if (!tonieInfo->exists)
        {
            assignFile = settings->internal.assign_unknown;
            TRACE_INFO(" >> this is a unknown tonie, assigning '%s'\r\n", assignFile);
        }

        if (settings->core.flex_enabled)
        {
            char uid[17];
            for (int pos = 0; pos < 16; pos += 2)
            {
                osStrncpy(&uid[pos], &ruid[14 - pos], 2);
            }
            uid[16] = 0;
            if (!osStrcasecmp(uid, settings->core.flex_uid))
            {
                assignFile = settings->internal.assign_unknown;
                setLive = true;
                TRACE_INFO(" >> this is the defined flex tonie, assigning '%s'\r\n", assignFile);
            }
        }
    }

    if (assignFile)
    {
        do
        {
            if (!fsFileExists(assignFile))
            {
                TRACE_ERROR("Path to assign not available: %s\r\n", assignFile);
                break;
            }

            tonie_info_t *tonieInfoAssign = getTonieInfo(assignFile, client_ctx->settings);
            if (!tonieInfoAssign->valid)
            {
                freeTonieInfo(tonieInfoAssign);
                TRACE_ERROR("TAF header invalid: %s\r\n", assignFile);
                break;
            }

            char *dir = strdup(tonieInfo->contentPath);
            dir[osStrlen(dir) - 8] = '\0';
            fsCreateDir(dir);
            osFreeMem(dir);

            error = fsCopyFile(assignFile, tonieInfo->contentPath, true);
            if (error != NO_ERROR)
            {
                freeTonieInfo(tonieInfoAssign);
                TRACE_ERROR("Could not copy %s to %s, error=%" PRIu32 "\r\n", assignFile, tonieInfo->contentPath, error);
                break;
            }

            char *oldFile = strdup(tonieInfo->contentPath);
            freeTonieInfo(tonieInfo);
            tonieInfo = getTonieInfo(oldFile, client_ctx->settings);
            free(oldFile);

            if (!tonieInfo->valid)
            {
                TRACE_ERROR("TAF headerinvalid, delete it again: %s\r\n", tonieInfo->contentPath);
                fsDeleteFile(tonieInfo->contentPath);
                break;
            }

            TRACE_INFO("Assigned to %s\r\n", assignFile);

            if (setLive)
            {
                markLiveTonie(tonieInfo);
            }

        } while (0);

        settings_set_string("internal.assign_unknown", "");
        error = NO_ERROR;
    }

    if (tonieInfo->json._stream)
    {
        char *streamFileRel = &tonieInfo->json._streamFile[osStrlen(client_ctx->settings->internal.datadirfull)];
        TRACE_INFO("Serve streaming content from %s\r\n", tonieInfo->json.source);
        connection->response.keepAlive = true;

        ffmpeg_stream_ctx_t ffmpeg_ctx;
        ffmpeg_ctx.active = false;
        ffmpeg_ctx.quit = false;
        ffmpeg_ctx.source = tonieInfo->json.source;
        ffmpeg_ctx.skip_seconds = tonieInfo->json.skip_seconds;
        ffmpeg_ctx.targetFile = tonieInfo->json._streamFile;
        ffmpeg_ctx.error = NO_ERROR;
        ffmpeg_ctx.taskId = osCreateTask(streamFileRel, &ffmpeg_stream_task, &ffmpeg_ctx, 10 * 1024, 0);

        while (!ffmpeg_ctx.active && ffmpeg_ctx.error == NO_ERROR)
        {
            osDelayTask(100);
        }
        if (ffmpeg_ctx.error == NO_ERROR)
        {
            error_t error = httpSendResponseStream(connection, streamFileRel, tonieInfo->json._stream);
            if (error)
            {
                TRACE_ERROR(" >> file %s not available or not send, error=%u...\r\n", tonieInfo->contentPath, error);
            }
        }
        ffmpeg_ctx.active = false;
        while (!ffmpeg_ctx.quit)
        {
            osDelayTask(100);
        }
    }
    else if (tonieInfo->exists && tonieInfo->valid)
    {
        TRACE_INFO("Serve local content from %s\r\n", tonieInfo->contentPath);
        connection->response.keepAlive = true;

        if (tonieInfo->stream)
        {
            TRACE_INFO("Found streaming content\r\n");
        }

        error_t error = httpSendResponseStream(connection, &tonieInfo->contentPath[osStrlen(client_ctx->settings->internal.datadirfull)], tonieInfo->stream);
        if (error)
        {
            TRACE_ERROR(" >> file %s not available or not send, error=%u...\r\n", tonieInfo->contentPath, error);
        }
    }
    else
    {
        if (!client_ctx->settings->cloud.enabled || !client_ctx->settings->cloud.enableV2Content || (tonieInfo->json.nocloud && !tonieInfo->json.cloud_override))
        {
            if (tonieInfo->json.nocloud && !tonieInfo->json.cloud_override)
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

            if (tonieInfo->json.cloud_override)
            {
                token = tonieInfo->json.cloud_auth;
                convertTokenBytesToString(token, msg, client_ctx->settings->log.logFullAuth);
                osMemcpy((char_t *)&uri[RUID_URI_CONTENT_BEGIN], tonieInfo->json.cloud_ruid, osStrlen(tonieInfo->json.cloud_ruid));
                TRACE_INFO("Serve cloud from alternative rUID %s, auth %s\r\n", tonieInfo->json.cloud_ruid, msg);
            }

            connection->response.keepAlive = true;
            cbr_ctx_t ctx;
            ctx.tonieInfo = tonieInfo;
            req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V2_CONTENT, &ctx, client_ctx);
            cloud_request_get(NULL, 0, uri, queryString, token, &cbr);
            error = NO_ERROR;
        }
    }
    freeTonieInfo(tonieInfo);
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
        TRACE_WARNING("Missing auth for content v2: %s\r\n", uri);
    }
    return NO_ERROR;
}

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

    char current_time[64];
    time_format_current(current_time);
    mqtt_sendBoxEvent("LastCloudFreshnessCheckTime", current_time, client_ctx);

    settings_t *settings = client_ctx->settings;

    if (BODY_BUFFER_SIZE <= connection->request.byteCount)
    {
        TRACE_ERROR("Body size %zu bigger than buffer size %i bytes\r\n", connection->request.byteCount, BODY_BUFFER_SIZE);
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
                tonie_info_t *tonieInfo;
                tonieInfo = getTonieInfoFromUid(freshReq->tonie_infos[i]->uid, client_ctx->settings);

                char date_buffer_box[32];
                bool_t custom_box;
                char date_buffer_server[32];
                bool_t custom_server = FALSE;

                checkAudioIdForCustom(&custom_box, date_buffer_box, freshReq->tonie_infos[i]->audio_id);

                uint32_t boxAudioId = freshReq->tonie_infos[i]->audio_id;
                if (custom_box)
                    boxAudioId += TEDDY_BENCH_AUDIO_ID_DEDUCT;

                if (tonieInfo->valid)
                {
                    uint32_t serverAudioId = tonieInfo->tafHeader->audio_id;
                    checkAudioIdForCustom(&custom_server, date_buffer_server, serverAudioId);

                    if (custom_server)
                        serverAudioId += TEDDY_BENCH_AUDIO_ID_DEDUCT;

                    tonieInfo->updated = boxAudioId < serverAudioId;
                    tonieInfo->updated = tonieInfo->updated || (client_ctx->settings->cloud.updateOnLowerAudioId && (boxAudioId > serverAudioId));
                    if (client_ctx->settings->cloud.prioCustomContent)
                    {
                        if (custom_box && !custom_server)
                            tonieInfo->updated = false;
                        if (!custom_box && custom_server)
                            tonieInfo->updated = true;
                    }
                }

                if (!tonieInfo->json.nocloud)
                {
                    freshReqCloud.tonie_infos[freshReqCloud.n_tonie_infos++] = freshReq->tonie_infos[i];
                }

                bool isFlex = false;

                char uid[17];
                osSprintf(uid, "%016" PRIX64, freshReq->tonie_infos[i]->uid);

                if (settings->core.flex_enabled && !osStrcasecmp(settings->core.flex_uid, uid))
                {
                    isFlex = true;
                }
                (void)custom_box;
                (void)custom_server;
                TRACE_INFO("  uid: %016" PRIX64 ", nocloud: %d, live: %d, updated: %d, audioid: %08X (%s%s)",
                           freshReq->tonie_infos[i]->uid,
                           tonieInfo->json.nocloud,
                           tonieInfo->json.live || isFlex || tonieInfo->stream,
                           tonieInfo->updated,
                           freshReq->tonie_infos[i]->audio_id,
                           date_buffer_box,
                           custom_box ? ", custom" : "");

                if (tonieInfo->valid)
                {
                    TRACE_INFO_RESUME(", audioid-server: %08X (%s%s)",
                                      tonieInfo->tafHeader->audio_id,
                                      date_buffer_server,
                                      custom_server ? ", custom" : "");
                }
                TRACE_INFO_RESUME("\r\n");
                if (!tonieInfo->valid)
                {
                    content_json_update_model(&tonieInfo->json, freshReq->tonie_infos[i]->audio_id, NULL);
                }

                if (tonieInfo->json.live || tonieInfo->updated || tonieInfo->stream || isFlex)
                {
                    freshResp.tonie_marked[freshResp.n_tonie_marked++] = freshReq->tonie_infos[i]->uid;
                }
                freeTonieInfo(tonieInfo);
            }

            if (client_ctx->settings->cloud.enabled && client_ctx->settings->cloud.enableV1FreshnessCheck)
            {
                size_t dataLen = tonie_freshness_check_request__get_packed_size(&freshReqCloud);
                tonie_freshness_check_request__pack(&freshReqCloud, (uint8_t *)data);

                cbr_ctx_t ctx;
                ctx.customData = (void *)&freshResp;
                ctx.customDataLen = freshReq->n_tonie_infos; // Allocated slots
                req_cbr_t cbr = getCloudCbr(connection, uri, queryString, V1_FRESHNESS_CHECK, &ctx, client_ctx);
                if (!cloud_request_post(NULL, 0, "/v1/freshness-check", queryString, data, dataLen, NULL, &cbr))
                {
                    tonie_freshness_check_request__free_unpacked(freshReq, NULL);
                    osFreeMem(freshReqCloud.tonie_infos);
                    osFreeMem(freshResp.tonie_marked);
                    return NO_ERROR;
                }
            }
            tonie_freshness_check_request__free_unpacked(freshReq, NULL);
            if (client_ctx->settings->toniebox.overrideCloud)
            {
                setTonieboxSettings(&freshResp, client_ctx->settings);
            }

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

    char current_time[64];
    time_format_current(current_time);
    mqtt_sendBoxEvent("LastCloudResetTime", current_time, client_ctx);

    // EMPTY POST REQUEST?
    if (client_ctx->settings->cloud.enabled && client_ctx->settings->cloud.enableV1CloudReset)
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

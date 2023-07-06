#include <time.h>
#include <stdbool.h>

#include "handler_cloud.h"
#include "proto/toniebox.pb.freshness-check.fc-request.pb-c.h"
#include "proto/toniebox.pb.freshness-check.fc-response.pb-c.h"

error_t httpWriteResponse(HttpConnection *connection, const void *data, bool_t freeMemory)
{

    error_t error = httpWriteHeader(connection);
    if (error != NO_ERROR)
    {
        if (freeMemory)
            osFreeMem(data);
        TRACE_ERROR("Failed to send header");
        return error;
    }

    error = httpWriteStream(connection, data, connection->response.contentLength);
    if (freeMemory)
        if (freeMemory)
            osFreeMem(data);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to send payload");
        return error;
    }

    error = httpCloseStream(connection);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to close");
        return error;
    }

    return NO_ERROR;
}
void httpPrepareHeader(HttpConnection *connection, const void *contentType, size_t contentLength)
{
    httpInitResponseHeader(connection);
    connection->response.contentType = contentType;
    connection->response.contentLength = contentLength;
}

error_t handleCloudTime(HttpConnection *connection, const char_t *uri)
{
    TRACE_INFO(" >> respond with current time\n");

    char response[32];

    sprintf(response, "%ld", time(NULL));

    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(response));
    return httpWriteResponse(connection, response, false);
}

error_t handleCloudOTA(HttpConnection *connection, const char_t *uri)
{
    return NO_ERROR;
}

error_t handleCloudLog(HttpConnection *connection, const char_t *uri)
{
    return NO_ERROR;
}

error_t handleCloudClaim(HttpConnection *connection, const char_t *uri)
{
    char uid[18];
    uint8_t *token = connection->private.authentication_token;

    osStrncpy(uid, &uri[10], sizeof(uid));
    uid[17] = 0;

    if (osStrlen(uid) != 16)
    {
        TRACE_WARNING(" >>  invalid URI\n");
    }
    TRACE_INFO(" >> client requested UID %s\n", uid);
    TRACE_INFO(" >> client authenticated with %02X%02X%02X%02X...\n", token[0], token[1], token[2], token[3]);

    return NO_ERROR;
}

void strupr(char input[])
{
    for (uint16_t i = 0; input[i]; i++)
    {
        input[i] = toupper(input[i]);
    }
}
error_t handleCloudContent(HttpConnection *connection, const char_t *uri)
{
    char uid[18];
    char contentPath[1 + 7 + 1 + 8 + 1 + 8 + 1];
    uint8_t *token = connection->private.authentication_token;

    if (connection->request.auth.found && connection->request.auth.mode == HTTP_AUTH_MODE_DIGEST)
    {
        osStrncpy(uid, &uri[12], sizeof(uid));
        uid[17] = 0;

        if (osStrlen(uid) != 16)
        {
            TRACE_WARNING(" >>  invalid URI\n");
        }
        TRACE_INFO(" >> client requested UID %s\n", uid);
        TRACE_INFO(" >> client authenticated with %02X%02X%02X%02X...\n", token[0], token[1], token[2], token[3]);

        osSprintf(contentPath, "/CONTENT/%.8s/%.8s", uid, &uid[8]);
        strupr(contentPath);
        error_t error = httpSendResponse(connection, contentPath);
        if (error)
        {
            TRACE_ERROR(" >> file %s not available or not send, error=%lu...\n", contentPath, error);
        }

#if 0
        char *header_data = "Congratulations, here could have been the content for UID %s and the hash ";
        char *footer_data = " - if there was any...\r\n";

        char *build_string = osAllocMem(strlen(header_data) + osStrlen(uid) + 2 * AUTH_TOKEN_LENGTH + osStrlen(footer_data));

        osSprintf(build_string, header_data, uid);
        for (int pos = 0; pos < AUTH_TOKEN_LENGTH; pos++)
        {
            char buf[3];
            osSprintf(buf, "%02X", token[pos]);
            osStrcat(build_string, buf);
        }
        osStrcat(build_string, footer_data);

        httpPrepareHeader(connection, "application/binary", osStrlen(build_string));
        return httpWriteResponse(connection, build_string, true);
#endif
    }
    return NO_ERROR;
}

error_t handleCloudFreshnessCheck(HttpConnection *connection, const char_t *uri)
{
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
        TRACE_INFO("Content (%li of %li)\n", size, connection->request.byteCount);
        TonieFreshnessCheckRequest *freshReq = tonie_freshness_check_request__unpack(NULL, size, (const uint8_t *)data);
        if (freshReq == NULL)
        {
            TRACE_ERROR("Unpacking freshness request failed!\n");
        }
        else
        {
            uint32_t uidTest;
            TRACE_INFO("Found %li tonies:\n", freshReq->n_tonie_infos);
            for (uint16_t i = 0; i < freshReq->n_tonie_infos; i++)
            {
                struct tm tm_info;
                char date_buffer[32];
                bool custom = false;
                time_t unix_time = freshReq->tonie_infos[i]->audio_id;

                if (unix_time < 0x0e000000)
                {
                    sprintf(date_buffer, "special");
                }
                else
                {
                    /* custom tonies from TeddyBench have the audio id reduced by a constant */
                    if (unix_time < 0x50000000)
                    {
                        unix_time += 0x50000000;
                        custom = true;
                    }
                    if (localtime_r(&unix_time, &tm_info) == NULL)
                    {
                        sprintf(date_buffer, "(localtime failed)");
                    }
                    else
                    {
                        strftime(date_buffer, sizeof(date_buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
                    }
                }

                TRACE_INFO("  uid: %016lX, audioid: %08X (%s%s)\n",
                           freshReq->tonie_infos[i]->uid,
                           freshReq->tonie_infos[i]->audio_id,
                           date_buffer,
                           custom ? ", custom" : "");
                if (custom)
                    uidTest = freshReq->tonie_infos[i]->uid;
            }
            tonie_freshness_check_request__free_unpacked(freshReq, NULL);

            // Upstream
            // TODO push to Boxine
            TonieFreshnessCheckResponse freshResp = TONIE_FRESHNESS_CHECK_RESPONSE__INIT;
            freshResp.max_vol_spk = 3;
            freshResp.slap_en = 0;
            freshResp.slap_dir = 0;
            freshResp.max_vol_hdp = 3;
            freshResp.led = 1;
            freshResp.n_tonie_marked = 1;
            freshResp.tonie_marked = malloc(sizeof(char *) * freshResp.n_tonie_marked);
            freshResp.tonie_marked[0] = uidTest;
            size_t dataLen = tonie_freshness_check_response__get_packed_size(&freshResp);
            tonie_freshness_check_response__pack(&freshResp, (uint8_t *)data);
            free(freshResp.tonie_marked);
            TRACE_INFO("Freshness check response: size=%li, content=%s\n", dataLen, data);

            httpPrepareHeader(connection, "application/octet-stream; charset=utf-8", dataLen);
            return httpWriteResponse(connection, data, false);
            // tonie_freshness_check_response__free_unpacked(&freshResp, NULL);
        }
        return NO_ERROR;
    }
    return NO_ERROR;
}
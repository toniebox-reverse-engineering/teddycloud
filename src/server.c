

#include <errno.h>     // for error_t
#include <stdint.h>    // for uint8_t
#include <stdio.h>     // for printf
#include <stdlib.h>    // for atoi, exit, free
#include <string.h>    // for NULL, strdup, strlen, strncmp, strcmp
#include <sys/types.h> // for time_t
#include <time.h>      // for time

#include "compiler_port.h"        // for char_t, PRIuTIME
#include "core/net.h"             // for ipStringToAddr, IpAddr
#include "core/socket.h"          // for _Socket
#include "debug.h"                // for TRACE_DEBUG, TRACE_ERROR, TRACE_INFO
#include "error.h"                // for NO_ERROR, error2text, ERROR_FAILURE
#include "fs_port_posix.h"        // for fsDirExists
#include "handler_api.h"          // for handleApiAssignUnknown, handleApiA...
#include "handler_cloud.h"        // for handleCloudClaim, handleCloudConte...
#include "handler_reverse.h"      // for handleReverse
#include "handler_rtnl.h"         // for handleRtnl
#include "handler_security_mit.h" // for handleSecMitRobotsTxt, checkSecMit...
#include "handler_sse.h"          // for handleApiSse, sse_init
#include "http/http_common.h"     // for HTTP_AUTH_MODE_DIGEST
#include "http/http_server.h"     // for _HttpConnection, HttpServerSettings
#include "mutex_manager.h"        // for mutex_unlock, mutex_lock, MUTEX_CL...
#include "net_config.h"           // for client_ctx_t, http_connection_priv...
#include "os_port.h"              // for osFreeMem, osStrlen, osStrstr, osG...
#include "pcaplog.h"              // for pcaplog_close, pcaplog_open
#include "rand.h"                 // for rand_get_algo, rand_get_context
#include "returncodes.h"          // for RETURNCODE_INVALID_CONFIG
#include "server_helpers.h"       // for httpServerUriNotFoundCallback, cus...
#include "settings.h"             // for settings_t, settings_get_string
#include "stdbool.h"              // for true, bool, false
#include "tls.h"                  // for _TlsContext, tlsLoadCertificate
#include "tls_adapter.h"          // for tls_context_key_log_init, tlsCache
#include "toniebox_state.h"       // for get_toniebox_state, get_toniebox_s...
#include "toniebox_state_type.h"  // for toniebox_state_box_t, toniebox_sta...
#include "toniesJson.h"           // for tonieboxes_update, tonies_deinit
#include "compiler_port.h"        // for char_t, PRIuTIME
#include "core/net.h"             // for ipStringToAddr, IpAddr
#include "core/socket.h"          // for _Socket
#include "web.h"                  // for web_download
#include "cache.h"                // for image cache functions
#include "debug.h"                // for TRACE_DEBUG, TRACE_ERROR, TRACE_INFO
#include "error.h"                // for NO_ERROR, error2text, ERROR_FAILURE
#include "fs_port_posix.h"        // for fsDirExists
#include "handler_api.h"          // for handleApiAssignUnknown, handleApiA...
#include "handler_cloud.h"        // for handleCloudClaim, handleCloudConte...
#include "handler_reverse.h"      // for handleReverse
#include "handler_rtnl.h"         // for handleRtnl
#include "handler_security_mit.h" // for handleSecMitRobotsTxt, checkSecMit...
#include "handler_sse.h"          // for handleApiSse, sse_init
#include "http/http_common.h"     // for HTTP_AUTH_MODE_DIGEST
#include "http/http_server.h"     // for _HttpConnection, HttpServerSettings
#include "mutex_manager.h"        // for mutex_unlock, mutex_lock, MUTEX_CL...
#include "net_config.h"           // for client_ctx_t, http_connection_priv...
#include "os_port.h"              // for osFreeMem, osStrlen, osStrstr, osG...
#include "pcaplog.h"              // for pcaplog_close, pcaplog_open
#include "rand.h"                 // for rand_get_algo, rand_get_context
#include "returncodes.h"          // for RETURNCODE_INVALID_CONFIG
#include "server_helpers.h"       // for httpServerUriNotFoundCallback, cus...
#include "settings.h"             // for settings_t, settings_get_string
#include "stdbool.h"              // for true, bool, false
#include "tls.h"                  // for _TlsContext, tlsLoadCertificate
#include "tls_adapter.h"          // for tls_context_key_log_init, tlsCache
#include "toniebox_state.h"       // for get_toniebox_state, get_toniebox_s...
#include "toniebox_state_type.h"  // for toniebox_state_box_t, toniebox_sta...
#include "toniesJson.h"           // for tonieboxes_update, tonies_deinit

#define APP_HTTP_MAX_CONNECTIONS 32
HttpConnection httpConnections[APP_HTTP_MAX_CONNECTIONS];
HttpConnection httpsWebConnections[APP_HTTP_MAX_CONNECTIONS];
HttpConnection httpsApiConnections[APP_HTTP_MAX_CONNECTIONS];

size_t openRequestsLast = 0;

enum eRequestMethod
{
    REQ_ANY,
    REQ_GET,
    REQ_POST
};

typedef enum
{
    SERTY_NONE = 0,
    SERTY_WEB = 1,
    SERTY_API = 2,
    SERTY_BOTH = 3,
} server_type_t;

typedef struct
{
    enum eRequestMethod method;
    char *path;
    server_type_t server_type;
    error_t (*handler)(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
} request_type_t;

error_t handleCacheDownload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);

/* const for now. later maybe dynamic? */
request_type_t request_paths[] = {
    /*binary handler (rtnl)*/
    {REQ_ANY, "*binary", SERTY_BOTH, &handleRtnl},
    /* reverse proxy handler */
    {REQ_ANY, "/reverse", SERTY_WEB, &handleReverse},
    /* cached files */
    {REQ_GET, "/cache/", SERTY_WEB, &handleCacheDownload},
    /* web interface directory */
    {REQ_GET, "/content/download/", SERTY_WEB, &handleApiContentDownload},
    {REQ_GET, "/content/json/get/", SERTY_WEB, &handleApiContentJsonGet},
    {REQ_POST, "/content/json/set/", SERTY_WEB, &handleApiContentJsonSet},
    {REQ_GET, "/content/json/", SERTY_WEB, &handleApiContentJson},
    {REQ_GET, "/content/", SERTY_WEB, &handleApiContent},
    /* auth API */
    {REQ_POST, "/api/auth/login", SERTY_WEB, &handleApiAuthLogin},
    {REQ_GET, "/api/auth/logout", SERTY_WEB, &handleApiAuthLogout},
    {REQ_POST, "/api/auth/refresh-token", SERTY_WEB, &handleApiAuthRefreshToken},
    /* custom API */
    {REQ_POST, "/api/fileDelete", SERTY_WEB, &handleApiFileDelete},
    {REQ_POST, "/api/fileMove", SERTY_WEB, &handleApiFileMove},
    {REQ_POST, "/api/dirDelete", SERTY_WEB, &handleApiDirectoryDelete},
    {REQ_POST, "/api/dirCreate", SERTY_WEB, &handleApiDirectoryCreate},
    {REQ_POST, "/api/uploadCert", SERTY_WEB, &handleApiUploadCert},
    {REQ_POST, "/api/uploadFirmware", SERTY_WEB, &handleApiUploadFirmware},
    {REQ_GET, "/api/patchFirmware", SERTY_WEB, &handleApiPatchFirmware},
    {REQ_POST, "/api/fileUpload", SERTY_WEB, &handleApiFileUpload},
    {REQ_POST, "/api/pcmUpload", SERTY_WEB, &handleApiPcmUpload},
    {REQ_GET, "/api/fileIndexV2", SERTY_WEB, &handleApiFileIndexV2},
    {REQ_GET, "/api/fileIndex", SERTY_WEB, &handleApiFileIndex},
    {REQ_GET, "/api/stats", SERTY_WEB, &handleApiStats},
    {REQ_GET, "/api/toniesJsonSearch", SERTY_WEB, &handleApiToniesJsonSearch},
    {REQ_GET, "/api/toniesJsonUpdate", SERTY_WEB, &handleApiToniesJsonUpdate},
    {REQ_GET, "/api/toniesJsonReload", SERTY_WEB, &handleApiToniesJsonReload},
    {REQ_GET, "/api/toniesJson", SERTY_WEB, &handleApiToniesJson},
    {REQ_GET, "/api/toniesCustomJson", SERTY_WEB, &handleApiToniesCustomJson},
    {REQ_GET, "/api/tonieboxesJson", SERTY_WEB, &handleApiTonieboxJson},
    {REQ_GET, "/api/tonieboxesCustomJson", SERTY_WEB, &handleApiTonieboxCustomJson},
    {REQ_GET, "/api/trigger", SERTY_WEB, &handleApiTrigger},
    {REQ_GET, "/api/getTagIndex", SERTY_WEB, &handleApiTagIndex},
    {REQ_GET, "/api/getTagInfo", SERTY_WEB, &handleApiTagInfo},
    {REQ_GET, "/api/getBoxes", SERTY_WEB, &handleApiGetBoxes},
    {REQ_POST, "/api/assignUnknown", SERTY_WEB, &handleApiAssignUnknown},
    {REQ_GET, "/api/settings/getIndex", SERTY_WEB, &handleApiGetIndex},
    {REQ_GET, "/api/settings/get/", SERTY_WEB, &handleApiSettingsGet},
    {REQ_POST, "/api/settings/set/", SERTY_WEB, &handleApiSettingsSet},
    {REQ_POST, "/api/settings/reset/", SERTY_WEB, &handleApiSettingsReset},
    {REQ_POST, "/api/settings/removeOverlay", SERTY_WEB, &handleDeleteOverlay},
    {REQ_POST, "/api/migrateContent2Lib", SERTY_WEB, &handleApiMigrateContent2Lib},
    {REQ_POST, "/api/cacheFlush", SERTY_WEB, &handleApiCacheFlush},
    {REQ_GET, "/api/cacheStats", SERTY_WEB, &handleApiCacheStats},
    {REQ_GET, "/api/sse", SERTY_WEB, &handleApiSse},
    {REQ_GET, "/robots.txt", SERTY_WEB, &handleSecMitRobotsTxt},
    /* official tonies API */
    {REQ_GET, "/v1/time", SERTY_BOTH, &handleCloudTime},
    {REQ_GET, "/v1/ota", SERTY_BOTH, &handleCloudOTA},
    {REQ_GET, "/v1/claim", SERTY_BOTH, &handleCloudClaim},
    {REQ_GET, "/v1/content", SERTY_BOTH, &handleCloudContentV1},
    {REQ_GET, "/v2/content", SERTY_BOTH, &handleCloudContentV2},
    {REQ_POST, "/v1/freshness-check", SERTY_BOTH, &handleCloudFreshnessCheck},
    {REQ_POST, "/v1/log", SERTY_BOTH, &handleCloudLog},
    {REQ_POST, "/v1/cloud-reset", SERTY_BOTH, &handleCloudReset}};

error_t handleCacheDownload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    /* guerilla-style stats page for internal tests, to be removed when web ui is finished */
    if (osStrcmp(uri, "/cache/stats.html") == 0)
    {
        cache_stats_t stats;
        cache_stats(&stats);

        char stats_page[4096];
        snprintf(stats_page, sizeof(stats_page),
                 "<!DOCTYPE html>"
                 "<html lang=\"en\">"
                 "<head>"
                 "<meta charset=\"UTF-8\">"
                 "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
                 "<meta http-equiv=\"refresh\" content=\"1\">"
                 "<title>Cache Statistics</title>"
                 "<style>"
                 "body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; }"
                 "h1 { color: #444; text-align: center; }"
                 ".container { max-width: 800px; margin: 50px auto; padding: 20px; background-color: #fff; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }"
                 "table { width: 100%%; border-collapse: collapse; margin-top: 20px; }"
                 "th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }"
                 "th { background-color: #f2f2f2; }"
                 ".btn { display: inline-block; padding: 10px 20px; font-size: 16px; color: #fff; background-color: #007bff; border: none; border-radius: 5px; text-decoration: none; margin-top: 20px; }"
                 "</style>"
                 "<script>"
                 "function flushCache() {"
                 "  fetch('/api/cacheFlush', { method: 'POST' })"
                 "    .then(response => response.json())"
                 "    .then(data => {"
                 "      alert(data.message + ' Number of files deleted: ' + data.deleted_files);"
                 "      location.reload();"
                 "    })"
                 "    .catch(error => {"
                 "      console.error('Error flushing cache:', error);"
                 "      alert('Failed to flush cache.');"
                 "    });"
                 "}"

                 "</script>"
                 "</head>"
                 "<body>"
                 "<div class=\"container\">"
                 "<h1>Cache Statistics</h1>"
                 "<table>"
                 "<tr><th>Total Entries</th><td>%zu</td></tr>"
                 "<tr><th>Entries with Existing Files</th><td>%zu</td></tr>"
                 "<tr><th>Total Cached Files</th><td>%zu</td></tr>"
                 "<tr><th>Total Cache Size</th><td>%zu bytes</td></tr>"
                 "<tr><th>Memory Used</th><td>%zu bytes</td></tr>"
                 "</table>"
                 "<button class=\"btn\" onclick=\"flushCache()\">Flush Cache</button>"
                 "</div>"
                 "</body>"
                 "</html>",
                 stats.total_entries,
                 stats.exists_entries,
                 stats.total_files,
                 stats.total_size,
                 stats.memory_used);

        httpPrepareHeader(connection, "text/html; charset=utf-8", osStrlen(stats_page));
        return httpWriteResponseString(connection, stats_page, false);
    }

    cache_entry_t *entry = cache_fetch_by_path(uri);
    if (!entry)
    {
        TRACE_ERROR("Failed to find cache entry\r\n");
        return ERROR_NOT_FOUND;
    }

    if (!entry->exists)
    {
        if (entry->statusCode == 404)
        {
            TRACE_WARNING("Failed, server reported 404 for '%s' cached: '%s'\r\n", entry->original_url, entry->cached_url);
            return ERROR_NOT_FOUND;
        }
        TRACE_INFO("Failed to fetch, redirecting instead: '%s' cached: '%s'\r\n", entry->original_url, entry->cached_url);
        return httpSendRedirectResponse(connection, 301, entry->original_url);
    }

    error_t err = httpSendResponseUnsafe(connection, uri, entry->file_path);
    return err;
}

error_t resGetData(const char_t *path, const uint8_t **data, size_t *length)
{
    TRACE_DEBUG("resGetData: %s (static response)\n", path);

    *data = (uint8_t *)"CONTENT\r\n";
    *length = (size_t)osStrlen((char *)*data);

    return NO_ERROR;
}

error_t httpServerRequestCallback(HttpConnection *connection, const char_t *uri, bool is_api_only)
{
    size_t openRequests = ++openRequestsLast;
    error_t error = NO_ERROR;
    connection->private.api_access_only = is_api_only;

    stats_update("connections", 1);

    char *request_source;
    if (connection->tlsContext != NULL && osStrlen(connection->tlsContext->client_cert_issuer))
    {
        TRACE_DEBUG("Certificate authentication:\r\n");
        TRACE_DEBUG("  Issuer:     '%s'\r\n", connection->tlsContext->client_cert_issuer);
        TRACE_DEBUG("  Subject:    '%s'\r\n", connection->tlsContext->client_cert_subject);
        TRACE_DEBUG("  Serial:     '%s'\r\n", connection->tlsContext->client_cert_serial);
        request_source = connection->tlsContext->client_cert_subject;
    }
    else
    {
        TRACE_DEBUG("No certificate authentication\r\n");
        request_source = "unknown/web";
    }
    TRACE_DEBUG("Started server request to %s, request %zu, by %s\r\n", uri, openRequests, request_source);

    TRACE_DEBUG(" >> client requested '%s' via %s \n", uri, connection->request.method);

    mutex_lock(MUTEX_CLIENT_CTX);
    client_ctx_t *client_ctx = &connection->private.client_ctx;
    osMemset(client_ctx, 0x00, sizeof(client_ctx_t));
    client_ctx->settings = get_settings();
    client_ctx->state = get_toniebox_state();

    if (connection->tlsContext && connection->private.api_access_only)
    {
        char_t *subject = connection->tlsContext->client_cert_subject;
        char_t *issuer = connection->tlsContext->client_cert_issuer;

        if (osStrstr(issuer, "Boxine Factory SubCA") != NULL || osStrstr(issuer, "TeddyCloud") != NULL || osStrstr(subject, "TeddyCloud") != NULL)
        {
            if (osStrlen(subject) == 15 && !osStrncmp(subject, "b'", 2) && subject[14] == '\'') // tonies standard cn with b'[MAC]'
            {
                char_t *commonName;
                commonName = strdup(&subject[2]);
                commonName[osStrlen(commonName) - 1] = '\0';
                if (get_overlay_id(commonName) == 0)
                {
                    if (client_ctx->settings->core.allowNewBox)
                    {
                        TRACE_INFO("Added new client certificate with CN=%s\n", commonName);
                    }
                    else
                    {
                        TRACE_WARNING("Found unknown client certificate with CN=%s\n", commonName);
                    }
                }
                if (get_overlay_id(commonName) > 0 || client_ctx->settings->core.allowNewBox)
                {
                    client_ctx->settings = get_settings_cn(commonName);
                    connection->private.authenticated = client_ctx->settings->toniebox.api_access;
                }
                osFreeMem(commonName);
                // TODO: CHECK THE CERTIFICATES FOR REAL!!!!!
            }
            else
            {
                if (get_overlay_id(subject) > 0 || client_ctx->settings->core.allowNewBox)
                {
                    client_ctx->settings = get_settings_cn(subject);
                    connection->private.authenticated = client_ctx->settings->toniebox.api_access;
                }
            }
            client_ctx->state = get_toniebox_state_id(client_ctx->settings->internal.overlayNumber);

            char *ua = connection->request.userAgent;
            if (ua != NULL && osStrlen(ua) > 3)
            {
                settings_internal_toniebox_firmware_t *firmware_info = &client_ctx->settings->internal.toniebox_firmware;

                char *espDetectNew = "toniebox-esp32-";

                char *tbV = osStrstr(ua, "TB/");
                char *tbSp = osStrstr(ua, "SP/");
                char *tbHw = osStrstr(ua, "HW/");
                char *tbEsp = osStrstr(ua, espDetectNew);
                char *buffer;
                char *spacePos;

                time_t fwVersionTime = 0;
                time_t spVersionTime = 0;
                time_t hwVersionTime = 0;
                char *fwEsp = NULL;

                if (tbV != NULL)
                {
                    buffer = strdup(tbV + 3);
                    spacePos = osStrchr(buffer, ' ');
                    if (spacePos != NULL)
                    {
                        buffer[spacePos - buffer] = '\0';
                    }
                    fwVersionTime = atoi(buffer);
                    osFreeMem(buffer);
                }
                if (tbSp != NULL)
                {
                    buffer = strdup(tbSp + 3);
                    spacePos = osStrchr(buffer, ' ');
                    if (spacePos != NULL)
                    {
                        buffer[spacePos - buffer] = '\0';
                    }
                    spVersionTime = atoi(buffer);
                    osFreeMem(buffer);
                }
                if (tbHw != NULL)
                {
                    buffer = strdup(tbHw + 3);
                    spacePos = osStrchr(buffer, ' ');
                    if (spacePos != NULL)
                    {
                        buffer[spacePos - buffer] = '\0';
                    }
                    hwVersionTime = atoi(buffer);
                    osFreeMem(buffer);
                }
                if (tbEsp != NULL)
                {
                    fwEsp = tbEsp + osStrlen(espDetectNew);
                }

                if (fwVersionTime > 0)
                {
                    if (tbV == ua)
                    {
                        if (hwVersionTime > 1100000)
                        {
                            // CC3235 User-Agent: TB/%firmware-ts% SP/%sp% HW/%hw%
                            client_ctx->settings->internal.toniebox_firmware.boxIC = BOX_CC3235;
                        }
                        else
                        {
                            // CC3200 User-Agent: TB/%firmware-ts% SP/%sp% HW/%hw%
                            client_ctx->settings->internal.toniebox_firmware.boxIC = BOX_CC3200;
                        }
                    }
                    else
                    {
                        // ESP32 User-Agent (old): %box-color% TB/%firmware-ts%
                        client_ctx->settings->internal.toniebox_firmware.boxIC = BOX_ESP32;
                    }
                }
                else if (fwEsp != NULL)
                {
                    // ESP32 User-Agent: toniebox-esp-eu/v5.226.0
                    client_ctx->settings->internal.toniebox_firmware.boxIC = BOX_ESP32;
                    if (osStrcmp(firmware_info->uaEsp32Firmware, fwEsp) != 0)
                    {
                        settings_set_string_id("internal.toniebox_firmware.uaEsp32Firmware", fwEsp, client_ctx->settings->internal.overlayNumber);
                    }
                }
                else
                {
                    client_ctx->settings->internal.toniebox_firmware.boxIC = BOX_UNKNOWN;
                }

                TRACE_INFO("UA=%s", ua);
                if (fwVersionTime > 0)
                {
                    TRACE_INFO_RESUME(", FW=%" PRIuTIME ", SP=%" PRIuTIME ", HW=%" PRIuTIME, fwVersionTime, spVersionTime, hwVersionTime);
                }
                if (fwEsp != NULL)
                {
                    TRACE_INFO_RESUME(", ESPFW=%s", fwEsp);
                }
                TRACE_INFO_RESUME("\r\n");

                firmware_info->uaVersionFirmware = fwVersionTime;
                firmware_info->uaVersionServicePack = spVersionTime;
                firmware_info->uaVersionHardware = hwVersionTime;
            }
        }
    }
    client_ctx->state->box.id = client_ctx->settings->commonName;
    client_ctx->state->box.name = client_ctx->settings->boxName;
    client_ctx->settingsNoOverlay = client_ctx->settings;

    char *ipStr = ipAddrToString(&connection->socket->remoteIpAddr, NULL);
    settings_set_string_id("internal.ip", ipStr, client_ctx->settings->internal.overlayNumber);
    mutex_unlock(MUTEX_CLIENT_CTX);

    connection->response.keepAlive = connection->request.keepAlive;

    do
    {
        bool handled = false;

        checkSecMitHandlers(connection, uri, connection->request.queryString, client_ctx);
        if (isSecMitIncident(connection) && get_settings()->security_mit.lockAccess)
        {
            error = handleSecMitLock(connection, uri, connection->request.queryString, client_ctx);
            break;
        }

        if (connection->settings->isHttps && client_ctx->settings->core.boxCertAuth && connection->private.api_access_only && !connection->private.authenticated)
        {
            error = httpServerUriUnauthorizedCallback(connection, uri);
            break;
        }

        for (size_t i = 0; i < sizeof(request_paths) / sizeof(request_paths[0]); i++)
        {
            size_t pathLen = osStrlen(request_paths[i].path);
            if (!osStrncmp(request_paths[i].path, uri, pathLen) && ((request_paths[i].method == REQ_ANY) || (request_paths[i].method == REQ_GET && !osStrcasecmp(connection->request.method, "GET")) || (request_paths[i].method == REQ_POST && !osStrcasecmp(connection->request.method, "POST"))))
            {
                if ((!connection->private.api_access_only && (request_paths[i].server_type & SERTY_WEB) == SERTY_WEB) || (connection->private.api_access_only && (request_paths[i].server_type & SERTY_API) == SERTY_API))
                {
                    error = (*request_paths[i].handler)(connection, uri, connection->request.queryString, client_ctx);
                    if (error == ERROR_NOT_FOUND || error == ERROR_FILE_NOT_FOUND)
                    {
                        error = httpServerUriNotFoundCallback(connection, uri);
                    }
                    else if (error != NO_ERROR)
                    {
                        // return httpServerUriErrorCallback(connection, uri, error);
                    }
                    handled = true;
                    break;
                }
            }
        }
        if (handled)
            break;

        if (!connection->private.api_access_only)
        {
            if (!strcmp(uri, "/") || !strcmp(uri, "index.shtm"))
            {
                if (!client_ctx->settings->core.new_webgui_as_default)
                {
                    uri = "/legacy.html";
                }
                else
                {
                    uri = "/web";
                    httpPrepareHeader(connection, "", 0);
                    connection->response.keepAlive = false;
                    connection->response.location = uri;
                    connection->response.statusCode = 301;
                    return httpWriteResponseString(connection, "", false);
                    continue;
                }
            }

            if (!strncmp(uri, "/web", 4) && (uri[4] == '\0' || uri[strlen(uri) - 1] == '/' || !strchr(uri, '.')))
            {
                uri = "/web/index.html";
            }

            char_t *newUri = custom_asprintf("%s%s", client_ctx->settings->core.wwwdir, uri);

            error = httpSendResponse(connection, newUri);
            free(newUri);
        }
        else
        {
            error = httpServerUriNotFoundCallback(connection, uri);
        }
    } while (0);

    TRACE_DEBUG("Stopped server request to %s, request %zu\r\n", uri, openRequests);
    openRequestsLast--;
    return error;
}

error_t httpServerWebRequestCallback(HttpConnection *connection, const char_t *uri)
{
    return httpServerRequestCallback(connection, uri, false);
}
error_t httpServerAPIRequestCallback(HttpConnection *connection, const char_t *uri)
{
    return httpServerRequestCallback(connection, uri, true);
}

void httpParseAuthorizationField(HttpConnection *connection, char_t *value)
{
    if (!strncmp(value, "BD ", 3))
    {
        if (strlen(value) != 3 + 2 * TONIE_AUTH_TOKEN_LENGTH)
        {
            TRACE_WARNING("Authentication: Failed to parse auth token '%s'\r\n", value);
            return;
        }
        for (int pos = 0; pos < TONIE_AUTH_TOKEN_LENGTH; pos++)
        {
            char hex_digits[3];
            char *end_ptr = NULL;

            /* get a hex byte into a buffer for parsing it */
            osStrncpy(hex_digits, &value[3 + 2 * pos], 2);
            hex_digits[2] = 0;

            /* will still fail for minus sign and possibly other things, but then the token is just incorrect */
            connection->private.authentication_token[pos] = (uint8_t)osStrtoul(hex_digits, &end_ptr, 16);

            if (end_ptr != &hex_digits[2])
            {
                TRACE_WARNING("Authentication: Failed to parse auth token '%s'\n", value);
                return;
            }
        }
        /* if we come across this part, this means the token was most likely correctly *parsed* */
        connection->request.auth.found = 1;
        connection->request.auth.mode = HTTP_AUTH_MODE_DIGEST;
        connection->status = HTTP_ACCESS_ALLOWED;
    }
    if (!strncmp(value, "Bearer ", 7))
    {
        if (strlen(value) != 7 + 2 * JWT_AUTH_TOKEN_LENGTH)
        {
            TRACE_WARNING("Authentication: Failed to parse auth token '%s'\r\n", value);
            return;
        }
        // TODO: check JWT TOKEN
        for (int pos = 0; pos < JWT_AUTH_TOKEN_LENGTH; pos++)
        {
            char hex_digits[3];
            char *end_ptr = NULL;

            /* get a hex byte into a buffer for parsing it */
            osStrncpy(hex_digits, &value[3 + 2 * pos], 2);
            hex_digits[2] = 0;

            /* will still fail for minus sign and possibly other things, but then the token is just incorrect */
            connection->private.authentication_token[pos] = (uint8_t)osStrtoul(hex_digits, &end_ptr, 16);

            if (end_ptr != &hex_digits[2])
            {
                TRACE_WARNING("Authentication: Failed to parse auth token '%s'\n", value);
                return;
            }
        }
        /* if we come across this part, this means the token was most likely correctly *parsed* */
        connection->request.auth.found = 1;
        connection->request.auth.mode = HTTP_AUTH_MODE_DIGEST;
        connection->status = HTTP_ACCESS_ALLOWED;
    }
}

HttpAccessStatus httpServerAuthCallback(HttpConnection *connection, const char_t *user, const char_t *uri)
{
    return HTTP_ACCESS_ALLOWED;
}

size_t httpAddAuthenticateField(HttpConnection *connection, char_t *output)
{
    TRACE_DEBUG("httpAddAuthenticateField\r\n");
    return 0;
}

error_t httpServerCgiCallback(HttpConnection *connection,
                              const char_t *param)
{
    // Not implemented
    TRACE_DEBUG("httpServerCgiCallback: %s\r\n", param);
    return NO_ERROR;
}

error_t httpServerTlsInitCallbackBase(HttpConnection *connection, TlsContext *tlsContext, TlsClientAuthMode authMode)
{
    error_t error;

    // Set TX and RX buffer size
    error = tlsSetBufferSize(tlsContext, TLS_TX_BUFFER_SIZE, TLS_RX_BUFFER_SIZE);
    // Any error to report?
    if (error)
        return error;

    // Set the PRNG algorithm to be used
    error = tlsSetPrng(tlsContext, rand_get_algo(), rand_get_context());
    // Any error to report?
    if (error)
        return error;

    tls_context_key_log_init(tlsContext);

    // Session cache that will be used to save/resume TLS sessions
    error = tlsSetCache(tlsContext, tlsCache);
    // Any error to report?
    if (error)
        return error;

    // Client authentication
    error = tlsSetClientAuthMode(tlsContext, authMode);
    // Any error to report?
    if (error)
        return error;

    // Import server's certificate
    const char *cert_chain = settings_get_string("internal.server.cert_chain");
    const char *server_key = settings_get_string("internal.server.key");

    if (!cert_chain || !server_key)
    {
        TRACE_ERROR("Failed to get certificates\r\n");
        return ERROR_FAILURE;
    }

    error = tlsLoadCertificate(tlsContext, 0, cert_chain, strlen(cert_chain), server_key, strlen(server_key), NULL);

    if (error)
    {
        TRACE_ERROR("  Failed to add cert: %s\r\n", error2text(error));
        return error;
    }

    // Successful processing
    return NO_ERROR;
}
error_t httpServerTlsInitCallback(HttpConnection *connection, TlsContext *tlsContext)
{
    return httpServerTlsInitCallbackBase(connection, tlsContext, TLS_CLIENT_AUTH_NONE);
}
error_t httpServerBoxTlsInitCallback(HttpConnection *connection, TlsContext *tlsContext)
{
    settings_t *settings = get_settings(); // Overlay is currently unknown and settings in the context empty
    TlsClientAuthMode authMode = TLS_CLIENT_AUTH_OPTIONAL;
    error_t error = NO_ERROR;
    /*
    if (settings->core.boxCertAuth)
    {
        authMode = TLS_CLIENT_AUTH_REQUIRED;
    }
    */
    error = httpServerTlsInitCallbackBase(connection, tlsContext, authMode);
    if (error)
        return error;

    if (settings->core.boxCertAuth && 1 == 0)
    {
        // TODO add client certs and check if this works.
        // CA cannot be used - the intermedia CAs are not available
        // Doesn't work, because cyclone checks for the chain
        uint32_t trustedCaListLen = 0;
        for (uint8_t settingsId = 1; settingsId < MAX_OVERLAYS; settingsId++)
        {
            const char *cert = get_settings_id(settingsId)->internal.client.crt;
            if (cert != NULL)
            {
                trustedCaListLen += osStrlen(cert);
            }
        }

        if (trustedCaListLen > 0)
        {
            char *trustedCaList = osAllocMem(trustedCaListLen + 1);
            trustedCaList[0] = '\0';
            for (uint8_t settingsId = 1; settingsId < MAX_OVERLAYS; settingsId++)
            {
                const char *cert = get_settings_id(settingsId)->internal.client.crt;
                if (cert != NULL)
                {
                    osStrcat(trustedCaList, cert);
                }
            }
            error = tlsSetTrustedCaList(tlsContext, trustedCaList, osStrlen(trustedCaList));
        }
        else
        {
            TRACE_ERROR("Failed to get trusted CA list\r\n");
            error = ERROR_FAILURE; // TODO which error
        }
    }

    return error;
}

bool sanityCheckDir(const char *dir)
{
    const char *path = settings_get_string(dir);

    if (!path)
    {
        TRACE_ERROR("Config item '%s' not found\r\n", dir);
        return false;
    }
    if (!fsDirExists(path))
    {
        TRACE_ERROR("Config item '%s' is set to '%s' which was not found\r\n", dir, path);
        return false;
    }
    return true;
}

bool sanityChecks()
{
    bool ret = true;

    ret &= sanityCheckDir("internal.datadirfull");
    ret &= sanityCheckDir("internal.wwwdirfull");
    ret &= sanityCheckDir("internal.contentdirfull");

    if (!ret)
    {
        TRACE_ERROR("Sanity checks failed, exiting\r\n");
        settings_set_signed("internal.returncode", RETURNCODE_INVALID_CONFIG);
        settings_set_bool("internal.exit", true);
    }

    return ret;
}

void server_init(bool test)
{
    if (test)
    {
        printf("Docker container started teddyCloud for testing, running smoke test.\r\n");
    }

    mutex_manager_init();
    if (!sanityChecks())
    {
        return;
    }
    settings_set_bool("internal.exit", FALSE);
    sse_init();

    HttpServerSettings http_settings;
    HttpServerSettings https_web_settings;
    HttpServerSettings https_api_settings;
    HttpServerContext http_context;
    HttpServerContext https_web_context;
    HttpServerContext https_api_context;
    IpAddr listenIpAddr;

    /* setup settings for HTTP */
    httpServerGetDefaultSettings(&http_settings);

    const char *bindIp = settings_get_string("core.server.bind_ip");

    if (bindIp != NULL && strlen(bindIp) > 0)
    {
        TRACE_INFO("Binding to ip %s only\r\n", bindIp);
        ipStringToAddr(bindIp, &listenIpAddr);
        http_settings.ipAddr = listenIpAddr;
    }

    http_settings.maxConnections = APP_HTTP_MAX_CONNECTIONS - 1; // Workaround to prevent overflow crash?!
    http_settings.connections = httpConnections;
    osStrcpy(http_settings.rootDirectory, settings_get_string("internal.datadirfull"));
    osStrcpy(http_settings.defaultDocument, "index.shtm");

    http_settings.cgiCallback = httpServerCgiCallback;
    http_settings.requestCallback = httpServerWebRequestCallback;
    http_settings.uriNotFoundCallback = httpServerUriNotFoundCallback;
    http_settings.authCallback = httpServerAuthCallback;
    http_settings.port = settings_get_unsigned("core.server.http_port");
    http_settings.allowOrigin = strdup(settings_get_string("core.allowOrigin"));
    http_settings.isHttps = false;

    /* use them for HTTPS */
    https_web_settings = http_settings;
    https_web_settings.connections = httpsWebConnections;
    https_web_settings.port = settings_get_unsigned("core.server.https_web_port");
    https_web_settings.tlsInitCallback = httpServerTlsInitCallback;
    https_web_settings.allowOrigin = strdup(settings_get_string("core.allowOrigin"));
    https_web_settings.isHttps = true;

    /* use them for Box HTTPS */
    https_api_settings = https_web_settings;
    https_api_settings.connections = httpsApiConnections;
    https_api_settings.port = settings_get_unsigned("core.server.https_api_port");
    https_api_settings.tlsInitCallback = httpServerBoxTlsInitCallback;
    https_api_settings.requestCallback = httpServerAPIRequestCallback;

    error_t err = httpServerInit(&http_context, &http_settings);
    if (err != NO_ERROR)
    {
        TRACE_ERROR("httpServerInit() for HTTP failed with code %d\r\n", err);
        return;
    }
    err = httpServerInit(&https_web_context, &https_web_settings);
    if (err != NO_ERROR)
    {
        TRACE_ERROR("httpServerInit() for HTTPS Web failed with code %d\r\n", err);
        return;
    }
    err = httpServerInit(&https_api_context, &https_api_settings);
    if (err != NO_ERROR)
    {
        TRACE_ERROR("httpServerInit() for HTTPS API failed with code %d\r\n", err);
        return;
    }

    pcaplog_open();

    err = httpServerStart(&http_context);
    if (err != NO_ERROR)
    {
        TRACE_ERROR("httpServerStart() for HTTP failed with code %d\r\n", err);
        return;
    }
    err = httpServerStart(&https_web_context);
    if (err != NO_ERROR)
    {
        TRACE_ERROR("httpServerStart() for HTTPS failed with code %d\r\n", err);
        return;
    }
    err = httpServerStart(&https_api_context);
    if (err != NO_ERROR)
    {
        TRACE_ERROR("httpServerStart() for HTTPS failed with code %d\r\n", err);
        return;
    }

    tonies_init();
    if (get_settings()->core.tonies_json_auto_update || test)
    {
        tonies_update();
        tonieboxes_update();
    }

    systime_t last = osGetSystemTime();
    size_t openWebConnectionsLast = 0;
    size_t openAPIConnectionsLast = 0;
    while (!settings_get_bool("internal.exit"))
    {
        osDelayTask(250);
        settings_loop();
        systime_t now = osGetSystemTime();
        if ((now - last) / 1000 > 5)
        {
            last = now;
            sanityChecks();
        }
        mutex_manager_loop();

        size_t openConnections = 0;
        for (size_t i = 0; i < APP_HTTP_MAX_CONNECTIONS; i++)
        {
            HttpConnection *conn = &httpsWebConnections[i];
            if (!conn->running)
            {
                continue;
            }
            openConnections++;
            mutex_lock(MUTEX_CLIENT_CTX);
            client_ctx_t *client_ctx = &conn->private.client_ctx;
            if (client_ctx->settings == NULL)
            {
                mutex_unlock(MUTEX_CLIENT_CTX);
                continue;
            }
            settings_internal_t *internal = &client_ctx->settings->internal;
            if (internal->config_used)
            {
                time_t curr_time = time(NULL);
                internal->online = true;
                internal->last_connection = curr_time;
            }
            mutex_unlock(MUTEX_CLIENT_CTX);
        }
        if (openConnections != openWebConnectionsLast)
        {
            openWebConnectionsLast = openConnections;
            TRACE_INFO("%zu open HTTPS Web connections\r\n", openConnections);
        }
        openConnections = 0;
        for (size_t i = 0; i < APP_HTTP_MAX_CONNECTIONS; i++)
        {
            HttpConnection *conn = &httpsApiConnections[i];
            if (!conn->running)
            {
                continue;
            }
            openConnections++;
            mutex_lock(MUTEX_CLIENT_CTX);
            client_ctx_t *client_ctx = &conn->private.client_ctx;
            if (client_ctx->settings == NULL)
            {
                mutex_unlock(MUTEX_CLIENT_CTX);
                continue;
            }
            settings_internal_t *internal = &client_ctx->settings->internal;
            if (internal->config_used)
            {
                time_t curr_time = time(NULL);
                internal->online = true;
                internal->last_connection = curr_time;
            }
            mutex_unlock(MUTEX_CLIENT_CTX);
        }
        if (openConnections != openAPIConnectionsLast)
        {
            openAPIConnectionsLast = openConnections;
            TRACE_INFO("%zu open HTTPS API connections\r\n", openConnections);
        }
        for (size_t i = 0; i < MAX_OVERLAYS; i++)
        {
            settings_internal_t *internal = &get_settings_id(i)->internal;
            if (internal->config_init)
            {
                time_t curr_time = time(NULL);
                if (curr_time > internal->last_connection + 1)
                {
                    internal->online = false;
                }
            }
        }
        if (test == TRUE)
        {
            settings_set_bool("internal.exit", TRUE);
        }
    }
    tonies_deinit();
    mutex_manager_deinit();

    pcaplog_close();

    int ret = settings_get_signed("internal.returncode");
    TRACE_INFO("Exiting TeddyCloud with returncode %d\r\n", ret);

    exit(ret);
}

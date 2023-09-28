
#ifdef WIN32
#else
#include <sys/random.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"
#include "rand.h"
#include "tls_adapter.h"
#include "settings.h"
#include "returncodes.h"

#include "server_helpers.h"
#include "toniesJson.h"

#include "path.h"
#include "debug.h"
#include "os_port.h"

#include "mutex_manager.h"
#include "cloud_request.h"
#include "handler_cloud.h"
#include "handler_reverse.h"
#include "handler_rtnl.h"
#include "handler_api.h"
#include "handler_sse.h"
#include "proto/toniebox.pb.rtnl.pb-c.h"

#define APP_HTTP_MAX_CONNECTIONS 32
HttpConnection httpConnections[APP_HTTP_MAX_CONNECTIONS];
HttpConnection httpsConnections[APP_HTTP_MAX_CONNECTIONS];

enum eRequestMethod
{
    REQ_ANY,
    REQ_GET,
    REQ_POST
};

typedef struct
{
    enum eRequestMethod method;
    char *path;
    error_t (*handler)(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
} request_type_t;

/* const for now. later maybe dynamic? */
request_type_t request_paths[] = {
    /*binary handler (rtnl)*/
    {REQ_ANY, "*binary", &handleRtnl},
    /* reverse proxy handler */
    {REQ_ANY, "/reverse", &handleReverse},
    /* web interface directory */
    {REQ_GET, "/content/", &handleApiContent},
    /* custom API */
    {REQ_POST, "/api/fileDelete", &handleApiFileDelete},
    {REQ_POST, "/api/dirDelete", &handleApiDirectoryDelete},
    {REQ_POST, "/api/dirCreate", &handleApiDirectoryCreate},
    {REQ_POST, "/api/uploadCert", &handleApiUploadCert},
    {REQ_POST, "/api/uploadFirmware", &handleApiUploadFirmware},
    {REQ_GET, "/api/patchFirmware", &handleApiPatchFirmware},
    {REQ_POST, "/api/fileUpload", &handleApiFileUpload},
    {REQ_POST, "/api/pcmUpload", &handleApiPcmUpload},
    {REQ_GET, "/api/fileIndex", &handleApiFileIndex},
    {REQ_GET, "/api/stats", &handleApiStats},
    {REQ_GET, "/api/toniesJson", &handleApiToniesJson},

    {REQ_GET, "/api/trigger", &handleApiTrigger},
    {REQ_GET, "/api/getIndex", &handleApiGetIndex},
    {REQ_GET, "/api/getBoxes", &handleApiGetBoxes},
    {REQ_POST, "/api/assignUnknown", &handleApiAssignUnknown},
    {REQ_GET, "/api/get/", &handleApiGet},
    {REQ_POST, "/api/set/", &handleApiSet},
    {REQ_GET, "/api/sse", &handleApiSse},
    /* official tonies API */
    {REQ_GET, "/v1/time", &handleCloudTime},
    {REQ_GET, "/v1/ota", &handleCloudOTA},
    {REQ_GET, "/v1/claim", &handleCloudClaim},
    {REQ_GET, "/v1/content", &handleCloudContentV1},
    {REQ_GET, "/v2/content", &handleCloudContentV2},
    {REQ_POST, "/v1/freshness-check", &handleCloudFreshnessCheck},
    {REQ_POST, "/v1/log", &handleCloudLog},
    {REQ_POST, "/v1/cloud-reset", &handleCloudReset}};

error_t resGetData(const char_t *path, const uint8_t **data, size_t *length)
{
    TRACE_DEBUG("resGetData: %s (static response)\n", path);

    *data = (uint8_t *)"CONTENT\r\n";
    *length = (size_t)osStrlen((char *)*data);

    return NO_ERROR;
}

error_t httpServerRequestCallback(HttpConnection *connection, const char_t *uri)
{
    error_t error = NO_ERROR;

    stats_update("connections", 1);

    if (connection->tlsContext != NULL && osStrlen(connection->tlsContext->client_cert_issuer))
    {
        TRACE_DEBUG("Certificate authentication:\r\n");
        TRACE_DEBUG("  Issuer:     '%s'\r\n", connection->tlsContext->client_cert_issuer);
        TRACE_DEBUG("  Subject:    '%s'\r\n", connection->tlsContext->client_cert_subject);
        TRACE_DEBUG("  Serial:     '%s'\r\n", connection->tlsContext->client_cert_serial);
    }
    else
    {
        TRACE_DEBUG("No certificate authentication\r\n");
    }

    TRACE_DEBUG(" >> client requested '%s' via %s \n", uri, connection->request.method);

    mutex_lock(MUTEX_CLIENT_CTX);
    client_ctx_t *client_ctx = &connection->private.client_ctx;
    osMemset(client_ctx, 0x00, sizeof(client_ctx_t));
    client_ctx->settings = get_settings();

    if (connection->tlsContext)
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
                client_ctx->settings = get_settings_cn(commonName);
                osFreeMem(commonName);
            }
            else
            {
                client_ctx->settings = get_settings_cn(subject);
            }

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
    client_ctx->box_id = client_ctx->settings->commonName;
    client_ctx->box_name = client_ctx->settings->boxName;
    mutex_unlock(MUTEX_CLIENT_CTX);

    connection->response.keepAlive = connection->request.keepAlive;

    for (size_t i = 0; i < sizeof(request_paths) / sizeof(request_paths[0]); i++)
    {
        size_t pathLen = osStrlen(request_paths[i].path);
        if (!osStrncmp(request_paths[i].path, uri, pathLen) && ((request_paths[i].method == REQ_ANY) || (request_paths[i].method == REQ_GET && !osStrcasecmp(connection->request.method, "GET")) || (request_paths[i].method == REQ_POST && !osStrcasecmp(connection->request.method, "POST"))))
        {
            return (*request_paths[i].handler)(connection, uri, connection->request.queryString, client_ctx);
        }
    }

    if (!strcmp(uri, "/") || !strcmp(uri, "index.shtm"))
    {
        uri = "/index.html";
    }
    if (!strcmp(uri, "/web") || !strcmp(uri, "/web/"))
    {
        uri = "/web/index.html";
    }

    char_t *newUri = custom_asprintf("%s%s", client_ctx->settings->core.wwwdir, uri);

    error = httpSendResponse(connection, newUri);
    free(newUri);
    return error;
}

error_t httpServerUriNotFoundCallback(HttpConnection *connection, const char_t *uri)
{
    error_t error = NO_ERROR;

    error = httpSendErrorResponse(connection, 404,
                                  "The requested page could not be found");

    /*
    char_t *newUri = custom_asprintf("%s/404.html", get_settings()->core.wwwdir);
    error = httpSendResponse(connection, newUri);
    free(newUri);
    */

    return error;
}

void httpParseAuthorizationField(HttpConnection *connection, char_t *value)
{
    if (!strncmp(value, "BD ", 3))
    {
        if (strlen(value) != 3 + 2 * AUTH_TOKEN_LENGTH)
        {
            TRACE_WARNING("Authentication: Failed to parse auth token '%s'\r\n", value);
            return;
        }
        for (int pos = 0; pos < AUTH_TOKEN_LENGTH; pos++)
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

error_t httpServerTlsInitCallback(HttpConnection *connection, TlsContext *tlsContext)
{
    error_t error;

    // Set TX and RX buffer size
    error = tlsSetBufferSize(tlsContext, 2048, 2048);
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

    // Client authentication is not required
    error = tlsSetClientAuthMode(tlsContext, TLS_CLIENT_AUTH_OPTIONAL);
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
        TRACE_ERROR("  Failed to add cert: %d\r\n", error);
        return error;
    }

    // Successful processing
    return NO_ERROR;
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

    ret &= sanityCheckDir("core.datadir");
    ret &= sanityCheckDir("internal.datadirfull");
    ret &= sanityCheckDir("internal.wwwdirfull");
    ret &= sanityCheckDir("internal.contentdirfull");
    ret &= sanityCheckDir("core.certdir");

    if (!ret)
    {
        TRACE_ERROR("Sanity checks failed, exiting\r\n");
        settings_set_signed("internal.returncode", RETURNCODE_INVALID_CONFIG);
        settings_set_bool("internal.exit", true);
    }

    return ret;
}

void server_init()
{
    mutex_manager_init();
    if (!sanityChecks())
    {
        return;
    }
    settings_set_bool("internal.exit", FALSE);
    sse_init();
    tonies_init();

    HttpServerSettings http_settings;
    HttpServerSettings https_settings;
    HttpServerContext http_context;
    HttpServerContext https_context;
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

    http_settings.maxConnections = APP_HTTP_MAX_CONNECTIONS;
    http_settings.connections = httpConnections;
    osStrcpy(http_settings.rootDirectory, settings_get_string("internal.datadirfull"));
    osStrcpy(http_settings.defaultDocument, "index.shtm");

    http_settings.cgiCallback = httpServerCgiCallback;
    http_settings.requestCallback = httpServerRequestCallback;
    http_settings.uriNotFoundCallback = httpServerUriNotFoundCallback;
    http_settings.authCallback = httpServerAuthCallback;
    http_settings.port = settings_get_unsigned("core.server.http_port");
    http_settings.allowOrigin = strdup(settings_get_string("core.allowOrigin"));

    /* use them for HTTPS */
    https_settings = http_settings;
    https_settings.connections = httpsConnections;
    https_settings.port = settings_get_unsigned("core.server.https_port");
    https_settings.tlsInitCallback = httpServerTlsInitCallback;
    https_settings.allowOrigin = strdup(settings_get_string("core.allowOrigin"));

    if (httpServerInit(&http_context, &http_settings) != NO_ERROR)
    {
        TRACE_ERROR("httpServerInit() for HTTP failed\r\n");
        return;
    }
    if (httpServerInit(&https_context, &https_settings) != NO_ERROR)
    {
        TRACE_ERROR("httpServerInit() for HTTPS failed\r\n");
        return;
    }
    if (httpServerStart(&http_context) != NO_ERROR)
    {
        TRACE_ERROR("httpServerStart() for HTTP failed\r\n");
        return;
    }
    if (httpServerStart(&https_context) != NO_ERROR)
    {
        TRACE_ERROR("httpServerStart() for HTTPS failed\r\n");
        return;
    }

    systime_t last = osGetSystemTime();
    size_t openConnectionsLast = 0;
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
            HttpConnection *conn = &httpsConnections[i];
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
        if (openConnections != openConnectionsLast)
        {
            openConnectionsLast = openConnections;
            TRACE_INFO("%" PRIuSIZE " open HTTPS connections\r\n", openConnections);
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
    }
    tonies_deinit();
    mutex_manager_deinit();

    int ret = settings_get_signed("internal.returncode");
    TRACE_INFO("Exiting TeddyCloud with returncode %d\r\n", ret);

    exit(ret);
}

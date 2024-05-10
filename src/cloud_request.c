
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

#include <errno.h>
#include <stdlib.h>

#include "tls.h"
#include "pem_export.h"
#include "tls_cipher_suites.h"
#include "cloud_request.h"
#include "http/http_client.h"
#include "rand.h"
#include "debug.h"
#include "settings.h"

#include "tls_adapter.h"
#include "handler_api.h"
#include "settings.h"
#include "mqtt.h"
#include "platform.h"

#include "handler_cloud.h"

#define MAX_REDIRECTS 5

error_t httpClientTlsInitCallbackBase(HttpClientContext *context,
                                      TlsContext *tlsContext, const char *client_ca, const char *client_crt, const char *client_key)
{
    TRACE_INFO("Initializing TLS...\r\n");
    error_t error;

    // Select client operation mode
    error = tlsSetConnectionEnd(tlsContext, TLS_CONNECTION_END_CLIENT);
    // Any error to report?
    if (error)
        return error;

    // Set the PRNG algorithm to be used
    error = tlsSetPrng(tlsContext, rand_get_algo(), rand_get_context());
    // Any error to report?
    if (error)
        return error;

    if (client_ca != NULL)
    {
        // Import the list of trusted CA certificates
        error = tlsSetTrustedCaList(tlsContext, client_ca, strlen(client_ca));
        // Any error to report?
        if (error)
            return error;
    }

    if (client_crt != NULL && client_key != NULL)
    {
        // Import the client's certificate
        error = tlsAddCertificate(tlsContext, client_crt, strlen(client_crt), client_key, strlen(client_key));
        // Any error to report?
        if (error)
            return error;
    }

    tls_context_key_log_init(tlsContext);

    TRACE_INFO("Initializing TLS done\r\n");

    // Successful processing
    return NO_ERROR;
}
error_t httpClientTlsInitCallbackNoCA(HttpClientContext *context,
                                      TlsContext *tlsContext)
{
    return httpClientTlsInitCallbackBase(context, tlsContext, NULL, NULL, NULL);
}
error_t httpClientTlsInitCallbackClientAuthTonies(HttpClientContext *context,
                                                  TlsContext *tlsContext)
{
    // TODO fix code duplication with server.c
    req_cbr_t *cbr_ctx = context->sourceCtx;
    client_ctx_t *client_ctx = ((cbr_ctx_t *)cbr_ctx->ctx)->client_ctx;
    settings_t *settings = client_ctx->settings;

    const char *client_ca = settings->internal.client.ca;
    const char *client_crt = settings->internal.client.crt;
    const char *client_key = settings->internal.client.key;

    if (!client_ca || !client_crt || !client_key)
    {
        TRACE_ERROR("Failed to get certificates\r\n");
        return ERROR_FAILURE;
    }
    return httpClientTlsInitCallbackBase(context, tlsContext, client_ca, client_crt, client_key);
}

int_t cloud_request_get(const char *server, int port, const char *uri, const char *queryString, const uint8_t *hash, req_cbr_t *cbr)
{
    return cloud_request(server, port, true, uri, queryString, "GET", NULL, 0, hash, cbr);
}

int_t cloud_request_post(const char *server, int port, const char *uri, const char *queryString, const uint8_t *body, size_t bodyLen, const uint8_t *hash, req_cbr_t *cbr)
{
    return cloud_request(server, port, true, uri, queryString, "POST", body, bodyLen, hash, cbr);
}

char_t *ipv4AddrToString(Ipv4Addr ipAddr, char_t *str);

int_t cloud_request(const char *server, int port, bool https, const char *uri, const char *queryString, const char *method, const uint8_t *body, size_t bodyLen, const uint8_t *hash, req_cbr_t *cbr)
{
    return web_request(server, port, https, uri, queryString, method, body, bodyLen, hash, cbr, true, true);
}
error_t web_request(const char *server, int port, bool https, const char *uri, const char *queryString, const char *method, const uint8_t *body, size_t bodyLen, const uint8_t *hash, req_cbr_t *cbr, bool isCloud, bool printTextData)
{
    cbr_ctx_t *cbr_ctx = (cbr_ctx_t *)cbr->ctx;
    client_ctx_t *client_ctx = cbr_ctx->client_ctx;
    settings_t *settings;
    error_t error = NO_ERROR;
    static int redirect_counter = 0;

    if (client_ctx == NULL)
    {
        settings = get_settings();
    }
    else
    {
        settings = client_ctx->settings;
    }

    if (isCloud)
    {
        if (!settings->cloud.enabled)
        {
            TRACE_INFO("Cloud requests generally blocked in settings\r\n");
            stats_update("cloud_blocked", 1);
            return ERROR_ADDRESS_NOT_FOUND;
        }

        mqtt_sendEvent("CloudRequest", uri, client_ctx);
    }
    HttpClientContext httpClientContext;

    if (isCloud)
    {
        if (!server)
        {
            server = settings->cloud.remote_hostname;
        }
        if (port <= 0)
        {
            port = settings->cloud.remote_port;
        }

        stats_update("cloud_requests", 1);
    }
    TRACE_INFO("Connecting to HTTP server %s:%d...\r\n",
               server, port);

    httpClientInit(&httpClientContext);
    httpClientContext.sourceCtx = cbr;
    if (https)
    {
        HttpClientTlsInitCallback callback = httpClientTlsInitCallbackNoCA;
        if (isCloud)
            callback = httpClientTlsInitCallbackClientAuthTonies;
        error = httpClientRegisterTlsInitCallback(&httpClientContext, callback);
        if (error)
        {
            return error;
        }
    }

    error = httpClientSetVersion(&httpClientContext, HTTP_VERSION_1_1);
    if (error)
    {
        return error;
    }
    error = httpClientSetTimeout(&httpClientContext, 1000);
    if (error)
    {
        return error;
    }

    void *resolve_ctx = resolve_host(server);
    if (!resolve_ctx)
    {
        TRACE_ERROR("Failed to resolve ipv4 address!\r\n");
        if (isCloud)
            stats_update("cloud_failed", 1);
        return ERROR_ADDRESS_NOT_FOUND;
    }

    int pos = 0;
    do
    {
        IpAddr ipAddr;
        if (!resolve_get_ip(resolve_ctx, pos, &ipAddr))
        {
            break;
        }
        bool success = FALSE;

        char_t host[129];

        ipv4AddrToString(ipAddr.ipv4Addr, host);
        TRACE_INFO("  trying IP: %s\n", host);

        do
        {
            error = httpClientConnect(&httpClientContext, &ipAddr,
                                      port);
            // Any error to report?
            if (error)
            {
                // Debug message
                TRACE_ERROR("Failed to connect to HTTP server! Error=%s\r\n", error2text(error));
                if (isCloud)
                    stats_update("cloud_failed", 1);
                break;
            }

            // Create an HTTP request
            httpClientCreateRequest(&httpClientContext);
            httpClientSetMethod(&httpClientContext, method);
            httpClientSetUri(&httpClientContext, uri);
            httpClientSetQueryString(&httpClientContext, queryString);
            if (body && bodyLen > 0)
            {
                error = httpClientSetContentLength(&httpClientContext, bodyLen);
                if (error)
                {
                    // Debug message
                    TRACE_ERROR("Failed to set content length! Error=%s\r\n", error2text(error));
                    if (isCloud)
                        stats_update("cloud_failed", 1);
                    break;
                }
            }

            // Add HTTP header fields
            char host_line[128];
            snprintf(host_line, sizeof(host_line), "%s:%d", server, port);
            httpClientAddHeaderField(&httpClientContext, "Host", host_line);

            if (hash)
            {
                char tmp[3];
                char auth_line[128];

                osStrcpy(auth_line, "BD ");

                for (int pos = 0; pos < TONIE_AUTH_TOKEN_LENGTH; pos++)
                {
                    osSprintf(tmp, "%02X", hash[pos]);
                    osStrcat(auth_line, tmp);
                }
                httpClientAddHeaderField(&httpClientContext, "Authorization", auth_line);
            }

            if (cbr_ctx->user_agent)
            {
                httpClientAddHeaderField(&httpClientContext, "User-Agent", cbr_ctx->user_agent);
            }

            // Send HTTP request header
            error = httpClientWriteHeader(&httpClientContext);
            // Any error to report?
            if (error)
            {
                // Debug message
                TRACE_ERROR("Failed to write HTTP request header, error=%s!\r\n", error2text(error));
                if (isCloud)
                    stats_update("cloud_failed", 1);
                break;
            }
            // Send HTTP request body
            if (body && bodyLen > 0)
            {
                size_t n;
                error = httpClientWriteBody(&httpClientContext, body, bodyLen, &n, 0);
                // Any error to report?
                if (error)
                {
                    // Debug message
                    TRACE_ERROR("Failed to write HTTP request body, error=%s!\r\n", error2text(error));
                    if (isCloud)
                        stats_update("cloud_failed", 1);
                    break;
                }
            }

            // Receive HTTP response header
            error = httpClientReadHeader(&httpClientContext);
            // Any error to report?
            if (error)
            {
                // Debug message
                TRACE_ERROR("Failed to read HTTP response header!\r\n");
                if (isCloud)
                    stats_update("cloud_failed", 1);
                break;
            }

            success = TRUE;

            // Retrieve HTTP status code
            uint_t status = httpClientGetStatus(&httpClientContext);

            if (status)
            {
                TRACE_INFO("HTTP code: %u\r\n", status);

                if (status == 302 && redirect_counter < MAX_REDIRECTS)
                {
                    // Extract location from response header
                    const char *location = httpClientGetHeaderField(&httpClientContext, "Location");
                    if (!location)
                    {
                        TRACE_ERROR("302 Found but no Location header present.\r\n");
                        error = ERROR_INVALID_RESPONSE;
                        break;
                    }

                    TRACE_INFO("Redirecting to: %s\r\n", location);

                    redirect_counter++;

                    // Disconnect HTTP client
                    httpClientDisconnect(&httpClientContext);

                    char uri_base[256], uri_path[256], query_string[256];
                    // TODO: handling of relative URLs
                    split_url(location, uri_base, uri_path, query_string);

                    TRACE_DEBUG("URI Base: %s\r\n", uri_base);
                    TRACE_DEBUG("URI Path: %s\r\n", uri_path);
                    TRACE_DEBUG("Query String: %s\r\n", query_string);

                    error = web_request(uri_base, 443, true, uri_path, query_string, "GET", NULL, 0, NULL, cbr, false, false);
                    break;
                }
            }

            redirect_counter = 0;

            if (cbr && cbr->response)
            {
                cbr->response(cbr->ctx, &httpClientContext);
            }

            char content_type[64];

            strcpy(content_type, "");

            do
            {
                const char *header_name = NULL;
                const char *header_value = NULL;
                error_t ret = httpClientGetNextHeaderField(&httpClientContext, &header_name, &header_value);

                if (cbr && cbr->header)
                {
                    cbr->header(cbr->ctx, &httpClientContext, header_name, header_value);
                }

                if (ret != NO_ERROR)
                {
                    break;
                }

                if (!osStrcmp(header_name, "Content-Type"))
                {
                    osStrncpy(content_type, header_value, sizeof(content_type) - 1);
                    TRACE_INFO("Content-Type is %s\r\n", content_type);
                }
            } while (1);

            // Header field found?
            if (strlen(content_type) == 0)
            {
                TRACE_INFO("Content-Type header field not found!\r\n");
            }

            bool binary = true;
            if (!strncmp(content_type, "text", 4))
            {
                binary = false;
            }
            else if (!strncmp(content_type, "application/json", 16))
            {
                binary = false;
            }
            else
            {
                TRACE_INFO("Binary data, not dumping body\r\n");
            }

            size_t maxSize = 4096;
            uint8_t *buffer = osAllocMem(maxSize + 1);
            // Receive HTTP response body
            while (!error)
            {
                // Read data
                size_t length = 0;

                error = httpClientReadBody(&httpClientContext, buffer, maxSize, &length, 0);

                if (cbr && cbr->body)
                {
                    cbr->body(cbr->ctx, &httpClientContext, (const char *)buffer, length, error);
                }

                // Check status code
                if (!error)
                {
                    if (printTextData && !binary)
                    {
                        // Properly terminate the string with a NULL character
                        buffer[length] = '\0';
                        // Dump HTTP response body
                        TRACE_INFO("Response: '%s'\r\n", buffer);
                    }
                }
            }

            osFreeMem(buffer);

            // Any error to report?
            if (error != ERROR_END_OF_STREAM)
                break;

            // Close HTTP response body
            error = httpClientCloseBody(&httpClientContext);
            // Any error to report?
            if (error)
            {
                // Debug message
                TRACE_INFO("Failed to read HTTP response trailer!\r\n");
                if (isCloud)
                    stats_update("cloud_failed", 1);
                break;
            }

            // Gracefully disconnect from the HTTP server
            httpClientDisconnect(&httpClientContext);
            if (cbr && cbr->disconnect)
            {
                cbr->disconnect(cbr->ctx, &httpClientContext);
            }

            // Debug message
            TRACE_INFO("Connection closed\r\n");
        } while (0);

        if (success)
        {
            break;
        }
    } while (0);

    resolve_free(resolve_ctx);
    // Release HTTP client context
    httpClientDeinit(&httpClientContext);

    return error;
}

void split_url(const char *location, char *uri_base, char *uri_path, char *query_string)
{
    const char *scheme_end = strstr(location, "://");
    if (!scheme_end)
    {
        TRACE_ERROR("Invalid URL: Scheme not found\n");
        return;
    }
    // Move pointer to start after "://"
    scheme_end += 3;

    const char *path_start = strchr(scheme_end, '/');
    if (!path_start)
    {
        TRACE_ERROR("Invalid URL: Path not found\n");
        return;
    }
    const char *query_start = strchr(path_start, '?');

    if (query_start)
    {
        // Copy base URI without scheme
        strncpy(uri_base, scheme_end, path_start - scheme_end);
        uri_base[path_start - scheme_end] = '\0';

        // Copy path
        strncpy(uri_path, path_start, query_start - path_start);
        uri_path[query_start - path_start] = '\0';

        // Copy query string
        strcpy(query_string, query_start + 1);
    }
    else
    {
        // Copy base URI without scheme
        strncpy(uri_base, scheme_end, path_start - scheme_end);
        uri_base[path_start - scheme_end] = '\0';

        // Copy path
        strcpy(uri_path, path_start);

        // No query string
        query_string[0] = '\0';
    }
}

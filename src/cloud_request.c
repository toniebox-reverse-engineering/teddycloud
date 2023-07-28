
#ifdef WIN32
#include <winsock2.h>
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
#include "rng/yarrow.h"
#include "debug.h"
#include "settings.h"

#include "tls_adapter.h"
#include "handler_api.h"
#include "settings.h"

error_t httpClientTlsInitCallback(HttpClientContext *context,
                                  TlsContext *tlsContext)
{
    TRACE_INFO("Initializing TLS...\r\n");
    error_t error;

    // Select client operation mode
    error = tlsSetConnectionEnd(tlsContext, TLS_CONNECTION_END_CLIENT);
    // Any error to report?
    if (error)
        return error;

    // Set the PRNG algorithm to be used
    error = tlsSetPrng(tlsContext, YARROW_PRNG_ALGO, &yarrowContext);
    // Any error to report?
    if (error)
        return error;

    const char *client_ca = settings_get_string("internal.client.ca");
    const char *client_crt = settings_get_string("internal.client.crt");
    const char *client_key = settings_get_string("internal.client.key");

    if (!client_ca || !client_crt || !client_key)
    {
        TRACE_ERROR("Failed to get certificates\r\n");
        return ERROR_FAILURE;
    }

    // Import the list of trusted CA certificates
    error = tlsSetTrustedCaList(tlsContext, client_ca, strlen(client_ca));
    // Any error to report?
    if (error)
        return error;

    // Import the client's certificate
    error = tlsAddCertificate(tlsContext, client_crt, strlen(client_crt), client_key, strlen(client_key));

    // Any error to report?
    if (error)
        return error;

    TRACE_INFO("Initializing TLS done\r\n");

    // Successful processing
    return NO_ERROR;
}

int_t cloud_request_get(const char *server, int port, const char *uri, const char *queryString, const uint8_t *hash, req_cbr_t *cbr)
{
    return cloud_request(server, port, true, uri, queryString, "GET", NULL, 0, hash, cbr);
}

int_t cloud_request_post(const char *server, int port, const char *uri, const char *queryString, const uint8_t *body, size_t bodyLen, const uint8_t *hash, req_cbr_t *cbr)
{
    return cloud_request(server, port, true, uri, queryString, "POST", body, bodyLen, hash, cbr);
}

int_t cloud_request(const char *server, int port, bool https, const char *uri, const char *queryString, const char *method, const uint8_t *body, size_t bodyLen, const uint8_t *hash, req_cbr_t *cbr)
{
    if (!settings_get_bool("cloud.enabled"))
    {
        TRACE_ERROR("Cloud requests generally blocked in settings\r\n");
        stats_update("cloud_blocked", 1);
        return ERROR_ADDRESS_NOT_FOUND;
    }

    HttpClientContext httpClientContext;
    IpAddr ipAddr;

    if (!server)
    {
        server = settings_get_string("cloud.hostname");
    }
    if (port <= 0)
    {
        port = settings_get_unsigned("cloud.port");
    }

    stats_update("cloud_requests", 1);

    TRACE_INFO("Connecting to HTTP server %s:%d...\r\n",
               server, port);

    struct hostent *host = gethostbyname(server);

    if (host->h_addrtype != AF_INET)
    {
        TRACE_ERROR("Failed to resolve ipv4 address!\r\n");
        stats_update("cloud_failed", 1);
        return ERROR_ADDRESS_NOT_FOUND;
    }
    TRACE_INFO("  resolved as: %s\n", host->h_name);

    httpClientInit(&httpClientContext);
    error_t error;
    if (https)
    {
        error = httpClientRegisterTlsInitCallback(&httpClientContext,
                                                  httpClientTlsInitCallback);
        if (error)
        {
            return error;
        }
    }

    error = httpClientSetVersion(&httpClientContext, HTTP_VERSION_1_0);
    if (error)
    {
        return error;
    }
    error = httpClientSetTimeout(&httpClientContext, 1000);
    if (error)
    {
        return error;
    }

    struct in_addr **addr_list = (struct in_addr **)host->h_addr_list;

    for (int i = 0; addr_list[i] != NULL; i++)
    {
        bool success = FALSE;

        TRACE_INFO("  trying IP: %s\n", inet_ntoa(*addr_list[i]));
        memcpy(&ipAddr.ipv4Addr, &addr_list[i]->s_addr, 4);

        ipAddr.length = host->h_length;
        do
        {
            error = httpClientConnect(&httpClientContext, &ipAddr,
                                      port);
            // Any error to report?
            if (error)
            {
                // Debug message
                TRACE_ERROR("Failed to connect to HTTP server! Error=%u\r\n", error);
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
                    TRACE_ERROR("Failed to set content length! Error=%u\r\n", error);
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

                for (int pos = 0; pos < AUTH_TOKEN_LENGTH; pos++)
                {
                    osSprintf(tmp, "%02X", hash[pos]);
                    osStrcat(auth_line, tmp);
                }
                httpClientAddHeaderField(&httpClientContext, "Authorization", auth_line);
            }

            // Send HTTP request header
            error = httpClientWriteHeader(&httpClientContext);
            // Any error to report?
            if (error)
            {
                // Debug message
                TRACE_ERROR("Failed to write HTTP request header, error=%u!\r\n", error);
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
                    TRACE_ERROR("Failed to write HTTP request body, error=%u!\r\n", error);
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
                stats_update("cloud_failed", 1);
                break;
            }

            success = TRUE;

            // Retrieve HTTP status code
            uint_t status = httpClientGetStatus(&httpClientContext);

            if (cbr && cbr->response)
            {
                cbr->response(cbr->ctx, &httpClientContext);
            }

            if (status)
            {
                TRACE_INFO("HTTP code: %u\r\n", status);
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
                    if (!binary)
                    {
                        // Properly terminate the string with a NULL character
                        buffer[maxSize] = '\0';
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
    }

    // Release HTTP client context
    httpClientDeinit(&httpClientContext);

    return 0;
}
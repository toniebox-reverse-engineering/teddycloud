
#include <sys/random.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

// Dependencies
#include <stdlib.h>
#include "tls.h"
#include "pem_export.h"
#include "tls_cipher_suites.h"
#include "http/http_client.h"
#include "rng/yarrow.h"
#include "debug.h"

#include "tls_adapter.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

    // Import the list of trusted CA certificates
    error = tlsSetTrustedCaList(tlsContext, trustedCaList, trustedCaListLen);
    // Any error to report?
    if (error)
        return error;

    // Import the client's certificate
    error = tlsAddCertificate(tlsContext, clientCert, clientCertLen,
                              clientPrivateKey, clientPrivateKeyLen);
    // Any error to report?
    if (error)
        return error;

    // Successful processing
    return NO_ERROR;
}

int_t cloud_request_get(const char *server, int port, const char *request, const char *hash)
{
    HttpClientContext httpClientContext;
    IpAddr ipAddr;

    if (!server)
    {
        server = "prod.de.tbs.toys";
    }
    if (port <= 0)
    {
        port = 443;
    }

    TRACE_INFO("# Connecting to HTTP server %s:%d...\r\n",
               server, port);

    struct hostent *host = gethostbyname(server);

    if (host->h_addrtype != AF_INET)
    {
        TRACE_ERROR("Failed to resolve ipv4 address!\r\n");
        return ERROR_ADDRESS_NOT_FOUND;
    }
    TRACE_INFO("#   resolved as: %s\n", host->h_name);

    httpClientInit(&httpClientContext);
    error_t error = httpClientRegisterTlsInitCallback(&httpClientContext,
                                                      httpClientTlsInitCallback);

    error = httpClientSetVersion(&httpClientContext, HTTP_VERSION_1_0);
    error = httpClientSetTimeout(&httpClientContext, 1000);

    struct in_addr **addr_list = (struct in_addr **)host->h_addr_list;

    for (int i = 0; addr_list[i] != NULL; i++)
    {
        bool success = FALSE;
        TRACE_INFO("#  trying IP: %s\n", inet_ntoa(*addr_list[i]));
        memcpy(&ipAddr.ipv4Addr, &addr_list[i]->s_addr, 4);

        ipAddr.length = host->h_length;
        do
        {
            // Debug message

            // Connect to the HTTP server
            error = httpClientConnect(&httpClientContext, &ipAddr,
                                      port);
            // Any error to report?
            if (error)
            {
                // Debug message
                TRACE_ERROR("Failed to connect to HTTP server!\r\n");
                break;
            }

            // Create an HTTP request
            httpClientCreateRequest(&httpClientContext);
            httpClientSetMethod(&httpClientContext, "GET");
            httpClientSetUri(&httpClientContext, request);

            // Add HTTP header fields
            char host_line[128];
            snprintf(host_line, sizeof(host_line), "%s:%d", server, port);
            httpClientAddHeaderField(&httpClientContext, "Host", host_line);

            if (hash)
            {
                char auth_line[128];
                sprintf(auth_line, "BD %s", hash);
                httpClientAddHeaderField(&httpClientContext, "Authorization", auth_line);
            }

            // Send HTTP request header
            error = httpClientWriteHeader(&httpClientContext);
            // Any error to report?
            if (error)
            {
                // Debug message
                TRACE_ERROR("Failed to write HTTP request header!\r\n");
                break;
            }

            // Receive HTTP response header
            error = httpClientReadHeader(&httpClientContext);
            // Any error to report?
            if (error)
            {
                // Debug message
                TRACE_ERROR("Failed to read HTTP response header!\r\n");
                break;
            }

            success = TRUE;

            // Retrieve HTTP status code
            uint_t status = httpClientGetStatus(&httpClientContext);
            // Debug message
            TRACE_INFO("HTTP code: %u\r\n", status);

            // Retrieve the value of the Content-Type header field
            const char *content_type = httpClientGetHeaderField(&httpClientContext, "Content-Type");

            // Header field found?
            if (content_type != NULL)
            {
                // Debug message
                TRACE_INFO("# Content-Type is %s\r\n", content_type);
            }
            else
            {
                // Debug message
                TRACE_INFO("# Content-Type header field not found!\r\n");
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

            // Receive HTTP response body
            while (!error)
            {
                // Read data
                size_t length;
                char_t buffer[128];
                error = httpClientReadBody(&httpClientContext, buffer,
                                           sizeof(buffer) - 1, &length, 0);

                // Check status code
                if (!error)
                {
                    if (!binary)
                    {
                        // Properly terminate the string with a NULL character
                        buffer[length] = '\0';
                        // Dump HTTP response body
                        TRACE_INFO("%s", buffer);
                    }
                }
            }
            // Terminate the HTTP response body with a CRLF
            TRACE_INFO("\r\n");

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
                break;
            }

            // Gracefully disconnect from the HTTP server
            httpClientDisconnect(&httpClientContext);

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
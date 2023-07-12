
#include <sys/random.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"
#include "rng/yarrow.h"
#include "tls_adapter.h"
#include "settings.h"
#include "debug.h"

#include "cloud_request.h"
#include "handler_cloud.h"
#include "handler_reverse.h"
#include "handler_api.h"
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
    error_t (*handler)(HttpConnection *connection, const char_t *uri);
} request_type_t;

error_t handleWww(HttpConnection *connection, const char_t *uri)
{
    return httpSendResponse(connection, &uri[4]);
}

/* const for now. later maybe dynamic? */
request_type_t request_paths[] = {
    /* reverse proxy handler */
    {REQ_ANY, "/reverse", &handleReverse},
    /* web interface directory */
    {REQ_GET, "/www", &handleWww},
    /* custom API */
    {REQ_GET, "/api/stats", &handleApiStats},
    {REQ_GET, "/api/get", &handleApiGet},
    {REQ_GET, "/api/trigger", &handleApiTrigger},
    {REQ_POST, "/api/set", &handleApiSet},
    /* official boxine API */
    {REQ_GET, "/v1/time", &handleCloudTime},
    {REQ_GET, "/v1/ota", &handleCloudOTA},
    {REQ_GET, "/v1/claim", &handleCloudClaim},
    {REQ_GET, "/v2/content", &handleCloudContent},
    {REQ_POST, "/v1/freshness-check", &handleCloudFreshnessCheck},
    {REQ_POST, "/v1/log", &handleCloudLog}};

char_t *ipv4AddrToString(Ipv4Addr ipAddr, char_t *str)
{
    uint8_t *p;
    static char_t buffer[16];

    // If the NULL pointer is given as parameter, then the internal buffer is used
    if (str == NULL)
        str = buffer;

    // Cast the address to byte array
    p = (uint8_t *)&ipAddr;
    // Format IPv4 address
    osSprintf(str, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "", p[0], p[1], p[2], p[3]);

    // Return a pointer to the formatted string
    return str;
}
char_t *ipv6AddrToString(const Ipv6Addr *ipAddr, char_t *str)
{
    static char_t buffer[40];
    uint_t i;
    uint_t j;
    char_t *p;

    // Best run of zeroes
    uint_t zeroRunStart = 0;
    uint_t zeroRunEnd = 0;

    // If the NULL pointer is given as parameter, then the internal buffer is used
    if (str == NULL)
        str = buffer;

    // Find the longest run of zeros for "::" short-handing
    for (i = 0; i < 8; i++)
    {
        // Compute the length of the current sequence of zeroes
        for (j = i; j < 8 && !ipAddr->w[j]; j++)
            ;

        // Keep track of the longest one
        if ((j - i) > 1 && (j - i) > (zeroRunEnd - zeroRunStart))
        {
            // The symbol "::" should not be used to shorten just one zero field
            zeroRunStart = i;
            zeroRunEnd = j;
        }
    }

    // Format IPv6 address
    for (p = str, i = 0; i < 8; i++)
    {
        // Are we inside the best run of zeroes?
        if (i >= zeroRunStart && i < zeroRunEnd)
        {
            // Append a separator
            *(p++) = ':';
            // Skip the sequence of zeroes
            i = zeroRunEnd - 1;
        }
        else
        {
            // Add a separator between each 16-bit word
            if (i > 0)
                *(p++) = ':';

            // Convert the current 16-bit word to string
            p += osSprintf(p, "%" PRIx16, ntohs(ipAddr->w[i]));
        }
    }

    // A trailing run of zeroes has been found?
    if (zeroRunEnd == 8)
        *(p++) = ':';

    // Properly terminate the string
    *p = '\0';

    // Return a pointer to the formatted string
    return str;
}
char_t *ipAddrToString(const IpAddr *ipAddr, char_t *str)
{
#if (IPV4_SUPPORT == ENABLED)
    // IPv4 address?
    if (ipAddr->length == sizeof(Ipv4Addr))
    {
        // Convert IPv4 address to string representation
        return ipv4AddrToString(ipAddr->ipv4Addr, str);
    }
    else
#endif
#if (IPV6_SUPPORT == ENABLED)
        // IPv6 address?
        if (ipAddr->length == sizeof(Ipv6Addr))
        {
            // Convert IPv6 address to string representation
            return ipv6AddrToString(&ipAddr->ipv6Addr, str);
        }
        else
#endif
        // Invalid IP address?
        {
            static char_t c;

            // The last parameter is optional
            if (str == NULL)
            {
                str = &c;
            }

            // Properly terminate the string
            str[0] = '\0';

            // Return an empty string
            return str;
        }
}

error_t resGetData(const char_t *path, const uint8_t **data, size_t *length)
{
    TRACE_INFO("resGetData: %s (static response)\n", path);

    *data = (uint8_t *)"CONTENT\r\n";
    *length = (size_t)osStrlen((char *)*data);

    return NO_ERROR;
}

error_t
httpServerRequestCallback(HttpConnection *connection,
                          const char_t *uri)
{
    stats_update("connections", 1);

    if (connection->tlsContext != NULL && connection->tlsContext->cert != NULL)
    {
        if (connection->tlsContext->clientCertRequested)
        {
            TRACE_INFO(" Client cert requested\r\n");
        }
        TRACE_INFO(" ID: -1 CertType=%i AuthMode=%i \n", connection->tlsContext->peerCertType, connection->tlsContext->clientAuthMode);
        for (size_t i = 0; i < connection->tlsContext->numCerts; i++)
        {
            TRACE_INFO(" ID: %li CertType=%i \n", i, connection->tlsContext->certs[i].type);
        }
    }
    else
    {
        TRACE_INFO(" No Cert or TLS\r\n");
    }

    TRACE_INFO(" >> client requested '%s' via %s \n", uri, connection->request.method);
    for (size_t i = 0; i < sizeof(request_paths) / sizeof(request_paths[0]); i++)
    {
        size_t pathLen = osStrlen(request_paths[i].path);
        if (!osStrncmp(request_paths[i].path, uri, pathLen) && ((request_paths[i].method == REQ_ANY) || (request_paths[i].method == REQ_GET && !osStrcasecmp(connection->request.method, "GET")) || (request_paths[i].method == REQ_POST && !osStrcasecmp(connection->request.method, "POST"))))
        {
            return (*request_paths[i].handler)(connection, uri);
        }
    }

    if (!strcmp(uri, "/") || !strcmp(uri, "index.shtm"))
    {
        return httpSendResponse(connection, "index.html");
    }

    char dest[128];
    snprintf(dest, sizeof(dest), "www/%s", uri);
    return httpSendResponse(connection, dest);
}

error_t httpServerUriNotFoundCallback(HttpConnection *connection,
                                      const char_t *uri)
{
    return httpSendResponse(connection, "404.html");
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
    TRACE_INFO("httpAddAuthenticateField\r\n");
    return 0;
}

error_t httpServerCgiCallback(HttpConnection *connection,
                              const char_t *param)
{
    // Not implemented
    TRACE_INFO("httpServerCgiCallback: %s\r\n", param);
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
    error = tlsSetPrng(tlsContext, YARROW_PRNG_ALGO, &yarrowContext);
    // Any error to report?
    if (error)
        return error;

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

    error = tlsAddCertificate(tlsContext, serverCert, serverCertLen, serverKey, serverKeyLen);
    // Any error to report?
    if (error)
    {
        if (error == ERROR_BAD_CERTIFICATE)
        {
            TRACE_INFO("Adding certificate failed: ERROR_BAD_CERTIFICATE\r\n");
        }
        else
        {
            TRACE_INFO("Adding certificate failed: %d\r\n", error);
        }
        return error;
    }

    // Successful processing
    return NO_ERROR;
}

void server_init()
{
    settings_set_bool("internal.exit", FALSE);

    HttpServerSettings http_settings;
    HttpServerSettings https_settings;
    HttpServerContext http_context;
    HttpServerContext https_context;

    /* setup settings for HTTP */
    httpServerGetDefaultSettings(&http_settings);

    http_settings.maxConnections = APP_HTTP_MAX_CONNECTIONS;
    http_settings.connections = httpConnections;
    strcpy(http_settings.rootDirectory, "www/");
    strcpy(http_settings.defaultDocument, "index.shtm");

    http_settings.cgiCallback = httpServerCgiCallback;
    http_settings.requestCallback = httpServerRequestCallback;
    http_settings.uriNotFoundCallback = httpServerUriNotFoundCallback;
    http_settings.authCallback = httpServerAuthCallback;
    http_settings.port = 80;

    /* use them for HTTPS */
    https_settings = http_settings;
    https_settings.connections = httpsConnections;
    https_settings.port = 443;
    https_settings.tlsInitCallback = httpServerTlsInitCallback;

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

    while (!settings_get_bool("internal.exit"))
    {
        usleep(100000);
    }

    TRACE_INFO("Exiting TeddyClout with returncode %d\r\n", settings_get_integer("internal.returncode"));
    usleep(100000);

    exit(settings_get_integer("internal.returncode"));
}
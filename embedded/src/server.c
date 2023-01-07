
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
#include "debug.h"

#define APP_HTTP_MAX_CONNECTIONS 32
HttpConnection httpConnections[APP_HTTP_MAX_CONNECTIONS];

char_t *ipAddrToString(const IpAddr *ipAddr, char_t *str)
{
    return "(not implemented)";
}

error_t resGetData(const char_t *path, const uint8_t **data, size_t *length)
{
    TRACE_INFO("resGetData: %s (static response)\n", path);

    *data = "CONTENT\r\n";
    *length = strlen(*data);

    return NO_ERROR;
}

error_t httpServerRequestCallback(HttpConnection *connection,
                                  const char_t *uri)
{
    // Not implemented yet. here we can stream data, but have to provide the headers and stuff ourselves

    TRACE_INFO("httpServerRequestCallback: %s (ignoring)\n", uri);

    return ERROR_NOT_FOUND;
}

error_t httpServerUriNotFoundCallback(HttpConnection *connection,
                                      const char_t *uri)
{
    TRACE_INFO("httpServerUriNotFoundCallback: %s (ignoring)\n", uri);
    return ERROR_NOT_FOUND;
}

error_t httpServerCgiCallback(HttpConnection *connection,
                              const char_t *param)
{
    // Not implemented
    TRACE_INFO("httpServerCgiCallback: %s\n", param);
    return ERROR_NOT_FOUND;
}

void server_init()
{
    HttpServerSettings settings;
    HttpServerContext context;

    httpServerGetDefaultSettings(&settings);
    settings.interface = NULL;
    settings.port = 80;
    settings.maxConnections = APP_HTTP_MAX_CONNECTIONS;
    settings.connections = httpConnections;

    strcpy(settings.rootDirectory, "www/");
    strcpy(settings.defaultDocument, "index.shtm");

    settings.cgiCallback = httpServerCgiCallback;
    settings.requestCallback = httpServerRequestCallback;
    settings.uriNotFoundCallback = httpServerUriNotFoundCallback;

    httpServerInit(&context, &settings);
    httpServerStart(&context);

    while (1)
    {
        sleep(100);
    }
}
#include <inttypes.h>
#include <stdio.h>

#include "core/net.h"
#include "http/http_server.h"
#include "str.h"
#include "debug.h"
#include "http_ext.h"

void httpExtParseRequestHeaderField(HttpConnection *connection, const char *name, char *value)
{
    if (osStrcasecmp(name, "Range") == 0)
    {
        sscanf(value, "bytes=%" PRIu32 "-%" PRIu32, &connection->request.Range.start, &connection->request.Range.end);
    }
    else if (osStrcasecmp(name, "If-Range") == 0)
    {
        strSafeCopy(connection->request.ifRange, value, HTTP_SERVER_IFRANGE_MAX_LEN);
    }
    else if (osStrcasecmp(name, "User-Agent") == 0)
    {
        strSafeCopy(connection->request.userAgent, value, sizeof(connection->request.userAgent));
    }
}

size_t httpExtFormatResponseHeader(HttpConnection *connection, char *p)
{
    char *start = p;

    p += osSprintf(p, "Accept-Ranges: bytes\r\n");

    char_t *allowOrigin = connection->serverContext->settings.allowOrigin;
    if (allowOrigin != NULL && osStrlen(allowOrigin) > 0)
    {
        p += osSprintf(p, "Access-Control-Allow-Origin: %s\r\n", allowOrigin);
    }

    if (connection->response.contentRange != NULL)
    {
        p += osSprintf(p, "Content-Range: %s\r\n", connection->response.contentRange);
    }

    return p - start;
}

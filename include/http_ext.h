#pragma once

/*
 * teddycloud's additions to Cyclone's HTTP server. They plug in through the
 * HTTP_*_HOOK / HTTP_*_PRIVATE_HEADER_FIELDS configuration macros, which are
 * what Cyclone 2.6 offers for this (backported to the vendored server).
 */

#include <stddef.h>
#include <stdint.h>

#define HTTP_SERVER_IFRANGE_MAX_LEN 31

typedef struct
{
    uint32_t start;
    uint32_t end;
    uint32_t size;
} HttpRangeHeader;

#define HTTP_REQUEST_PRIVATE_HEADER_FIELDS      \
    char userAgent[128 + 1];                    \
    char ifRange[HTTP_SERVER_IFRANGE_MAX_LEN + 1]; \
    HttpRangeHeader Range;

#define HTTP_RESPONSE_PRIVATE_HEADER_FIELDS \
    const char *contentRange;

struct _HttpConnection;

/* Range, If-Range and User-Agent */
void httpExtParseRequestHeaderField(struct _HttpConnection *connection, const char *name, char *value);
/* Accept-Ranges, Access-Control-Allow-Origin and Content-Range, returns the length written to p */
size_t httpExtFormatResponseHeader(struct _HttpConnection *connection, char *p);

#define HTTP_PARSE_REQUEST_HEADER_FIELD_HOOK(connection, name, value) httpExtParseRequestHeaderField(connection, name, value)
#define HTTP_FORMAT_RESPONSE_HEADER_HOOK(connection, p) (p) += httpExtFormatResponseHeader(connection, p)

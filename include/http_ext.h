#pragma once

/*
 * teddycloud's additions to Cyclone's HTTP server. They plug in through the
 * HTTP_*_HOOK / HTTP_*_PRIVATE_HEADER_FIELDS configuration macros, which are
 * what Cyclone 2.6 offers for this (backported to the vendored server).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "compiler_port.h"
#include "error.h"

#define HTTP_SERVER_IFRANGE_MAX_LEN 31

typedef struct
{
    uint32_t start;
    uint32_t end; /* 0 if not given */
    uint32_t size;
    bool valid;   /* a "bytes=N-" / "bytes=N-M" range was sent (start 0 included) */
    bool has_end; /* M was given */
} HttpRangeHeader;

typedef enum
{
    HTTP_RANGE_FULL,          /* no (usable) range: send everything with 200 */
    HTTP_RANGE_PARTIAL,       /* send bytes first..last with 206 */
    HTTP_RANGE_UNSATISFIABLE  /* start is behind the end: 416 */
} HttpRangeResult;

/* range_ext.c: what to answer for a Range request on a resource of the given size */
HttpRangeResult httpExtResolveRange(const HttpRangeHeader *range, uint32_t size, uint32_t *first, uint32_t *last);

#define HTTP_REQUEST_PRIVATE_HEADER_FIELDS      \
    char userAgent[128 + 1];                    \
    char ifRange[HTTP_SERVER_IFRANGE_MAX_LEN + 1]; \
    HttpRangeHeader Range;

#define HTTP_RESPONSE_PRIVATE_HEADER_FIELDS \
    const char *contentRange;

struct _HttpConnection;
struct _HttpClientContext;

/* Range, If-Range and User-Agent */
void httpExtParseRequestHeaderField(struct _HttpConnection *connection, const char *name, char *value);
/* Accept-Ranges, Access-Control-Allow-Origin and Content-Range, returns the length written to p */
size_t httpExtFormatResponseHeader(struct _HttpConnection *connection, char *p);

/* like httpSendResponse(), see http_ext.c; Unsafe takes the absolute path instead of resolving uri */
error_t httpExtSendResponse(struct _HttpConnection *connection, const char *uri);
error_t httpExtSendResponseUnsafe(struct _HttpConnection *connection, const char *uri, const char *absolutePath);
error_t httpExtSendResponseStream(struct _HttpConnection *connection, const char *uri, bool_t isStream);
error_t httpExtSendResponseStreamUnsafe(struct _HttpConnection *connection, const char *uri, const char *absolutePath, bool_t isStream);

/* pcap log of the plain HTTP traffic (above TLS), called from the vendored transport functions */
void httpExtPcapServerWrite(struct _HttpConnection *connection, bool is_tx, const void *data, size_t length);
void httpExtPcapClientReset(struct _HttpClientContext *context);
void httpExtPcapClientWrite(struct _HttpClientContext *context, bool is_tx, const void *data, size_t length);

#define HTTP_PARSE_REQUEST_HEADER_FIELD_HOOK(connection, name, value) httpExtParseRequestHeaderField(connection, name, value)
#define HTTP_FORMAT_RESPONSE_HEADER_HOOK(connection, p) (p) += httpExtFormatResponseHeader(connection, p)

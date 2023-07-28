#include "debug.h"

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

#define CONTENT_LENGTH_UNKNOWN ((size_t)-1)

error_t httpWriteResponseString(HttpConnection *connection, char_t *data, bool_t freeMemory);
error_t httpWriteResponse(HttpConnection *connection, void *data, size_t size, bool_t freeMemory);
error_t httpWriteString(HttpConnection *connection, const char_t *content);
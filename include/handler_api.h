#include "debug.h"

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

void stats_update(const char *item, int count);
error_t handleApiStats(HttpConnection *connection, const char_t *uri);
error_t handleApiGet(HttpConnection *connection, const char_t *uri);
error_t handleApiSet(HttpConnection *connection, const char_t *uri);

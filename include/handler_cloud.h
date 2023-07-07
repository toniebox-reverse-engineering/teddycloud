#include "debug.h"

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

#define BODY_BUFFER_SIZE 4096

void getContentPathFromCharRUID(char ruid[17], char contentPath[30]);
void getContentPathFromUID(uint64_t uid, char contentPath[30]);

error_t httpWriteResponse(HttpConnection *connection, const void *data, bool_t freeMemory);
void httpPrepareHeader(HttpConnection *connection, const void *contentType, size_t contentLength);

error_t handleCloudTime(HttpConnection *connection, const char_t *uri);
error_t handleCloudOTA(HttpConnection *connection, const char_t *uri);
error_t handleCloudLog(HttpConnection *connection, const char_t *uri);
error_t handleCloudClaim(HttpConnection *connection, const char_t *uri);
error_t handleCloudContent(HttpConnection *connection, const char_t *uri);
error_t handleCloudFreshnessCheck(HttpConnection *connection, const char_t *uri);
#include "debug.h"

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

#define BODY_BUFFER_SIZE 4096

typedef struct
{
    char contentPath[30];
    bool_t exists;
    bool_t nocloud;
    bool_t live;
} tonie_info_t;

void getContentPathFromCharRUID(char ruid[17], char contentPath[30]);
void getContentPathFromUID(uint64_t uid, char contentPath[30]);
tonie_info_t getTonieInfo(char contentPath[30]);

error_t httpWriteResponse(HttpConnection *connection, void *data, bool_t freeMemory);
void httpPrepareHeader(HttpConnection *connection, const void *contentType, size_t contentLength);

error_t handleCloudTime(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudOTA(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudLog(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudClaim(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudContent(HttpConnection *connection, const char_t *uri, const char_t *queryString, bool_t noPassword);
error_t handleCloudContentV1(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudContentV2(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudFreshnessCheck(HttpConnection *connection, const char_t *uri, const char_t *queryString);
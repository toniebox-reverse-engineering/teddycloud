#include "debug.h"

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

#include "proto/toniebox.pb.taf-header.pb-c.h"

#define BODY_BUFFER_SIZE 4096
#define TAF_HEADER_SIZE 4096

typedef struct
{
    char *contentPath;
    bool_t exists;
    bool_t valid;
    bool_t nocloud;
    bool_t live;
    bool_t updated;
    TonieboxAudioFileHeader *tafHeader;
} tonie_info_t;

void getContentPathFromCharRUID(char ruid[17], char **pcontentPath);
void getContentPathFromUID(uint64_t uid, char **pcontentPath);
tonie_info_t getTonieInfo(const char *contentPath);
void freeTonieInfo(tonie_info_t *tonieInfo);

error_t httpWriteResponse(HttpConnection *connection, void *data, bool_t freeMemory);
void httpPrepareHeader(HttpConnection *connection, const void *contentType, size_t contentLength);

error_t handleCloudTime(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudOTA(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudLog(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudClaim(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudContent(HttpConnection *connection, const char_t *uri, const char_t *queryString, bool_t noPassword);
error_t handleCloudContentV1(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudContentV2(HttpConnection *connection, const char_t *uri, const char_t *queryString);
<<<<<<< HEAD
error_t handleCloudFreshnessCheck(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleCloudReset(HttpConnection *connection, const char_t *uri, const char_t *queryString);
=======
error_t handleCloudFreshnessCheck(HttpConnection *connection, const char_t *uri, const char_t *queryString);
>>>>>>> e6efbc1 (passthrough queryString)

#include "debug.h"

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

void stats_update(const char *item, int count);
error_t handleApiUploadCert(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleApiStats(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleApiGetIndex(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleApiGet(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleApiSet(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleApiTrigger(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleApiFileIndex(HttpConnection *connection, const char_t *uri, const char_t *queryString);
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> bcbad4f (fix web interface, uploading etc)
error_t handleApiFileUpload(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleApiDirectoryCreate(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleApiFileDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString);
error_t handleApiDirectoryDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString);
<<<<<<< HEAD
=======
error_t handleApiFileUpload(HttpConnection *connection, const char_t *uri, const char_t *queryString);
>>>>>>> e6efbc1 (passthrough queryString)
=======
>>>>>>> bcbad4f (fix web interface, uploading etc)

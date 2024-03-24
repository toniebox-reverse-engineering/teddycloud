#ifndef _HANDLER_H
#define _HANDLER_H
#include "debug.h"

#include "core/net.h"
#include "core/ethernet.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "http/http_server.h"
#include "http/http_server_misc.h"

#include "proto/toniebox.pb.taf-header.pb-c.h"
#include "proto/toniebox.pb.freshness-check.fc-request.pb-c.h"
#include "proto/toniebox.pb.freshness-check.fc-response.pb-c.h"
#include "settings.h"
#include "cloud_request.h"

#include "contentJson.h"

#define CONTENT_LENGTH_UNKNOWN ((size_t)-1)

typedef struct
{
    char *contentPath;
    bool_t exists;
    bool_t valid;
    bool_t updated;
    bool_t stream;
    contentJson_t json;
    TonieboxAudioFileHeader *tafHeader;
} tonie_info_t;

#define PROX_STATUS_IDLE 0
#define PROX_STATUS_CONN 1
#define PROX_STATUS_HEAD 2
#define PROX_STATUS_BODY 3
#define PROX_STATUS_DONE 4

typedef enum
{
    API_NONE = 0,
    V1_TIME,
    V1_OTA,
    V1_CLAIM,
    V2_CONTENT,
    V1_FRESHNESS_CHECK,
    V1_LOG,
    V1_CLOUDRESET
} cloudapi_t;

typedef enum
{
    OTA_FIRMWARE_PD = 2,
    OTA_FIRMWARE_EU = 3,
    OTA_SERVICEPACK_CC3200 = 4,
    OTA_HTML_CONFIG = 5,
    OTA_SFX_BIN = 6,
} cloudapi_ota_t;

typedef struct
{
    const char_t *uri;
    const char_t *queryString;
    cloudapi_t api;
    char_t *buffer;
    size_t bufferPos;
    size_t bufferLen;
    uint32_t status;
    FsFile *file;
    tonie_info_t *tonieInfo;
    void *customData;
    size_t customDataLen;
    HttpConnection *connection;
    client_ctx_t *client_ctx;
} cbr_ctx_t;

void fillBaseCtx(HttpConnection *connection, const char_t *uri, const char_t *queryString, cloudapi_t api, cbr_ctx_t *ctx, client_ctx_t *client_ctx);
req_cbr_t getCloudCbr(HttpConnection *connection, const char_t *uri, const char_t *queryString, cloudapi_t api, cbr_ctx_t *ctx, client_ctx_t *client_ctx);
void cbrCloudResponsePassthrough(void *src_ctx, HttpClientContext *cloud_ctx);
void cbrCloudHeaderPassthrough(void *src_ctx, HttpClientContext *cloud_ctx, const char *header, const char *value);
void cbrCloudBodyPassthrough(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error);
void cbrCloudServerDiscoPassthrough(void *src_ctx, HttpClientContext *cloud_ctx);

char *strupr(char input[]);

#define TAF_HEADER_SIZE 4092

void getContentPathFromCharRUID(char ruid[17], char **pcontentPath, settings_t *settings);
void getContentPathFromUID(uint64_t uid, char **pcontentPath, settings_t *settings);
void setTonieboxSettings(TonieFreshnessCheckResponse *freshResp, settings_t *settings);
bool_t isValidTaf(const char *contentPath);
tonie_info_t *getTonieInfoFromUid(uint64_t uid, settings_t *settings);
tonie_info_t *getTonieInfoFromRuid(char ruid[17], settings_t *settings);
tonie_info_t *getTonieInfo(const char *contentPath, settings_t *settings);
void freeTonieInfo(tonie_info_t *tonieInfo);

void httpPrepareHeader(HttpConnection *connection, const void *contentType, size_t contentLength);
error_t httpWriteResponseString(HttpConnection *connection, char_t *data, bool_t freeMemory);
error_t httpWriteResponse(HttpConnection *connection, void *data, size_t size, bool_t freeMemory);
error_t httpWriteString(HttpConnection *connection, const char_t *content);
error_t httpFlushStream(HttpConnection *connection);

void setLastUid(uint64_t uid, settings_t *settings);
void setLastRuid(char ruid[17], settings_t *settings);
#endif
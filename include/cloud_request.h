#ifndef __CLOUD_REQUEST_H__
#define __CLOUD_REQUEST_H__

#define HTTP_CLIENT_PRIVATE_CONTEXT void *sourceCtx;

#include <stdbool.h>
#include <stdint.h>
#include "http/http_client.h"
#include "error.h"

typedef struct req_cbr_t req_cbr_t;
struct req_cbr_t
{
    void *ctx;
    void (*response)(void *ctx, HttpClientContext *cloud_ctx);
    void (*header)(void *ctx, HttpClientContext *cloud_ctx, const char *header, const char *value);
    void (*body)(void *ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error);
    void (*disconnect)(void *ctx, HttpClientContext *cloud_ctx);
};

int_t cloud_request_get(const char *server, int port, const char *uri, const char *queryString, const uint8_t *hash, req_cbr_t *cbr);
int_t cloud_request_post(const char *server, int port, const char *uri, const char *queryString, const uint8_t *body, size_t bodyLen, const uint8_t *hash, req_cbr_t *cbr);
int_t cloud_request(const char *server, int port, bool https, const char *uri, const char *queryString, const char *method, const uint8_t *body, size_t bodyLen, const uint8_t *hash, req_cbr_t *cbr);
error_t web_request(const char *server, int port, bool https, const char *uri, const char *queryString, const char *method, const uint8_t *body, size_t bodyLen, const uint8_t *hash, req_cbr_t *cbr, bool isCloud, bool printTextData);

#endif

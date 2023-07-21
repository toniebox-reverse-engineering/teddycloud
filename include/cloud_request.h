#ifndef __CLOUD_REQUEST_H__
#define __CLOUD_REQUEST_H__

#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    void *ctx;
    void (*response)(void *src_ctx, void *cloud_ctx);
    void (*header)(void *src_ctx, void *cloud_ctx, const char *header, const char *value);
    void (*body)(void *src_ctx, void *cloud_ctx, const char *payload, size_t length, error_t error);
    void (*disconnect)(void *src_ctx, void *cloud_ctx);
} req_cbr_t;

int_t cloud_request_get(const char *server, int port, const char *uri, const uint8_t *hash, req_cbr_t *cbr);
int_t cloud_request_post(const char *server, int port, const char *uri, const uint8_t *body, size_t bodyLen, const uint8_t *hash, req_cbr_t *cbr);
int_t cloud_request(const char *server, int port, bool https, const char *uri, const char *method, const uint8_t *body, size_t bodyLen, const uint8_t *hash, req_cbr_t *cbr);

#endif

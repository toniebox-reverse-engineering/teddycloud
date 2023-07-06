#ifndef __CLOUD_REQUEST_H__
#define __CLOUD_REQUEST_H__

typedef struct
{
    void *ctx;
    void (*response)(void *ctx);
    void (*header)(void *ctx, const char *header, const char *value);
    void (*body)(void *ctx, const char *payload, size_t length);
    void (*disconnect)(void *ctx);
} req_cbr_t;

int_t cloud_request_get(const char *server, int port, const char *uri, const uint8_t *hash, req_cbr_t *cbr);
int_t cloud_request_post(const char *server, int port, const char *uri, const uint8_t *hash, req_cbr_t *cbr);
int_t cloud_request(const char *server, int port, const char *uri, const char *method, const uint8_t *hash, req_cbr_t *cbr);

#endif

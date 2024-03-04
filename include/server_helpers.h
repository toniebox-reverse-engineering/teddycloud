#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "core/net.h"
#include "http/http_server.h"

typedef struct
{
    error_t (*multipart_start)(void *ctx, const char *name, const char *filename);
    error_t (*multipart_add)(void *ctx, void *data, size_t length);
    error_t (*multipart_end)(void *ctx);
} multipart_cbr_t;

error_t multipart_handle(HttpConnection *connection, multipart_cbr_t *cbr, void *multipart_ctx);

int urldecode(char *dest, size_t dest_max, const char *src);
bool queryGet(const char *query, const char *key, char *data, size_t data_len);
char_t *ipAddrToString(const IpAddr *ipAddr, char_t *str);
char_t *ipv6AddrToString(const Ipv6Addr *ipAddr, char_t *str);
char_t *ipv4AddrToString(Ipv4Addr ipAddr, char_t *str);
void time_format(time_t time, char_t *buffer);
void time_format_current(char_t *buffer);
char *custom_asprintf(const char *fmt, ...);

error_t httpServerUriNotFoundCallback(HttpConnection *connection, const char_t *uri);
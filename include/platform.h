#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#include <stdbool.h>
#include "core/net.h"

void *resolve_host(const char *hostname);
bool resolve_get_ip(void *res, int pos, IpAddr *ipAddr);
void resolve_free(void *res);

#endif
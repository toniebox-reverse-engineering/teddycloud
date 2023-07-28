#ifndef __PLATFORM_WINDOWS_H__
#define __PLATFORM_WINDOWS_H__

// Platform-specific dependencies
#define _CRTDBG_MAP_ALLOC
#define _WINERROR_
#include <stdbool.h>
#include "core/net.h"

void *resolve_host(const char *hostname);
bool resolve_get_ip(void *res, int pos, IpAddr *ipAddr);
void resolve_free(void *res);

#endif
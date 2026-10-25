#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#include <stdbool.h>
#include "core/net.h"

void *resolve_host(const char *hostname);

/* whether the terminal shows ANSI colors (enables them on Windows) */
bool platform_supports_ansi_colors(void);
bool resolve_get_ip(void *res, int pos, IpAddr *ipAddr);
void resolve_free(void *res);

#endif
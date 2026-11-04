#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#include <stdbool.h>
#include "core/net.h"

void *resolve_host(const char *hostname);

/* whether the terminal shows ANSI colors (enables them on Windows) */
bool platform_supports_ansi_colors(void);
bool resolve_get_ip(void *res, int pos, IpAddr *ipAddr);
void resolve_free(void *res);

/* TRUE if the peer of a connected socket has closed it (FIN, reset) or sent a TLS alert (its close_notify) while
   nothing was asked of it; FALSE while it is quiet or sent anything else. Consumes nothing. For a handler that waits
   long before it answers, so it notices a client that went away. On Windows a FIN behind data not read yet (a
   request after the one being answered) is not seen. A FIN is taken for gone, though a client that only shut down
   its sending side (a half-close) would still read the answer; boxes do not half-close. */
bool socketPeerClosed(Socket *socket);

#endif
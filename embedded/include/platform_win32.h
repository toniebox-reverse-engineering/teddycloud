#ifndef __PLATFORM_WIN32_H__
#define __PLATFORM_WIN32_H__

// Platform-specific dependencies
#ifndef _WIN32

#define SOCKET intptr_t
#define SOCKET_ERROR -1
#define SOCKADDR_IN struct sockaddr_in
#define PSOCKADDR struct sockaddr *
#define HOSTENT struct hostent
#define closesocket close

#define _CRTDBG_MAP_ALLOC
#define _WINERROR_
#include <crtdbg.h>
#include <winsock2.h>

#endif

#endif
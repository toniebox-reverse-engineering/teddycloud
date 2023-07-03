/**
 * @file bsd_socket.h
 * @brief BSD socket API
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneTCP Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

#ifndef _BSD_SOCKET_H
#define _BSD_SOCKET_H

//BSD socket support
#ifndef BSD_SOCKET_SUPPORT
   #define BSD_SOCKET_SUPPORT ENABLED
#elif (BSD_SOCKET_SUPPORT != ENABLED && BSD_SOCKET_SUPPORT != DISABLED)
   #error BSD_SOCKET_SUPPORT parameter is not valid
#endif

//Maximum number of file descriptors a fd_set object can hold
#ifndef FD_SETSIZE
   #define FD_SETSIZE 8
#elif (FD_SETSIZE < 1)
   #error FD_SETSIZE parameter is not valid
#endif

//Set errno variable
#ifndef BSD_SOCKET_SET_ERRNO
   #define BSD_SOCKET_SET_ERRNO(e)
#endif

//Keil RTX port?
#if defined(USE_RTX) && !defined(RTX_CUSTOM_HEADER)

//No support for BSD sockets
#undef BSD_SOCKET_SUPPORT
#define BSD_SOCKET_SUPPORT DISABLED

//Windows port?
#elif defined(_WIN32) && !defined(_DONT_USE_WINSOCK)

//Undefine conflicting definitions
#undef htons
#undef htonl
#undef ntohs
#undef ntohl

//Dependencies
#include <winsock2.h>

#elif (BSD_SOCKET_SUPPORT == ENABLED)

//Dependencies
#include "os_port.h"

//Address families
#define AF_UNSPEC         0
#define AF_INET           2
#define AF_INET6          10
#define AF_PACKET         17

//Protocol families
#define PF_UNSPEC         AF_UNSPEC
#define PF_INET           AF_INET
#define PF_INET6          AF_INET6
#define PF_PACKET         AF_PACKET

//Socket types
#define SOCK_STREAM       1
#define SOCK_DGRAM        2
#define SOCK_RAW          3

//IP protocol identifiers
#define IPPROTO_IP        0
#define IPPROTO_ICMP      1
#define IPPROTO_IGMP      2
#define IPPROTO_TCP       6
#define IPPROTO_UDP       17
#define IPPROTO_ICMPV6    58

//Ethernet protocol identifiers
#define ETH_P_ALL         0x0000
#define ETH_P_IP          0x0800
#define ETH_P_ARP         0x0806
#define ETH_P_IPV6        0x86DD

//Option levels
#define SOL_SOCKET        0xFFFF

//Common addresses
#define INADDR_ANY        0x00000000
#define INADDR_LOOPBACK   0x7F000001
#define INADDR_BROADCAST  0xFFFFFFFF

//Flags used by I/O functions
#define MSG_PEEK          0x02
#define MSG_DONTROUTE     0x04
#define MSG_WAITALL       0x08
#define MSG_DONTWAIT      0x01

//Flags used by shutdown function
#define SD_RECEIVE        0
#define SD_SEND           1
#define SD_BOTH           2

//Flags used by shutdown function (alias)
#define SHUT_RD           SD_RECEIVE
#define SHUT_WR           SD_SEND
#define SHUT_RDWR         SD_BOTH

//Socket level options
#define SO_REUSEADDR      0x0004
#define SO_KEEPALIVE      0x0008
#define SO_DONTROUTE      0x0010
#define SO_BROADCAST      0x0020
#define SO_LINGER         0x0080
#define SO_SNDBUF         0x1001
#define SO_RCVBUF         0x1002
#define SO_SNDTIMEO       0x1005
#define SO_RCVTIMEO       0x1006
#define SO_ERROR          0x1007
#define SO_TYPE           0x1008
#define SO_MAX_MSG_SIZE   0x2003
#define SO_BINDTODEVICE   0x3000

//IP level options
#define IP_TOS            1
#define IP_TTL            2
#define IP_MULTICAST_TTL  33

//TCP level options
#define TCP_NODELAY       0x0001
#define TCP_MAXSEG        0x0002
#define TCP_KEEPIDLE      0x0004
#define TCP_KEEPINTVL     0x0005
#define TCP_KEEPCNT       0x0006

//IP TOS option
#define IPTOS_LOWDELAY    0x10
#define IPTOS_THROUGHPUT  0x08
#define IPTOS_RELIABILITY 0x04

//IOCTL commands
#define FIONBIO           126
#define FIONREAD          127
#define FIONWRITE         121
#define FIONSPACE         120

//FCNTL commands
#define F_GETFL           3
#define F_SETFL           4

//FCNTL flags
#define O_NONBLOCK        0x0004

//Flags used by getaddrinfo
#define AI_PASSIVE        0x01
#define AI_CANONNAME      0x02
#define AI_NUMERICHOST    0x04
#define AI_NUMERICSERV    0x08
#define AI_ALL            0x10
#define AI_ADDRCONFIG     0x20
#define AI_V4MAPPED       0x40

//Flags used by getnameinfo
#define NI_NOFQDN         0x01
#define NI_NUMERICHOST    0x02
#define NI_NAMEREQD       0x04
#define NI_NUMERICSERV    0x08
#define NI_DGRAM          0x10

//Return values
#define SOCKET_SUCCESS    0
#define SOCKET_ERROR      (-1)

//Return values used by getaddrinfo and getnameinfo
#define EAI_ADDRFAMILY    1
#define EAI_AGAIN         2
#define EAI_BADFLAGS      3
#define EAI_FAIL          4
#define EAI_FAMILY        5
#define EAI_MEMORY        6
#define EAI_NODATA        7
#define EAI_NONAME        8
#define EAI_SERVICE       9
#define EAI_SOCKTYPE      10
#define EAI_SYSTEM        11
#define EAI_OVERFLOW      12

//Error codes
#define EINTR             4
#define EAGAIN            11
#define EWOULDBLOCK       11
#define EFAULT            14
#define EINVAL            22
#define EINPROGRESS       36
#define ETIMEDOUT         60
#define ENAMETOOLONG      63
#define ENOPROTOOPT       92
#define ECONNRESET        104
#define EISCONN           106
#define ENOTCONN          107
#define ESHUTDOWN         108
#define ECONNREFUSED      111

//Error codes used by gethostbyname_r
#define NETDB_SUCCESS  0
#define HOST_NOT_FOUND 1
#define TRY_AGAIN      2
#define NO_RECOVERY    3
#define NO_ADDRESS     4

//Return codes
#define INADDR_NONE ((in_addr_t) (-1))

//Maximum length for string representation of IPv4 address
#define INET_ADDRSTRLEN 16

//Maximum length for string representation of IPv6 address
#define INET6_ADDRSTRLEN 40

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Length type
 **/

typedef int_t socklen_t;


/**
 * @brief IPv4 address
 **/

typedef  uint32_t in_addr_t;


/**
 * @brief Socket address
 **/

typedef struct sockaddr
{
   uint16_t sa_family;
   uint8_t sa_data[14];
} SOCKADDR, *PSOCKADDR;


/**
 * @brief Structure that represents an IPv4 address
 **/

typedef struct in_addr
{
   in_addr_t s_addr;
} IN_ADDR, *PIN_ADDR;


/**
 * @brief IPv4 address information
 **/

typedef struct sockaddr_in
{
   uint16_t sin_family;
   uint16_t sin_port;
   struct in_addr sin_addr;
   uint8_t sin_zero[8];
} SOCKADDR_IN, *PSOCKADDR_IN;


/**
 * @brief Structure that represents an IPv6 address
 **/

typedef struct in6_addr
{
   uint8_t s6_addr[16];
} IN6_ADDR, *PIN6_ADDR;


/**
 * @brief IPv6 address information
 **/

typedef struct sockaddr_in6
{
   uint16_t sin6_family;
   uint16_t sin6_port;
   struct in6_addr sin6_addr;
} SOCKADDR_IN6, *PSOCKADDR_IN6;


/**
 * @brief Set of sockets
 **/

typedef struct fd_set
{
   int_t fd_count;
   int_t fd_array[FD_SETSIZE];
} fd_set, FD_SET, *PFD_SET;


/**
 * @brief Information about a given host
 **/

typedef struct hostent
{
   uint16_t h_addrtype;
   uint16_t h_length;
   uint8_t h_addr[16];
} HOSTENT, *PHOSTENT;


/**
 * @brief Information about address of a service provider
 **/

typedef struct addrinfo
{
   int_t ai_flags;
   int_t ai_family;
   int_t ai_socktype;
   int_t ai_protocol;
   socklen_t ai_addrlen;
   struct sockaddr *ai_addr;
   char_t *ai_canonname;
   struct addrinfo *ai_next;
} ADDRINFO, *PADDRINFO;


#ifndef _TIMEVAL_DEFINED

/**
 * @brief Timeout structure
 **/

typedef struct timeval
{
   int32_t tv_sec;
   int32_t tv_usec;
} TIMEVAL, *PTIMEVAL;

#endif


//Forward declaration of functions
void socketFdZero(fd_set *fds);
void socketFdSet(fd_set *fds, int_t s);
void socketFdClr(fd_set *fds, int_t s);
int_t socketFdIsSet(fd_set *fds, int_t s);

//Macros for manipulating and checking descriptor sets
#define FD_ZERO(fds) socketFdZero(fds)
#define FD_SET(s, fds) socketFdSet(fds, s)
#define FD_CLR(s, fds) socketFdClr(fds, s)
#define FD_ISSET(s, fds) socketFdIsSet(fds, s)

//BSD socket related constants
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;

//BSD socket related functions
int_t socket(int_t family, int_t type, int_t protocol);
int_t bind(int_t s, const struct sockaddr *addr, socklen_t addrlen);
int_t connect(int_t s, const struct sockaddr *addr, socklen_t addrlen);
int_t listen(int_t s, int_t backlog);
int_t accept(int_t s, struct sockaddr *addr, socklen_t *addrlen);
int_t send(int_t s, const void *data, size_t length, int_t flags);

int_t sendto(int_t s, const void *data, size_t length, int_t flags,
   const struct sockaddr *addr, socklen_t addrlen);

int_t recv(int_t s, void *data, size_t size, int_t flags);

int_t recvfrom(int_t s, void *data, size_t size, int_t flags,
   struct sockaddr *addr, socklen_t *addrlen);

int_t getsockname(int_t s, struct sockaddr *addr, socklen_t *addrlen);
int_t getpeername(int_t s, struct sockaddr *addr, socklen_t *addrlen);

int_t setsockopt(int_t s, int_t level, int_t optname, const void *optval,
   socklen_t optlen);

int_t getsockopt(int_t s, int_t level, int_t optname, void *optval,
   socklen_t *optlen);

int_t ioctlsocket(int_t s, uint32_t cmd, void *arg);
int_t fcntl(int_t s, int_t cmd, void *arg);

int_t shutdown(int_t s, int_t how);
int_t closesocket(int_t s);

int_t select(int_t nfds, fd_set *readfds, fd_set *writefds,
   fd_set *exceptfds, const struct timeval *timeout);

int_t gethostname(char_t *name, size_t len);
struct hostent *gethostbyname(const char_t *name);

struct hostent *gethostbyname_r(const char_t *name, struct hostent *result,
   char_t *buf, size_t buflen, int_t *h_errnop);

int_t getaddrinfo(const char_t *node, const char_t *service,
   const struct addrinfo *hints, struct addrinfo **res);

void freeaddrinfo(struct addrinfo *res);

int_t getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
   char_t *host, size_t hostlen, char_t *serv, size_t servlen, int flags);

in_addr_t inet_addr(const char_t *cp);

int_t inet_aton(const char_t *cp, struct in_addr *inp);
const char_t *inet_ntoa(struct in_addr in);
const char_t *inet_ntoa_r(struct in_addr in, char_t *buf, socklen_t buflen);

int_t inet_pton(int_t af, const char_t *src, void *dst);
const char_t *inet_ntop(int_t af, const void *src, char_t *dst, socklen_t size);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
#endif

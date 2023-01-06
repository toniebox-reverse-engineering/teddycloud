/**
 * @file bsd_socket.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL BSD_SOCKET_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "core/net.h"
#include "core/bsd_socket.h"
#include "core/bsd_socket_misc.h"
#include "core/socket.h"
#include "core/socket_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (BSD_SOCKET_SUPPORT == ENABLED)

//Common IPv6 addresses
const struct in6_addr in6addr_any =
   {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

const struct in6_addr in6addr_loopback =
   {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};


/**
 * @brief Create a socket that is bound to a specific transport service provider
 * @param[in] family Address family
 * @param[in] type Type specification for the new socket
 * @param[in] protocol Protocol to be used
 * @return On success, a file descriptor for the new socket is returned.
 *   On failure, SOCKET_ERROR is returned
 **/

int_t socket(int_t family, int_t type, int_t protocol)
{
   Socket *sock;

   //Check address family
   if(family == AF_INET || family == AF_INET6)
   {
      //Create a socket
      sock = socketOpen(type, protocol);
   }
   else if(family == AF_PACKET)
   {
      //Create a socket
      sock = socketOpen(SOCKET_TYPE_RAW_ETH, ntohs(protocol));
   }
   else
   {
      //The address family is not valid
      return SOCKET_ERROR;
   }

   //Failed to create a new socket?
   if(sock == NULL)
   {
      //Report an error
      return SOCKET_ERROR;
   }

   //Return the socket descriptor
   return sock->descriptor;
}


/**
 * @brief Associate a local address with a socket
 * @param[in] s Descriptor identifying an unbound socket
 * @param[in] addr Local address to assign to the bound socket
 * @param[in] addrlen Length in bytes of the address
 * @return If no error occurs, bind returns SOCKET_SUCCESS.
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t bind(int_t s, const struct sockaddr *addr, socklen_t addrlen)
{
   error_t error;
   uint16_t port;
   IpAddr ipAddr;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Check the length of the address
   if(addrlen < (socklen_t) sizeof(SOCKADDR))
   {
      //Report an error
      socketSetErrnoCode(sock, EINVAL);
      return SOCKET_ERROR;
   }

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address?
   if(addr->sa_family == AF_INET &&
      addrlen >= (socklen_t) sizeof(SOCKADDR_IN))
   {
      //Point to the IPv4 address information
      SOCKADDR_IN *sa = (SOCKADDR_IN *) addr;
      //Get port number
      port = ntohs(sa->sin_port);

      //Copy IPv4 address
      ipAddr.length = sizeof(Ipv4Addr);
      ipAddr.ipv4Addr = sa->sin_addr.s_addr;
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address?
   if(addr->sa_family == AF_INET6 &&
      addrlen >= (socklen_t) sizeof(SOCKADDR_IN6))
   {
      //Point to the IPv6 address information
      SOCKADDR_IN6 *sa = (SOCKADDR_IN6 *) addr;
      //Get port number
      port = ntohs(sa->sin6_port);

      //Copy IPv6 address
      if(ipv6CompAddr(sa->sin6_addr.s6_addr, &in6addr_any))
      {
         ipAddr.length = 0;
         ipAddr.ipv6Addr = IPV6_UNSPECIFIED_ADDR;
      }
      else
      {
         ipAddr.length = sizeof(Ipv6Addr);
         ipv6CopyAddr(&ipAddr.ipv6Addr, sa->sin6_addr.s6_addr);
      }
   }
   else
#endif
   //Invalid address?
   {
      //Report an error
      socketSetErrnoCode(sock, EINVAL);
      return SOCKET_ERROR;
   }

   //Associate the local address with the socket
   error = socketBind(sock, &ipAddr, port);

   //Any error to report?
   if(error)
   {
      socketTranslateErrorCode(sock, error);
      return SOCKET_ERROR;
   }

   //Successful processing
   return SOCKET_SUCCESS;
}


/**
 * @brief Establish a connection to a specified socket
 * @param[in] s Descriptor identifying an unconnected socket
 * @param[in] addr Address to which the connection should be established
 * @param[in] addrlen Length in bytes of the address
 * @return If no error occurs, connect returns SOCKET_SUCCESS.
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t connect(int_t s, const struct sockaddr *addr, socklen_t addrlen)
{
   error_t error;
   uint16_t port;
   IpAddr ipAddr;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Check the length of the address
   if(addrlen < (socklen_t) sizeof(SOCKADDR))
   {
      socketSetErrnoCode(sock, EINVAL);
      return SOCKET_ERROR;
   }

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address?
   if(addr->sa_family == AF_INET &&
      addrlen >= (socklen_t) sizeof(SOCKADDR_IN))
   {
      //Point to the IPv4 address information
      SOCKADDR_IN *sa = (SOCKADDR_IN *) addr;
      //Get port number
      port = ntohs(sa->sin_port);

      //Copy IPv4 address
      ipAddr.length = sizeof(Ipv4Addr);
      ipAddr.ipv4Addr = sa->sin_addr.s_addr;
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address?
   if(addr->sa_family == AF_INET6 &&
      addrlen >= (socklen_t) sizeof(SOCKADDR_IN6))
   {
      //Point to the IPv6 address information
      SOCKADDR_IN6 *sa = (SOCKADDR_IN6 *) addr;
      //Get port number
      port = ntohs(sa->sin6_port);

      //Copy IPv6 address
      if(ipv6CompAddr(sa->sin6_addr.s6_addr, &in6addr_any))
      {
         ipAddr.length = 0;
         ipAddr.ipv6Addr = IPV6_UNSPECIFIED_ADDR;
      }
      else
      {
         ipAddr.length = sizeof(Ipv6Addr);
         ipv6CopyAddr(&ipAddr.ipv6Addr, sa->sin6_addr.s6_addr);
      }
   }
   else
#endif
   //Invalid address?
   {
      //Report an error
      socketSetErrnoCode(sock, EINVAL);
      return SOCKET_ERROR;
   }

   //Establish connection
   error = socketConnect(sock, &ipAddr, port);

   //Check status code
   if(error == NO_ERROR)
   {
      //Successful processing
      return SOCKET_SUCCESS;
   }
   else if(error == ERROR_TIMEOUT)
   {
      //Non-blocking socket?
      if(sock->timeout == 0)
      {
         //The connection cannot be completed immediately
         socketSetErrnoCode(sock, EINPROGRESS);
      }
      else
      {
         //Timeout while attempting connection
         socketSetErrnoCode(sock, ETIMEDOUT);
      }

      //Report an error
      return SOCKET_ERROR;
   }
   else
   {
      //Report an error
      socketTranslateErrorCode(sock, error);
      return SOCKET_ERROR;
   }
}


/**
 * @brief Place a socket in the listening state
 *
 * Place a socket in a state in which it is listening for an incoming connection
 *
 * @param[in] s Descriptor identifying a bound, unconnected socket
 * @param[in] backlog Maximum length of the queue of pending connections
 * @return If no error occurs, listen returns SOCKET_SUCCESS.
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t listen(int_t s, int_t backlog)
{
   error_t error;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Place the socket in the listening state
   error = socketListen(sock, backlog);

   //Any error to report?
   if(error)
   {
      socketTranslateErrorCode(sock, error);
      return SOCKET_ERROR;
   }

   //Successful processing
   return SOCKET_SUCCESS;
}


/**
 * @brief Permit an incoming connection attempt on a socket
 * @param[in] s Descriptor that identifies a socket in the listening state
 * @param[out] addr Address of the connecting entity (optional)
 * @param[in,out] addrlen Length in bytes of the address (optional)
 * @return If no error occurs, accept returns a descriptor for the new socket.
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t accept(int_t s, struct sockaddr *addr, socklen_t *addrlen)
{
   uint16_t port;
   IpAddr ipAddr;
   Socket *sock;
   Socket *newSock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Permit an incoming connection attempt on a socket
   newSock = socketAccept(sock, &ipAddr, &port);

   //No connection request is pending in the SYN queue?
   if(newSock == NULL)
   {
      //Report an error
      socketSetErrnoCode(sock, EWOULDBLOCK);
      return SOCKET_ERROR;
   }

   //The address is optional
   if(addr != NULL && addrlen != NULL)
   {
#if (IPV4_SUPPORT == ENABLED)
      //IPv4 address?
      if(ipAddr.length == sizeof(Ipv4Addr) &&
         *addrlen >= (socklen_t) sizeof(SOCKADDR_IN))
      {
         //Point to the IPv4 address information
         SOCKADDR_IN *sa = (SOCKADDR_IN *) addr;

         //Set address family and port number
         sa->sin_family = AF_INET;
         sa->sin_port = htons(port);

         //Copy IPv4 address
         sa->sin_addr.s_addr = ipAddr.ipv4Addr;

         //Return the actual length of the address
         *addrlen = sizeof(SOCKADDR_IN);
      }
      else
#endif
#if (IPV6_SUPPORT == ENABLED)
      //IPv6 address?
      if(ipAddr.length == sizeof(Ipv6Addr) &&
         *addrlen >= (socklen_t) sizeof(SOCKADDR_IN6))
      {
         //Point to the IPv6 address information
         SOCKADDR_IN6 *sa = (SOCKADDR_IN6 *) addr;

         //Set address family and port number
         sa->sin6_family = AF_INET6;
         sa->sin6_port = htons(port);

         //Copy IPv6 address
         ipv6CopyAddr(sa->sin6_addr.s6_addr, &ipAddr.ipv6Addr);

         //Return the actual length of the address
         *addrlen = sizeof(SOCKADDR_IN6);
      }
      else
#endif
      //Invalid address?
      {
         //Close socket
         socketClose(newSock);

         //Report an error
         socketSetErrnoCode(sock, EINVAL);
         return SOCKET_ERROR;
      }
   }

   //Return the descriptor to the new socket
   return newSock->descriptor;
}


/**
 * @brief Send data to a connected socket
 * @param[in] s Descriptor that identifies a connected socket
 * @param[in] data Pointer to a buffer containing the data to be transmitted
 * @param[in] length Number of bytes to be transmitted
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return If no error occurs, send returns the total number of bytes sent,
 *   which can be less than the number requested to be sent in the
 *   length parameter. Otherwise, a value of SOCKET_ERROR is returned
 **/

int_t send(int_t s, const void *data, size_t length, int_t flags)
{
   error_t error;
   size_t written;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Send data
   error = socketSend(sock, data, length, &written, flags << 8);

   //Any error to report?
   if(error == ERROR_TIMEOUT)
   {
      //Check whether some data has been written
      if(written > 0)
      {
         //If a timeout error occurs and some data has been written, the
         //count of bytes transferred so far is returned...
      }
      else
      {
         //If no data has been written, a value of SOCKET_ERROR is returned
         socketTranslateErrorCode(sock, error);
         return SOCKET_ERROR;
      }
   }
   else if(error != NO_ERROR)
   {
      //Otherwise, a value of SOCKET_ERROR is returned
      socketTranslateErrorCode(sock, error);
      return SOCKET_ERROR;
   }

   //Return the number of bytes transferred so far
   return written;
}


/**
 * @brief Send a datagram to a specific destination
 * @param[in] s Descriptor that identifies a socket
 * @param[in] data Pointer to a buffer containing the data to be transmitted
 * @param[in] length Number of bytes to be transmitted
 * @param[in] flags Set of flags that influences the behavior of this function
 * @param[in] addr Destination address
 * @param[in] addrlen Length in bytes of the destination address
 * @return If no error occurs, sendto returns the total number of bytes sent,
 *   which can be less than the number requested to be sent in the
 *   length parameter. Otherwise, a value of SOCKET_ERROR is returned
 **/

int_t sendto(int_t s, const void *data, size_t length, int_t flags,
   const struct sockaddr *addr, socklen_t addrlen)
{
   error_t error;
   size_t written;
   uint16_t port;
   IpAddr ipAddr;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Check the length of the address
   if(addrlen < (socklen_t) sizeof(SOCKADDR))
   {
      //Report an error
      socketSetErrnoCode(sock, EINVAL);
      return SOCKET_ERROR;
   }

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address?
   if(addr->sa_family == AF_INET &&
      addrlen >= (socklen_t) sizeof(SOCKADDR_IN))
   {
      //Point to the IPv4 address information
      SOCKADDR_IN *sa = (SOCKADDR_IN *) addr;

      //Get port number
      port = ntohs(sa->sin_port);
      //Copy IPv4 address
      ipAddr.length = sizeof(Ipv4Addr);
      ipAddr.ipv4Addr = sa->sin_addr.s_addr;
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address?
   if(addr->sa_family == AF_INET6 &&
      addrlen >= (socklen_t) sizeof(SOCKADDR_IN6))
   {
      //Point to the IPv6 address information
      SOCKADDR_IN6 *sa = (SOCKADDR_IN6 *) addr;

      //Get port number
      port = ntohs(sa->sin6_port);
      //Copy IPv6 address
      ipAddr.length = sizeof(Ipv6Addr);
      ipv6CopyAddr(&ipAddr.ipv6Addr, sa->sin6_addr.s6_addr);
   }
   else
#endif
   //Invalid address?
   {
      //Report an error
      socketSetErrnoCode(sock, EINVAL);
      return SOCKET_ERROR;
   }

   //Send data
   error = socketSendTo(sock, &ipAddr, port, data, length, &written,
      flags << 8);

   //Any error to report?
   if(error == ERROR_TIMEOUT)
   {
      //Check whether some data has been written
      if(written > 0)
      {
         //If a timeout error occurs and some data has been written, the
         //count of bytes transferred so far is returned...
      }
      else
      {
         //If no data has been written, a value of SOCKET_ERROR is returned
         socketTranslateErrorCode(sock, error);
         return SOCKET_ERROR;
      }
   }
   else if(error != NO_ERROR)
   {
      //Otherwise, a value of SOCKET_ERROR is returned
      socketTranslateErrorCode(sock, error);
      return SOCKET_ERROR;
   }

   //Return the number of bytes transferred so far
   return written;
}


/**
 * @brief Receive data from a connected socket
 * @param[in] s Descriptor that identifies a connected socket
 * @param[out] data Buffer where to store the incoming data
 * @param[in] size Maximum number of bytes that can be received
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return If no error occurs, recv returns the number of bytes received. If the
 *   connection has been gracefully closed, the return value is zero.
 *   Otherwise, a value of SOCKET_ERROR is returned
 **/

int_t recv(int_t s, void *data, size_t size, int_t flags)
{
   error_t error;
   size_t received;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Receive data
   error = socketReceive(sock, data, size, &received, flags << 8);

   //Any error to report?
   if(error == ERROR_END_OF_STREAM)
   {
      //If the connection has been gracefully closed, the return value is zero
      return 0;
   }
   else if(error != NO_ERROR)
   {
      //Otherwise, a value of SOCKET_ERROR is returned
      socketTranslateErrorCode(sock, error);
      return SOCKET_ERROR;
   }

   //Return the number of bytes received
   return received;
}


/**
 * @brief Receive a datagram
 * @param[in] s Descriptor that identifies a socket
 * @param[out] data Buffer where to store the incoming data
 * @param[in] size Maximum number of bytes that can be received
 * @param[in] flags Set of flags that influences the behavior of this function
 * @param[out] addr Source address upon return (optional)
 * @param[in,out] addrlen Length in bytes of the address (optional)
 * @return If no error occurs, recvfrom returns the number of bytes received.
 *   If the connection has been gracefully closed, the return value is
 *   zero. Otherwise, a value of SOCKET_ERROR is returned
 **/

int_t recvfrom(int_t s, void *data, size_t size, int_t flags,
   struct sockaddr *addr, socklen_t *addrlen)
{
   error_t error;
   size_t received;
   uint16_t port;
   IpAddr ipAddr;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Receive data
   error = socketReceiveFrom(sock, &ipAddr, &port, data, size, &received,
      flags << 8);

   //Any error to report?
   if(error == ERROR_END_OF_STREAM)
   {
      //If the connection has been gracefully closed, the return value is zero
      return 0;
   }
   else if(error != NO_ERROR)
   {
      //Otherwise, a value of SOCKET_ERROR is returned
      socketTranslateErrorCode(sock, error);
      return SOCKET_ERROR;
   }

   //The address is optional
   if(addr != NULL && addrlen != NULL)
   {
#if (IPV4_SUPPORT == ENABLED)
      //IPv4 address?
      if(ipAddr.length == sizeof(Ipv4Addr) &&
         *addrlen >= (socklen_t) sizeof(SOCKADDR_IN))
      {
         //Point to the IPv4 address information
         SOCKADDR_IN *sa = (SOCKADDR_IN *) addr;

         //Set address family and port number
         sa->sin_family = AF_INET;
         sa->sin_port = htons(port);

         //Copy IPv4 address
         sa->sin_addr.s_addr = ipAddr.ipv4Addr;

         //Return the actual length of the address
         *addrlen = sizeof(SOCKADDR_IN);
      }
      else
#endif
#if (IPV6_SUPPORT == ENABLED)
      //IPv6 address?
      if(ipAddr.length == sizeof(Ipv6Addr) &&
         *addrlen >= (socklen_t) sizeof(SOCKADDR_IN6))
      {
         //Point to the IPv6 address information
         SOCKADDR_IN6 *sa = (SOCKADDR_IN6 *) addr;

         //Set address family and port number
         sa->sin6_family = AF_INET6;
         sa->sin6_port = htons(port);

         //Copy IPv6 address
         ipv6CopyAddr(sa->sin6_addr.s6_addr, &ipAddr.ipv6Addr);

         //Return the actual length of the address
         *addrlen = sizeof(SOCKADDR_IN6);
      }
      else
#endif
      //Invalid address?
      {
         //Report an error
         socketSetErrnoCode(sock, EINVAL);
         return SOCKET_ERROR;
      }
   }

   //Return the number of bytes received
   return received;
}


/**
 * @brief Retrieves the local name for a socket
 * @param[in] s Descriptor identifying a socket
 * @param[out] addr Address of the socket
 * @param[in,out] addrlen Length in bytes of the address
 * @return If no error occurs, getsockname returns SOCKET_SUCCESS
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t getsockname(int_t s, struct sockaddr *addr, socklen_t *addrlen)
{
   int_t ret;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Check whether the socket has been bound to an address
   if(sock->localIpAddr.length != 0)
   {
#if (IPV4_SUPPORT == ENABLED)
      //IPv4 address?
      if(sock->localIpAddr.length == sizeof(Ipv4Addr) &&
         *addrlen >= (socklen_t) sizeof(SOCKADDR_IN))
      {
         //Point to the IPv4 address information
         SOCKADDR_IN *sa = (SOCKADDR_IN *) addr;

         //Set address family and port number
         sa->sin_family = AF_INET;
         sa->sin_port = htons(sock->localPort);

         //Copy IPv4 address
         sa->sin_addr.s_addr = sock->localIpAddr.ipv4Addr;

         //Return the actual length of the address
         *addrlen = sizeof(SOCKADDR_IN);
         //Successful processing
         ret = SOCKET_SUCCESS;
      }
      else
#endif
#if (IPV6_SUPPORT == ENABLED)
      //IPv6 address?
      if(sock->localIpAddr.length == sizeof(Ipv6Addr) &&
         *addrlen >= (socklen_t) sizeof(SOCKADDR_IN6))
      {
         //Point to the IPv6 address information
         SOCKADDR_IN6 *sa = (SOCKADDR_IN6 *) addr;

         //Set address family and port number
         sa->sin6_family = AF_INET6;
         sa->sin6_port = htons(sock->localPort);

         //Copy IPv6 address
         ipv6CopyAddr(sa->sin6_addr.s6_addr, &sock->localIpAddr.ipv6Addr);

         //Return the actual length of the address
         *addrlen = sizeof(SOCKADDR_IN6);
         //Successful processing
         ret = SOCKET_SUCCESS;
      }
      else
#endif
      {
         //The specified length is not valid
         socketSetErrnoCode(sock, EINVAL);
         ret = SOCKET_ERROR;
      }
   }
   else
   {
      //The socket is not bound to any address
      socketSetErrnoCode(sock, ENOTCONN);
      ret = SOCKET_ERROR;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //return status code
   return ret;
}


/**
 * @brief Retrieves the address of the peer to which a socket is connected
 * @param[in] s Descriptor identifying a socket
 * @param[out] addr Address of the peer
 * @param[in,out] addrlen Length in bytes of the address
 * @return If no error occurs, getpeername returns SOCKET_SUCCESS
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t getpeername(int_t s, struct sockaddr *addr, socklen_t *addrlen)
{
   int_t ret;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Check whether the socket is connected to a peer
   if(sock->remoteIpAddr.length != 0)
   {
#if (IPV4_SUPPORT == ENABLED)
      //IPv4 address?
      if(sock->remoteIpAddr.length == sizeof(Ipv4Addr) &&
         *addrlen >= (socklen_t) sizeof(SOCKADDR_IN))
      {
         //Point to the IPv4 address information
         SOCKADDR_IN *sa = (SOCKADDR_IN *) addr;

         //Set address family and port number
         sa->sin_family = AF_INET;
         sa->sin_port = htons(sock->remotePort);

         //Copy IPv4 address
         sa->sin_addr.s_addr = sock->remoteIpAddr.ipv4Addr;

         //Return the actual length of the address
         *addrlen = sizeof(SOCKADDR_IN);
         //Successful processing
         ret = SOCKET_SUCCESS;
      }
      else
#endif
#if (IPV6_SUPPORT == ENABLED)
      //IPv6 address?
      if(sock->remoteIpAddr.length == sizeof(Ipv6Addr) &&
         *addrlen >= (socklen_t) sizeof(SOCKADDR_IN6))
      {
         //Point to the IPv6 address information
         SOCKADDR_IN6 *sa = (SOCKADDR_IN6 *) addr;

         //Set address family and port number
         sa->sin6_family = AF_INET6;
         sa->sin6_port = htons(sock->remotePort);

         //Copy IPv6 address
         ipv6CopyAddr(sa->sin6_addr.s6_addr, &sock->remoteIpAddr.ipv6Addr);

         //Return the actual length of the address
         *addrlen = sizeof(SOCKADDR_IN6);
         //Successful processing
         ret = SOCKET_SUCCESS;
      }
      else
#endif
      {
         //The specified length is not valid
         socketSetErrnoCode(sock, EINVAL);
         ret = SOCKET_ERROR;
      }
   }
   else
   {
      //The socket is not connected to any peer
      socketSetErrnoCode(sock, ENOTCONN);
      ret = SOCKET_ERROR;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //return status code
   return ret;
}


/**
 * @brief The setsockopt function sets a socket option
 * @param[in] s Descriptor that identifies a socket
 * @param[in] level The level at which the option is defined
 * @param[in] optname The socket option for which the value is to be set
 * @param[in] optval A pointer to the buffer in which the value for the requested option is specified
 * @param[in] optlen The size, in bytes, of the buffer pointed to by the optval parameter
 * @return If no error occurs, setsockopt returns SOCKET_SUCCESS
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t setsockopt(int_t s, int_t level, int_t optname, const void *optval,
   socklen_t optlen)
{
   int_t ret;
   int_t *val;
   TIMEVAL *t;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Make sure the option is valid
   if(optval != NULL)
   {
      //Level at which the option is defined?
      if(level == SOL_SOCKET)
      {
         //Check option type
         if(optname == SO_REUSEADDR)
         {
            //The socket can be bound to an address which is already in use
            ret = SOCKET_SUCCESS;
         }
         else if(optname == SO_BROADCAST)
         {
            //Allow transmission and receipt of broadcast messages
            ret = SOCKET_SUCCESS;
         }
         else if(optname == SO_SNDTIMEO || optname == SO_RCVTIMEO)
         {
            //Check the length of the option
            if(optlen >= (socklen_t) sizeof(TIMEVAL))
            {
               //Cast the option value to the relevant type
               t = (TIMEVAL *) optval;

               //If the specified value is of zero, I/O operations shall not
               //time out
               if(t->tv_sec == 0 && t->tv_usec == 0)
               {
                  socketSetTimeout(sock, INFINITE_DELAY);
               }
               else
               {
                  socketSetTimeout(sock, t->tv_sec * 1000 + t->tv_usec / 1000);
               }

               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#if (TCP_SUPPORT == ENABLED)
         else if(optname == SO_SNDBUF)
         {
            //Check the length of the option
            if(optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Adjust the size of the send buffer
               socketSetTxBufferSize(sock, *val);
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
         else if(optname == SO_RCVBUF)
         {
            //Check the length of the option
            if(optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Adjust the size of the receive buffer
               socketSetRxBufferSize(sock, *val);
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#endif
#if (TCP_SUPPORT == ENABLED && TCP_KEEP_ALIVE_SUPPORT == ENABLED)
         else if(optname == SO_KEEPALIVE)
         {
            //Check the length of the option
            if(optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //This option specifies whether TCP keep-alive is enabled
               socketEnableKeepAlive(sock, *val);
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#endif
         else
         {
            //Unknown option
            socketSetErrnoCode(sock, ENOPROTOOPT);
            //Report an error
            ret = SOCKET_ERROR;
         }
      }
      else if(level == IPPROTO_IP)
      {
         //Check option type
         if(optname == IP_TTL)
         {
            //Check the length of the option
            if(optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Save TTL value
               sock->ttl = *val;
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
         else if(optname == IP_MULTICAST_TTL)
         {
            //Check the length of the option
            if(optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Save TTL value for multicast packets
               sock->multicastTtl = *val;
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#if (IP_DIFF_SERV_SUPPORT == ENABLED)
         else if(optname == IP_TOS)
         {
            //Check the length of the option
            if(optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Save DSCP value
               sock->dscp = (*val & 0xFF) >> 2;
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#endif
         else
         {
            //Unknown option
            socketSetErrnoCode(sock, ENOPROTOOPT);
            ret = SOCKET_ERROR;
         }
      }
      else if(level == IPPROTO_TCP)
      {
         //Check option type
         if(optname == TCP_NODELAY)
         {
            //Disable Nagle algorithm
            ret = SOCKET_SUCCESS;
         }
#if (TCP_SUPPORT == ENABLED && TCP_KEEP_ALIVE_SUPPORT == ENABLED)
         else if(optname == TCP_KEEPIDLE)
         {
            //Check the length of the option
            if(optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Convert the time interval to milliseconds
               sock->keepAliveIdle = *val * 1000;
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
         else if(optname == TCP_KEEPINTVL)
         {
            //Check the length of the option
            if(optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Convert the time interval to milliseconds
               sock->keepAliveInterval = *val * 1000;
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
         else if(optname == TCP_KEEPCNT)
         {
            //Check the length of the option
            if(optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Save parameter value
               sock->keepAliveMaxProbes = *val;
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#endif
         else
         {
            //Unknown option
            socketSetErrnoCode(sock, ENOPROTOOPT);
            ret = SOCKET_ERROR;
         }
      }
      else
      {
         //The specified level is not valid
         socketSetErrnoCode(sock, EINVAL);
         ret = SOCKET_ERROR;
      }
   }
   else
   {
      //The option is not valid
      socketSetErrnoCode(sock, EFAULT);
      ret = SOCKET_ERROR;
   }

   //return status code
   return ret;
}


/**
 * @brief The getsockopt function retrieves a socket option
 * @param[in] s Descriptor that identifies a socket
 * @param[in] level The level at which the option is defined
 * @param[in] optname The socket option for which the value is to be retrieved
 * @param[out] optval A pointer to the buffer in which the value for the requested option is to be returned
 * @param[in,out] optlen The size, in bytes, of the buffer pointed to by the optval parameter
 * @return If no error occurs, getsockopt returns SOCKET_SUCCESS
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t getsockopt(int_t s, int_t level, int_t optname, void *optval,
   socklen_t *optlen)
{
   int_t ret;
   int_t *val;
   TIMEVAL *t;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Make sure the option is valid
   if(optval != NULL)
   {
      //Level at which the option is defined?
      if(level == SOL_SOCKET)
      {
         //Check option type
         if(optname == SO_SNDTIMEO || optname == SO_RCVTIMEO)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(TIMEVAL))
            {
               //Cast the option value to the relevant type
               t = (TIMEVAL *) optval;

               //Return the timeout value
               if(sock->timeout == INFINITE_DELAY)
               {
                  t->tv_sec = 0;
                  t->tv_usec = 0;
               }
               else
               {
                  t->tv_sec = sock->timeout / 1000;
                  t->tv_usec = (sock->timeout % 1000) * 1000;
               }

               //Return the actual length of the option
               *optlen = sizeof(TIMEVAL);
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#if (TCP_SUPPORT == ENABLED)
         else if(optname == SO_SNDBUF)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Return the size of the send buffer
               *val = sock->txBufferSize;
               //Return the actual length of the option
               *optlen = sizeof(int_t);
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
         else if(optname == SO_RCVBUF)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Return the size of the receive buffer
               *val = sock->rxBufferSize;
               //Return the actual length of the option
               *optlen = sizeof(int_t);
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#endif
#if (TCP_SUPPORT == ENABLED && TCP_KEEP_ALIVE_SUPPORT == ENABLED)
         else if(optname == SO_KEEPALIVE)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(TIMEVAL))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //This option specifies whether TCP keep-alive is enabled
               *val = sock->keepAliveEnabled;
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#endif
         else if(optname == SO_ERROR)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Return the error code
               *val = sock->errnoCode;
               //Return the actual length of the option
               *optlen = sizeof(int_t);

               //Clear error status
               sock->errnoCode = 0;

               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
         else
         {
            //Unknown option
            socketSetErrnoCode(sock, ENOPROTOOPT);
            ret = SOCKET_ERROR;
         }
      }
      else if(level == IPPROTO_IP)
      {
         //Check option type
         if(optname == IP_TTL)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Return TTL value
               *val = sock->ttl;
               //Return the actual length of the option
               *optlen = sizeof(int_t);

               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
         else if(optname == IP_MULTICAST_TTL)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Return TTL value for multicast packets
               *val = sock->multicastTtl;
               //Return the actual length of the option
               *optlen = sizeof(int_t);

               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#if (IP_DIFF_SERV_SUPPORT == ENABLED)
         else if(optname == IP_TOS)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Return DSCP value
               *val = sock->dscp << 2;
               //Return the actual length of the option
               *optlen = sizeof(int_t);

               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
#endif
         else
         {
            //Unknown option
            socketSetErrnoCode(sock, ENOPROTOOPT);
            ret = SOCKET_ERROR;
         }
      }
      else if(level == IPPROTO_TCP)
      {
#if (TCP_SUPPORT == ENABLED && TCP_KEEP_ALIVE_SUPPORT == ENABLED)
         //Check option type
         if(optname == TCP_KEEPIDLE)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Convert the time interval to seconds
               *val = sock->keepAliveIdle / 1000;
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
         else if(optname == TCP_KEEPINTVL)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Convert the time interval to seconds
               *val = sock->keepAliveInterval / 1000;
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
         else if(optname == TCP_KEEPCNT)
         {
            //Check the length of the option
            if(*optlen >= (socklen_t) sizeof(int_t))
            {
               //Cast the option value to the relevant type
               val = (int_t *) optval;
               //Return parameter value
               *val = sock->keepAliveMaxProbes;
               //Successful processing
               ret = SOCKET_SUCCESS;
            }
            else
            {
               //The option length is not valid
               socketSetErrnoCode(sock, EFAULT);
               ret = SOCKET_ERROR;
            }
         }
         else
#endif
         {
            //Unknown option
            socketSetErrnoCode(sock, ENOPROTOOPT);
            ret = SOCKET_ERROR;
         }
      }
      else
      {
         //The specified level is not valid
         socketSetErrnoCode(sock, EINVAL);
         ret = SOCKET_ERROR;
      }
   }
   else
   {
      //The option is not valid
      socketSetErrnoCode(sock, EFAULT);
      ret = SOCKET_ERROR;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //return status code
   return ret;
}


/**
 * @brief Control the I/O mode of a socket
 * @param[in] s Descriptor that identifies a socket
 * @param[in] cmd A command to perform on the socket
 * @param[in,out] arg A pointer to a parameter
 * @return If no error occurs, setsockopt returns SOCKET_SUCCESS
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t ioctlsocket(int_t s, uint32_t cmd, void *arg)
{
   int_t ret;
   uint_t *val;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Make sure the parameter is valid
   if(arg != NULL)
   {
      //Check command type
      switch(cmd)
      {
      //Enable or disable non-blocking mode
      case FIONBIO:
         //Cast the parameter to the relevant type
         val = (uint_t *) arg;
         //Enable blocking or non-blocking operation
         sock->timeout = (*val != 0) ? 0 : INFINITE_DELAY;
         //Successful processing
         ret = SOCKET_SUCCESS;
         break;

#if (TCP_SUPPORT == ENABLED)
      //Get the number of bytes that are immediately available for reading
      case FIONREAD:
         //Cast the parameter to the relevant type
         val = (uint_t *) arg;
         //Return the actual value
         *val = sock->rcvUser;
         //Successful processing
         ret = SOCKET_SUCCESS;
         break;

      //Get the number of bytes written to the send queue but not yet
      //acknowledged by the other side of the connection
      case FIONWRITE:
         //Cast the parameter to the relevant type
         val = (uint_t *) arg;
         //Return the actual value
         *val = sock->sndUser + sock->sndNxt - sock->sndUna;
         //Successful processing
         ret = SOCKET_SUCCESS;
         break;

      //Get the free space	in the send queue
      case FIONSPACE:
         //Cast the parameter to the relevant type
         val = (uint_t *) arg;
         //Return the actual value
         *val = sock->txBufferSize - (sock->sndUser + sock->sndNxt -
            sock->sndUna);
         //Successful processing
         ret = SOCKET_SUCCESS;
         break;
#endif

      //Unknown command?
      default:
         //Report an error
         socketSetErrnoCode(sock, EINVAL);
         ret = SOCKET_ERROR;
         break;
      }
   }
   else
   {
      //The parameter is not valid
      socketSetErrnoCode(sock, EFAULT);
      ret = SOCKET_ERROR;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //return status code
   return ret;
}


/**
 * @brief Perform specific operation
 * @param[in] s Descriptor that identifies a socket
 * @param[in] cmd A command to perform on the socket
 * @param[in,out] arg A pointer to a parameter
 * @return If no error occurs, setsockopt returns SOCKET_SUCCESS
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t fcntl(int_t s, int_t cmd, void *arg)
{
   int_t ret;
   int_t *flags;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Make sure the parameter is valid
   if(arg != NULL)
   {
      //Check command type
      switch(cmd)
      {
      //Get the file status flags?
      case F_GETFL:
         //Cast the parameter to the relevant type
         flags = (int_t *) arg;
         //Check whether non-blocking mode is currently enabled
         *flags = (sock->timeout == 0) ? O_NONBLOCK : 0;
         //Successful processing
         ret = SOCKET_SUCCESS;
         break;

      //Set the file status flags?
      case F_SETFL:
         //Cast the parameter to the relevant type
         flags = (int_t *) arg;
         //Enable blocking or non-blocking operation
         sock->timeout = (*flags & O_NONBLOCK) ? 0 : INFINITE_DELAY;
         //Successful processing
         ret = SOCKET_SUCCESS;
         break;

      //Unknown command?
      default:
         //Report an error
         socketSetErrnoCode(sock, EINVAL);
         ret = SOCKET_ERROR;
         break;
      }
   }
   else
   {
      //Report an error
      socketSetErrnoCode(sock, EFAULT);
      ret = SOCKET_ERROR;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //return status code
   return ret;
}


/**
 * @brief The shutdown function disables sends or receives on a socket
 * @param[in] s Descriptor that identifies a socket
 * @param[in] how A flag that describes what types of operation will no longer be allowed
 * @return If no error occurs, shutdown returns SOCKET_SUCCESS
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t shutdown(int_t s, int_t how)
{
   error_t error;
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Shut down socket
   error = socketShutdown(sock, how);

   //Any error to report?
   if(error)
   {
      socketTranslateErrorCode(sock, error);
      return SOCKET_ERROR;
   }

   //Successful processing
   return SOCKET_SUCCESS;
}


/**
 * @brief The closesocket function closes an existing socket
 * @param[in] s Descriptor that identifies a socket
 * @return If no error occurs, closesocket returns SOCKET_SUCCESS
 *   Otherwise, it returns SOCKET_ERROR
 **/

int_t closesocket(int_t s)
{
   Socket *sock;

   //Make sure the socket descriptor is valid
   if(s < 0 || s >= SOCKET_MAX_COUNT)
   {
      return SOCKET_ERROR;
   }

   //Point to the socket structure
   sock = &socketTable[s];

   //Close socket
   socketClose(sock);

   //Successful processing
   return SOCKET_SUCCESS;
}


/**
 * @brief Determine the status of one or more sockets
 *
 * The select function determines the status of one or more sockets,
 * waiting if necessary, to perform synchronous I/O
 *
 * @param[in] nfds Unused parameter included only for compatibility with
 *   Berkeley socket
 * @param[in,out] readfds An optional pointer to a set of sockets to be
 *   checked for readability
 * @param[in,out] writefds An optional pointer to a set of sockets to be
 *   checked for writability
 * @param[in,out] exceptfds An optional pointer to a set of sockets to be
 *   checked for errors
 * @param[in] timeout The maximum time for select to wait. Set the timeout
 *   parameter to null for blocking operations
 * @return The select function returns the total number of socket handles that
 *   are ready and contained in the fd_set structures, zero if the time limit
 *   expired, or SOCKET_ERROR if an error occurred
 **/

int_t select(int_t nfds, fd_set *readfds, fd_set *writefds,
   fd_set *exceptfds, const struct timeval *timeout)
{
   int_t i;
   int_t j;
   int_t n;
   int_t s;
   systime_t time;
   uint_t eventMask;
   uint_t eventFlags;
   OsEvent event;
   fd_set *fds;

   //Parse all the descriptor sets
   for(i = 0; i < 3; i++)
   {
      //Select the suitable descriptor set
      switch(i)
      {
      case 0:
         //Set of sockets to be checked for readability
         fds = readfds;
         break;
      case 1:
         //Set of sockets to be checked for writability
         fds = writefds;
         break;
      default:
         //Set of sockets to be checked for errors
         fds = exceptfds;
         break;
      }

      //Each descriptor is optional and may be omitted
      if(fds != NULL)
      {
         //Parse the current set of sockets
         for(j = 0; j < fds->fd_count; j++)
         {
            //Invalid socket descriptor?
            if(fds->fd_array[j] < 0 || fds->fd_array[j] >= SOCKET_MAX_COUNT)
            {
               //Report an error
               return SOCKET_ERROR;
            }
         }
      }
   }

   //Create an event object to get notified of socket events
   if(!osCreateEvent(&event))
   {
      //Failed to create event
      return SOCKET_ERROR;
   }

   //Parse all the descriptor sets
   for(i = 0; i < 3; i++)
   {
      //Select the suitable descriptor set
      switch(i)
      {
      case 0:
         //Set of sockets to be checked for readability
         fds = readfds;
         eventMask = SOCKET_EVENT_RX_READY;
         break;
      case 1:
         //Set of sockets to be checked for writability
         fds = writefds;
         eventMask = SOCKET_EVENT_TX_READY;
         break;
      default:
         //Set of sockets to be checked for errors
         fds = exceptfds;
         eventMask = SOCKET_EVENT_CLOSED;
         break;
      }

      //Each descriptor is optional and may be omitted
      if(fds != NULL)
      {
         //Parse the current set of sockets
         for(j = 0; j < fds->fd_count; j++)
         {
            //Get the descriptor associated with the current entry
            s = fds->fd_array[j];
            //Subscribe to the requested events
            socketRegisterEvents(&socketTable[s], &event, eventMask);
         }
      }
   }

   //Retrieve timeout value
   if(timeout != NULL)
   {
      time = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
   }
   else
   {
      time = INFINITE_DELAY;
   }

   //Block the current task until an event occurs
   osWaitForEvent(&event, time);

   //Count the number of events in the signaled state
   n = 0;

   //Parse all the descriptor sets
   for(i = 0; i < 3; i++)
   {
      //Select the suitable descriptor set
      switch(i)
      {
      case 0:
         //Set of sockets to be checked for readability
         fds = readfds;
         eventMask = SOCKET_EVENT_RX_READY;
         break;
      case 1:
         //Set of sockets to be checked for writability
         fds = writefds;
         eventMask = SOCKET_EVENT_TX_READY;
         break;
      default:
         //Set of sockets to be checked for errors
         fds = exceptfds;
         eventMask = SOCKET_EVENT_CLOSED;
         break;
      }

      //Each descriptor is optional and may be omitted
      if(fds != NULL)
      {
         //Parse the current set of sockets
         for(j = 0; j < fds->fd_count; )
         {
            //Get the descriptor associated with the current entry
            s = fds->fd_array[j];
            //Retrieve event flags for the current socket
            eventFlags = socketGetEvents(&socketTable[s]);
            //Unsubscribe previously registered events
            socketUnregisterEvents(&socketTable[s]);

            //Event flag is set?
            if(eventFlags & eventMask)
            {
               //Track the number of events in the signaled state
               n++;
               //Jump to the next socket descriptor
               j++;
            }
            else
            {
               //Remove descriptor from the current set
               socketFdClr(fds, s);
            }
         }
      }
   }

   //Delete event object
   osDeleteEvent(&event);
   //Return the number of events in the signaled state
   return n;
}


/**
 * @brief Get system host name
 * @param[out] name Output buffer where to store the system host name
 * @param[in] len Length of the buffer, in bytes
 * @return On success, zero is returned. On error, -1 is returned
 **/

int_t gethostname(char_t *name, size_t len)
{
   size_t n;
   NetInterface *interface;

   //Check parameter
   if(name == NULL)
   {
      //Report an error
      BSD_SOCKET_SET_ERRNO(EINVAL);
      return -1;
   }

   //Select the default network interface
   interface = netGetDefaultInterface();

   //Retrieve the length of the host name
   n = osStrlen(interface->hostname);

   //Make sure the buffer is large enough to hold the string
   if(len <= n)
   {
      //Report an error
      BSD_SOCKET_SET_ERRNO(ENAMETOOLONG);
      return -1;
   }

   //Copy the host name
   osStrcpy(name, interface->hostname);

   //Successful processing
   return 0;
}


/**
 * @brief Host name resolution
 * @param[in] name Name of the host to resolve
 * @return Pointer to the hostent structure or a NULL if an error occurs
 **/

struct hostent *gethostbyname(const char_t *name)
{
   int_t herrno;
   static HOSTENT result;

   //The hostent structure returned by the function resides in static
   //memory area
   return gethostbyname_r(name, &result, NULL, 0, &herrno);
}


/**
 * @brief Host name resolution (reentrant version)
 * @param[in] name Name of the host to resolve
 * @param[in] result Pointer to a hostent structure where the function can
 *   store the host entry
 * @param[out] buf Pointer to a temporary work buffer
 * @param[in] buflen Length of the temporary work buffer
 * @param[out] h_errnop Pointer to a location where the function can store an
 *   h_errno value if an error occurs
 * @return Pointer to the hostent structure or a NULL if an error occurs
 **/

struct hostent *gethostbyname_r(const char_t *name, struct hostent *result,
   char_t *buf, size_t buflen, int_t *h_errnop)
{
   error_t error;
   IpAddr ipAddr;

   //Check input parameters
   if(name == NULL || result == NULL)
   {
      //Report an error
      *h_errnop = NO_RECOVERY;
      return NULL;
   }

   //Resolve host address
   error = getHostByName(NULL, name, &ipAddr, 0);
   //Address resolution failed?
   if(error)
   {
      //Report an error
      *h_errnop = HOST_NOT_FOUND;
      return NULL;
   }

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address?
   if(ipAddr.length == sizeof(Ipv4Addr))
   {
      //Set address family
      result->h_addrtype = AF_INET;
      result->h_length = sizeof(Ipv4Addr);

      //Copy IPv4 address
      ipv4CopyAddr(result->h_addr, &ipAddr.ipv4Addr);
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address?
   if(ipAddr.length == sizeof(Ipv6Addr))
   {
      //Set address family
      result->h_addrtype = AF_INET6;
      result->h_length = sizeof(Ipv6Addr);

      //Copy IPv6 address
      ipv6CopyAddr(result->h_addr, &ipAddr.ipv6Addr);
   }
   else
#endif
   //Invalid address?
   {
      //Report an error
      *h_errnop = NO_ADDRESS;
      return NULL;
   }

   //Successful host name resolution
   *h_errnop = NETDB_SUCCESS;

   //Return a pointer to the hostent structure
   return result;
}


/**
 * @brief Convert host and service names to socket address
 * @param[in] node Host name or numerical network address
 * @param[in] service Service name or decimal number
 * @param[in] hints Criteria for selecting the socket address structures
 * @param[out] res Dynamically allocated list of socket address structures
 * @return On success, zero is returned. On error, a non-zero value is returned
 **/

int_t getaddrinfo(const char_t *node, const char_t *service,
   const struct addrinfo *hints, struct addrinfo **res)
{
   error_t error;
   size_t n;
   char_t *p;
   uint_t flags;
   uint16_t port;
   IpAddr ipAddr;
   ADDRINFO h;
   ADDRINFO *ai;

   //Check whether both node and service name are NULL
   if(node == NULL && service == NULL)
      return EAI_NONAME;

   //The hints argument is optional
   if(hints != NULL)
   {
      //If hints is not NULL, it points to an addrinfo structure that specifies
      //criteria that limit the set of socket addresses that will be returned
      h = *hints;
   }
   else
   {
      //If hints is NULL, then default criteria are used
      osMemset(&h, 0, sizeof(ADDRINFO));
      h.ai_family = AF_UNSPEC;
      h.ai_socktype = 0;
      h.ai_protocol = 0;
      h.ai_flags = 0;
   }

   //The user may provide a hint to choose between IPv4 and IPv6
   if(h.ai_family == AF_UNSPEC)
   {
      //The value AF_UNSPEC indicates that function should return socket
      //addresses for any address family (either IPv4 or IPv6)
      flags = 0;
   }
#if (IPV4_SUPPORT == ENABLED)
   else if(h.ai_family == AF_INET)
   {
      //The value AF_INET indicates that the function should return an IPv4
      //address
      flags = HOST_TYPE_IPV4;
   }
#endif
#if (IPV6_SUPPORT == ENABLED)
   else if(h.ai_family == AF_INET6)
   {
      //The value AF_INET6 indicates that the function should return an IPv6
      //address
      flags = HOST_TYPE_IPV6;
   }
#endif
   else
   {
      //The requested address family is not supported
      return EAI_FAMILY;
   }

   //Check whether a host name or numerical network address is specified
   if(node != NULL)
   {
      //If the AI_NUMERICHOST flag, then node must be a numerical network
      //address
      if((h.ai_flags & AI_NUMERICHOST) != 0)
      {
         //Convert the string representation to a binary IP address
         error = ipStringToAddr(node, &ipAddr);
      }
      else
      {
         //Resolve host address
         error = getHostByName(NULL, node, &ipAddr, flags);
      }

      //Check status code
      if(error == NO_ERROR)
      {
         //Successful host name resolution
      }
      else if(error == ERROR_IN_PROGRESS)
      {
         //Host name resolution is in progress
         return EAI_AGAIN;
      }
      else
      {
         //Permanent failure indication
         return EAI_FAIL;
      }
   }
   else
   {
      //Check flags
      if((h.ai_flags & AI_PASSIVE) != 0)
      {
#if (IPV4_SUPPORT == ENABLED)
         //IPv4 address family?
         if(h.ai_family == AF_INET || h.ai_family == AF_UNSPEC)
         {
            ipAddr.length = sizeof(Ipv4Addr);
            ipAddr.ipv4Addr = IPV4_UNSPECIFIED_ADDR;
         }
         else
#endif
#if (IPV6_SUPPORT == ENABLED)
         //IPv6 address family?
         if(h.ai_family == AF_INET6 || h.ai_family == AF_UNSPEC)
         {
            ipAddr.length = sizeof(Ipv6Addr);
            ipAddr.ipv6Addr = IPV6_UNSPECIFIED_ADDR;
         }
         else
#endif
         //Unknown address family?
         {
            //Report an error
            return EAI_ADDRFAMILY;
         }
      }
      else
      {
         //Invalid flags
         return EAI_BADFLAGS;
      }
   }

   //Only service names containing a numeric port number are supported
   port = strtoul(service, &p, 10);
   //Invalid service name?
   if(*p != '\0')
   {
      //The requested service is not available
      return EAI_SERVICE;
   }

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address?
   if(ipAddr.length == sizeof(Ipv4Addr))
   {
      //Select the relevant socket family
      h.ai_family = AF_INET;
      //Get the length of the corresponding socket address
      n = sizeof(SOCKADDR_IN);
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address?
   if(ipAddr.length == sizeof(Ipv6Addr))
   {
      //Select the relevant socket family
      h.ai_family = AF_INET6;
      //Get the length of the corresponding socket address
      n = sizeof(SOCKADDR_IN6);
   }
   else
#endif
   //Unknown address?
   {
      //Report an error
      return EAI_ADDRFAMILY;
   }

   //Allocate a memory buffer to hold the address information structure
   ai = osAllocMem(sizeof(ADDRINFO) + n);
   //Failed to allocate memory?
   if(ai == NULL)
   {
      //Out of memory
      return EAI_MEMORY;
   }

   //Initialize address information structure
   osMemset(ai, 0, sizeof(ADDRINFO) + n);
   ai->ai_family = h.ai_family;
   ai->ai_socktype = h.ai_socktype;
   ai->ai_protocol = h.ai_protocol;
   ai->ai_addr = (SOCKADDR *) ((uint8_t *) ai + sizeof(ADDRINFO));
   ai->ai_addrlen = n;
   ai->ai_next = NULL;

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address?
   if(ipAddr.length == sizeof(Ipv4Addr))
   {
      //Point to the IPv4 address information
      SOCKADDR_IN *sa = (SOCKADDR_IN *) ai->ai_addr;

      //Set address family and port number
      sa->sin_family = AF_INET;
      sa->sin_port = htons(port);

      //Copy IPv4 address
      sa->sin_addr.s_addr = ipAddr.ipv4Addr;
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address?
   if(ipAddr.length == sizeof(Ipv6Addr))
   {
      //Point to the IPv6 address information
      SOCKADDR_IN6 *sa = (SOCKADDR_IN6 *) ai->ai_addr;

      //Set address family and port number
      sa->sin6_family = AF_INET6;
      sa->sin6_port = htons(port);

      //Copy IPv6 address
      ipv6CopyAddr(sa->sin6_addr.s6_addr, &ipAddr.ipv6Addr);
   }
   else
#endif
   //Unknown address?
   {
      //Clean up side effects
      osFreeMem(ai);
      //Report an error
      return EAI_ADDRFAMILY;
   }

   //Return a pointer to the allocated address information
   *res = ai;

   //Successful processing
   return 0;
}


/**
 * @brief Free socket address structures
 * @param[in] res Dynamically allocated list of socket address structures
 **/

void freeaddrinfo(struct addrinfo *res)
{
   ADDRINFO *next;

   //Free the list of socket address structures
   while(res != NULL)
   {
      //Get next entry
      next = res->ai_next;
      //Free current socket address structure
      osFreeMem(res);
      //Point to the next entry
      res = next;
   }
}


/**
 * @brief Convert a socket address to a corresponding host and service
 * @param[in] addr Generic socket address structure
 * @param[in] addrlen Length in bytes of the address
 * @param[out] host Output buffer where to store the host name
 * @param[in] hostlen Length of the host name buffer, in bytes
 * @param[out] serv Output buffer where to store the service name
 * @param[in] servlen Length of the service name buffer, in bytes
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return On success, zero is returned. On error, a non-zero value is returned
 **/

int_t getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
   char_t *host, size_t hostlen, char_t *serv, size_t servlen, int flags)
{
   uint16_t port;

   //At least one of hostname or service name must be requested
   if(host == NULL && serv == NULL)
      return EAI_NONAME;

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address?
   if(addr->sa_family == AF_INET &&
      addrlen >= (socklen_t) sizeof(SOCKADDR_IN))
   {
      SOCKADDR_IN *sa;
      Ipv4Addr ipv4Addr;

      //Point to the IPv4 address information
      sa = (SOCKADDR_IN *) addr;

      //The caller can specify that no host name is required
      if(host != NULL)
      {
         //Make sure the buffer is large enough to hold the host name
         if(hostlen < 16)
            return EAI_OVERFLOW;

         //Copy the binary representation of the IPv4 address
         ipv4CopyAddr(&ipv4Addr, &sa->sin_addr.s_addr);
         //Convert the IPv4 address to dot-decimal notation
         ipv4AddrToString(ipv4Addr, host);
      }

      //Retrieve port number
      port = ntohs(sa->sin_port);
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address?
   if(addr->sa_family == AF_INET6 &&
      addrlen >= (socklen_t) sizeof(SOCKADDR_IN6))
   {
      SOCKADDR_IN6 *sa;
      Ipv6Addr ipv6Addr;

      //Point to the IPv6 address information
      sa = (SOCKADDR_IN6 *) addr;

      //The caller can specify that no host name is required
      if(host != NULL)
      {
         //Make sure the buffer is large enough to hold the host name
         if(hostlen < 40)
            return EAI_OVERFLOW;

         //Copy the binary representation of the IPv6 address
         ipv6CopyAddr(&ipv6Addr, sa->sin6_addr.s6_addr);
         //Convert the IPv6 address to string representation
         ipv6AddrToString(&ipv6Addr, host);
      }

      //Retrieve port number
      port = ntohs(sa->sin6_port);
   }
   else
#endif
   //Invalid address?
   {
      //The address family was not recognized, or the address length was
      //invalid for the specified family
      return EAI_FAMILY;
   }

   //The caller can specify that no service name is required
   if(serv != NULL)
   {
      //Make sure the buffer is large enough to hold the service name
      if(servlen < 6)
         return EAI_OVERFLOW;

      //Convert the port number to string representation
      osSprintf(serv, "%" PRIu16, ntohs(port));
   }

   //Successful processing
   return 0;
}


/**
 * @brief Convert a dot-decimal string into binary data in network byte order
 * @param[in] cp NULL-terminated string representing the IPv4 address
 * @return Binary data in network byte order
 **/

in_addr_t inet_addr(const char_t *cp)
{
#if (IPV4_SUPPORT == ENABLED)
   error_t error;
   Ipv4Addr ipv4Addr;

   //Convert a dot-decimal string to a binary IPv4 address
   error = ipv4StringToAddr(cp, &ipv4Addr);

   //Check status code
   if(error)
   {
      //The input is invalid
      return INADDR_NONE;
   }
   else
   {
      //Return the binary representation
      return ipv4Addr;
   }
#else
   //IPv4 is not implemented
   return INADDR_NONE;
#endif
}


/**
 * @brief Convert a dot-decimal string into binary form
 * @param[in] cp NULL-terminated string representing the IPv4 address
 * @param[out] inp Binary data in network byte order
 * @return The function returns non-zero if the address is valid, zero if not
 **/

int_t inet_aton(const char_t *cp, struct in_addr *inp)
{
#if (IPV4_SUPPORT == ENABLED)
   error_t error;
   Ipv4Addr ipv4Addr;

   //Convert a dot-decimal string to a binary IPv4 address
   error = ipv4StringToAddr(cp, &ipv4Addr);

   //Check status code
   if(error)
   {
      //The input is invalid
      return 0;
   }
   else
   {
      //Copy the binary representation of the IPv4 address
      inp->s_addr = ipv4Addr;
      //The conversion succeeded
      return 1;
   }
#else
   //IPv4 is not implemented
   return 0;
#endif
}


/**
 * @brief Convert a binary IPv4 address to dot-decimal notation
 * @param[in] in Binary representation of the IPv4 address
 * @return Pointer to the formatted string
 **/

const char_t *inet_ntoa(struct in_addr in)
{
   static char_t buf[16];

   //The string returned by the function resides in static memory area
   return inet_ntoa_r(in, buf, sizeof(buf));
}


/**
 * @brief Convert a binary IPv4 address to dot-decimal notation (reentrant version)
 * @param[in] in Binary representation of the IPv4 address
 * @param[out] buf Pointer to the buffer where to format the string
 * @param[in] buflen Number of bytes available in the buffer
 * @return Pointer to the formatted string
 **/

const char_t *inet_ntoa_r(struct in_addr in, char_t *buf, socklen_t buflen)
{
   //Properly terminate the string
   buf[0] = '\0';

#if (IPV4_SUPPORT == ENABLED)
   //Check the length of the buffer
   if(buflen >= 16)
   {
      //Convert the binary IPv4 address to dot-decimal notation
      ipv4AddrToString(in.s_addr, buf);
   }
#endif

   //Return a pointer to the formatted string
   return buf;
}


/**
 * @brief Convert an IPv4 or IPv6 address from text to binary form
 * @param[in] af Address family
 * @param[in] src NULL-terminated string representing the IP address
 * @param[out] dst Binary representation of the IP address
 * @return The function returns 1 on success. 0 is returned if the address
 *   is not valid. If the address family is not valid, -1 is returned
 **/

int_t inet_pton(int_t af, const char_t *src, void *dst)
{
   error_t error;

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address?
   if(af == AF_INET)
   {
      Ipv4Addr ipv4Addr;

      //Convert the IPv4 address from text to binary form
      error = ipv4StringToAddr(src, &ipv4Addr);

      //Check status code
      if(error)
      {
         //The input is invalid
         return 0;
      }
      else
      {
         //Copy the binary representation of the IPv4 address
         ipv4CopyAddr(dst, &ipv4Addr);
         //The conversion succeeded
         return 1;
      }
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address?
   if(af == AF_INET6)
   {
      Ipv6Addr ipv6Addr;

      //Convert the IPv6 address from text to binary form
      error = ipv6StringToAddr(src, &ipv6Addr);

      //Check status code
      if(error)
      {
         //The input is invalid
         return 0;
      }
      else
      {
         //Copy the binary representation of the IPv6 address
         ipv6CopyAddr(dst, &ipv6Addr);
         //The conversion succeeded
         return 1;
      }
   }
   else
#endif
   //Invalid address family?
   {
      //Report an error
      return -1;
   }
}


/**
 * @brief Convert an IPv4 or IPv6 address from binary to text
 * @param[in] af Address family
 * @param[in] src Binary representation of the IP address
 * @param[out] dst NULL-terminated string representing the IP address
 * @param[in] size Number of bytes available in the buffer
 * @return On success, the function returns a pointer to the formatted string.
 *   NULL is returned if there was an error
 **/

const char_t *inet_ntop(int_t af, const void *src, char_t *dst, socklen_t size)
{
#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address?
   if(af == AF_INET && size >= INET_ADDRSTRLEN)
   {
      Ipv4Addr ipv4Addr;

      //Copy the binary representation of the IPv4 address
      ipv4CopyAddr(&ipv4Addr, src);

      //Convert the IPv4 address to dot-decimal notation
      return ipv4AddrToString(ipv4Addr, dst);
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address?
   if(af == AF_INET6 && size >= INET6_ADDRSTRLEN)
   {
      Ipv6Addr ipv6Addr;

      //Copy the binary representation of the IPv6 address
      ipv6CopyAddr(&ipv6Addr, src);

      //Convert the IPv6 address to string representation
      return ipv6AddrToString(&ipv6Addr, dst);
   }
   else
#endif
   //Invalid address family?
   {
      //Report an error
      return NULL;
   }
}

#endif

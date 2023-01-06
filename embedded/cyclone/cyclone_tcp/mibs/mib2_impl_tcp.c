/**
 * @file mib2_impl_tcp.c
 * @brief MIB-II module implementation (TCP group)
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
#define TRACE_LEVEL SNMP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "mibs/mib_common.h"
#include "mibs/mib2_module.h"
#include "mibs/mib2_impl.h"
#include "mibs/mib2_impl_tcp.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (MIB2_SUPPORT == ENABLED && MIB2_TCP_GROUP_SUPPORT == ENABLED)


/**
 * @brief Get tcpCurrEstab object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t mib2GetTcpCurrEstab(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   uint_t i;
   Socket *socket;

   //Initialize object value
   value->gauge32 = 0;

   //Loop through socket descriptors
   for(i = 0; i < SOCKET_MAX_COUNT; i++)
   {
      //Point to current socket
      socket = &socketTable[i];

      //TCP socket?
      if(socket->type == SOCKET_TYPE_STREAM)
      {
         //Filter out IPv6 connections
         if(socket->localIpAddr.length != sizeof(Ipv6Addr) &&
            socket->remoteIpAddr.length != sizeof(Ipv6Addr))
         {
            //Check current state
            if(socket->state == TCP_STATE_ESTABLISHED ||
               socket->state == TCP_STATE_CLOSE_WAIT)
            {
               //Number of TCP connections for which the current state
               //is either ESTABLISHED or CLOSE-WAIT
               value->gauge32++;
            }
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set tcpConnEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t mib2SetTcpConnEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
   //Not implemented
   return ERROR_WRITE_FAILED;
}


/**
 * @brief Get tcpConnEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t mib2GetTcpConnEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t i;
   size_t n;
   Ipv4Addr localIpAddr;
   uint16_t localPort;
   Ipv4Addr remoteIpAddr;
   uint16_t remotePort;
   Socket *socket;

   //Point to the instance identifier
   n = object->oidLen;

   //tcpConnLocalAddress is used as 1st instance identifier
   error = mibDecodeIpv4Addr(oid, oidLen, &n, &localIpAddr);
   //Invalid instance identifier?
   if(error)
      return error;

   //tcpConnLocalPort is used as 2nd instance identifier
   error = mibDecodePort(oid, oidLen, &n, &localPort);
   //Invalid instance identifier?
   if(error)
      return error;

   //tcpConnRemAddress is used as 3rd instance identifier
   error = mibDecodeIpv4Addr(oid, oidLen, &n, &remoteIpAddr);
   //Invalid instance identifier?
   if(error)
      return error;

   //tcpConnRemPort is used as 4th instance identifier
   error = mibDecodePort(oid, oidLen, &n, &remotePort);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Loop through socket descriptors
   for(i = 0; i < SOCKET_MAX_COUNT; i++)
   {
      //Point to current socket
      socket = &socketTable[i];

      //TCP socket?
      if(socket->type == SOCKET_TYPE_STREAM)
      {
         //Check local IP address
         if(socket->localIpAddr.length == sizeof(Ipv6Addr))
            continue;
         if(socket->localIpAddr.ipv4Addr != localIpAddr)
            continue;
         //Check local port number
         if(socket->localPort != localPort)
            continue;
         //Check remote IP address
         if(socket->remoteIpAddr.length == sizeof(Ipv6Addr))
            continue;
         if(socket->remoteIpAddr.ipv4Addr != remoteIpAddr)
            continue;
         //Check remote port number
         if(socket->remotePort != remotePort)
            continue;

         //A matching socket has been found
         break;
      }
   }

   //No matching connection found in socket table?
   if(i >= SOCKET_MAX_COUNT)
      return ERROR_INSTANCE_NOT_FOUND;

   //tcpConnState object?
   if(!osStrcmp(object->name, "tcpConnState"))
   {
      //Get object value
      switch(socket->state)
      {
      case TCP_STATE_CLOSED:
         value->integer = MIB2_TCP_CONN_STATE_CLOSED;
         break;
      case TCP_STATE_LISTEN:
         value->integer = MIB2_TCP_CONN_STATE_LISTEN;
         break;
      case TCP_STATE_SYN_SENT:
         value->integer = MIB2_TCP_CONN_STATE_SYN_SENT;
         break;
      case TCP_STATE_SYN_RECEIVED:
         value->integer = MIB2_TCP_CONN_STATE_SYN_RECEIVED;
         break;
      case TCP_STATE_ESTABLISHED:
         value->integer = MIB2_TCP_CONN_STATE_ESTABLISHED;
         break;
      case TCP_STATE_FIN_WAIT_1:
         value->integer = MIB2_TCP_CONN_STATE_FIN_WAIT_1;
         break;
      case TCP_STATE_FIN_WAIT_2:
         value->integer = MIB2_TCP_CONN_STATE_FIN_WAIT_2;
         break;
      case TCP_STATE_CLOSE_WAIT:
         value->integer = MIB2_TCP_CONN_STATE_CLOSE_WAIT;
         break;
      case TCP_STATE_LAST_ACK:
         value->integer = MIB2_TCP_CONN_STATE_LAST_ACK;
         break;
      case TCP_STATE_CLOSING:
         value->integer = MIB2_TCP_CONN_STATE_CLOSING;
         break;
      case TCP_STATE_TIME_WAIT:
         value->integer = MIB2_TCP_CONN_STATE_TIME_WAIT;
         break;
      default:
         value->integer = 0;
         break;
      }
   }
   //tcpConnLocalAddress object?
   else if(!osStrcmp(object->name, "tcpConnLocalAddress"))
   {
      //Get object value
      ipv4CopyAddr(value->ipAddr, &socket->localIpAddr.ipv4Addr);
   }
   //tcpConnLocalPort object?
   else if(!osStrcmp(object->name, "tcpConnLocalPort"))
   {
      //Get object value
      value->integer = socket->localPort;
   }
   //tcpConnRemAddress object?
   else if(!osStrcmp(object->name, "tcpConnRemAddress"))
   {
      //Get object value
      ipv4CopyAddr(value->ipAddr, &socket->remoteIpAddr.ipv4Addr);
   }
   //tcpConnRemPort object?
   else if(!osStrcmp(object->name, "tcpConnRemPort"))
   {
      //Get object value
      value->integer = socket->remotePort;
   }
   //Unknown object?
   else
   {
      //The specified object does not exist
      error = ERROR_OBJECT_NOT_FOUND;
   }

   //Return status code
   return error;
}


/**
 * @brief Get next tcpConnEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t mib2GetNextTcpConnEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   bool_t acceptable;
   Ipv4Addr localIpAddr;
   uint16_t localPort;
   Ipv4Addr remoteIpAddr;
   uint16_t remotePort;
   Socket *socket;

   //Initialize variables
   localIpAddr = IPV4_UNSPECIFIED_ADDR;
   localPort = 0;
   remoteIpAddr = IPV4_UNSPECIFIED_ADDR;
   remotePort = 0;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through socket descriptors
   for(i = 0; i < SOCKET_MAX_COUNT; i++)
   {
      //Point to current socket
      socket = &socketTable[i];

      //TCP socket?
      if(socket->type == SOCKET_TYPE_STREAM)
      {
         //Filter out IPv6 connections
         if(socket->localIpAddr.length != sizeof(Ipv6Addr) &&
            socket->remoteIpAddr.length != sizeof(Ipv6Addr))
         {
            //Append the instance identifier to the OID prefix
            n = object->oidLen;

            //tcpConnLocalAddress is used as 1st instance identifier
            error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, socket->localIpAddr.ipv4Addr);
            //Any error to report?
            if(error)
               return error;

            //tcpConnLocalPort is used as 2nd instance identifier
            error = mibEncodePort(nextOid, *nextOidLen, &n, socket->localPort);
            //Any error to report?
            if(error)
               return error;

            //tcpConnRemAddress is used as 3rd instance identifier
            error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, socket->remoteIpAddr.ipv4Addr);
            //Any error to report?
            if(error)
               return error;

            //tcpConnRemPort is used as 4th instance identifier
            error = mibEncodePort(nextOid, *nextOidLen, &n, socket->remotePort);
            //Any error to report?
            if(error)
               return error;

            //Check whether the resulting object identifier lexicographically
            //follows the specified OID
            if(oidComp(nextOid, n, oid, oidLen) > 0)
            {
               //Perform lexicographic comparison
               if(localPort == 0 && remotePort == 0)
               {
                  acceptable = TRUE;
               }
               else if(ntohl(socket->localIpAddr.ipv4Addr) < ntohl(localIpAddr))
               {
                  acceptable = TRUE;
               }
               else if(ntohl(socket->localIpAddr.ipv4Addr) > ntohl(localIpAddr))
               {
                  acceptable = FALSE;
               }
               else if(socket->localPort < localPort)
               {
                  acceptable = TRUE;
               }
               else if(socket->localPort > localPort)
               {
                  acceptable = FALSE;
               }
               else if(ntohl(socket->remoteIpAddr.ipv4Addr) < ntohl(remoteIpAddr))
               {
                  acceptable = TRUE;
               }
               else if(ntohl(socket->remoteIpAddr.ipv4Addr) > ntohl(remoteIpAddr))
               {
                  acceptable = FALSE;
               }
               else if(socket->remotePort < remotePort)
               {
                  acceptable = TRUE;
               }
               else
               {
                  acceptable = FALSE;
               }

               //Save the closest object identifier that follows the specified
               //OID in lexicographic order
               if(acceptable)
               {
                  localIpAddr = socket->localIpAddr.ipv4Addr;
                  localPort = socket->localPort;
                  remoteIpAddr = socket->remoteIpAddr.ipv4Addr;
                  remotePort = socket->remotePort;
               }
            }
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(localPort == 0 && remotePort == 0)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //tcpConnLocalAddress is used as 1st instance identifier
   error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, localIpAddr);
   //Any error to report?
   if(error)
      return error;

   //tcpConnLocalPort is used as 2nd instance identifier
   error = mibEncodePort(nextOid, *nextOidLen, &n, localPort);
   //Any error to report?
   if(error)
      return error;

   //tcpConnRemAddress is used as 3rd instance identifier
   error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, remoteIpAddr);
   //Any error to report?
   if(error)
      return error;

   //tcpConnRemPort is used as 4th instance identifier
   error = mibEncodePort(nextOid, *nextOidLen, &n, remotePort);
   //Any error to report?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}

#endif

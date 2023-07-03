/**
 * @file mib2_impl_udp.c
 * @brief MIB-II module implementation (UDP group)
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
#include "mibs/mib2_impl_udp.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (MIB2_SUPPORT == ENABLED && MIB2_UDP_GROUP_SUPPORT == ENABLED)


/**
 * @brief Get udpEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t mib2GetUdpEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t i;
   size_t n;
   Ipv4Addr localIpAddr;
   uint16_t localPort;

   //Point to the instance identifier
   n = object->oidLen;

   //udpLocalAddress is used as 1st instance identifier
   error = mibDecodeIpv4Addr(oid, oidLen, &n, &localIpAddr);
   //Invalid instance identifier?
   if(error)
      return error;

   //udpLocalPort is used as 2nd instance identifier
   error = mibDecodePort(oid, oidLen, &n, &localPort);
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
      Socket *socket = &socketTable[i];

      //UDP socket?
      if(socket->type == SOCKET_TYPE_DGRAM)
      {
         //Check local IP address
         if(socket->localIpAddr.length == sizeof(Ipv6Addr))
            continue;
         if(socket->localIpAddr.ipv4Addr != localIpAddr)
            continue;
         //Check local port number
         if(socket->localPort != localPort)
            continue;

         //A matching socket has been found
         break;
      }
   }

   //No matching connection found in socket table?
   if(i >= SOCKET_MAX_COUNT)
   {
      //Loop through the UDP callback table
      for(i = 0; i < UDP_CALLBACK_TABLE_SIZE; i++)
      {
         //Point to the current entry
         UdpRxCallbackEntry *entry = &udpCallbackTable[i];

         //Check whether the entry is currently in use
         if(entry->callback != NULL)
         {
            //Check local port number
            if(entry->port == localPort)
               break;
         }
      }

      //No matching connection found in UDP callback table?
      if(i >= UDP_CALLBACK_TABLE_SIZE)
         return ERROR_INSTANCE_NOT_FOUND;
   }

   //udpLocalAddress object?
   if(!osStrcmp(object->name, "udpLocalAddress"))
   {
      //Get object value
      ipv4CopyAddr(value->ipAddr, &localIpAddr);
   }
   //udpLocalPort object?
   else if(!osStrcmp(object->name, "udpLocalPort"))
   {
      //Get object value
      value->integer = localPort;
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
 * @brief Get next udpEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t mib2GetNextUdpEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   bool_t acceptable;
   Ipv4Addr localIpAddr;
   uint16_t localPort;

   //Initialize variables
   localIpAddr = IPV4_UNSPECIFIED_ADDR;
   localPort = 0;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through socket descriptors
   for(i = 0; i < SOCKET_MAX_COUNT; i++)
   {
      //Point to current socket
      Socket *socket = &socketTable[i];

      //UDP socket?
      if(socket->type == SOCKET_TYPE_DGRAM)
      {
         //Filter out IPv6 connections
         if(socket->localIpAddr.length != sizeof(Ipv6Addr) &&
            socket->remoteIpAddr.length != sizeof(Ipv6Addr))
         {
            //Append the instance identifier to the OID prefix
            n = object->oidLen;

            //udpLocalAddress is used as 1st instance identifier
            error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, socket->localIpAddr.ipv4Addr);
            //Any error to report?
            if(error)
               return error;

            //udpLocalPort is used as 2nd instance identifier
            error = mibEncodePort(nextOid, *nextOidLen, &n, socket->localPort);
            //Any error to report?
            if(error)
               return error;

            //Check whether the resulting object identifier lexicographically
            //follows the specified OID
            if(oidComp(nextOid, n, oid, oidLen) > 0)
            {
               //Perform lexicographic comparison
               if(localPort == 0)
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
               }
            }
         }
      }
   }

   //Loop through the UDP callback table
   for(i = 0; i < UDP_CALLBACK_TABLE_SIZE; i++)
   {
      //Point to the current entry
      UdpRxCallbackEntry *entry = &udpCallbackTable[i];

      //Check whether the entry is currently in use
      if(entry->callback != NULL)
      {
         //Append the instance identifier to the OID prefix
         n = object->oidLen;

         //udpLocalAddress is used as 1st instance identifier
         error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, IPV4_UNSPECIFIED_ADDR);
         //Any error to report?
         if(error)
            return error;

         //udpLocalPort is used as 2nd instance identifier
         error = mibEncodePort(nextOid, *nextOidLen, &n, entry->port);
         //Any error to report?
         if(error)
            return error;

         //Check whether the resulting object identifier lexicographically
         //follows the specified OID
         if(oidComp(nextOid, n, oid, oidLen) > 0)
         {
            //Perform lexicographic comparison
            if(localPort == 0)
            {
               acceptable = TRUE;
            }
            else if(ntohl(IPV4_UNSPECIFIED_ADDR) < ntohl(localIpAddr))
            {
               acceptable = TRUE;
            }
            else if(ntohl(IPV4_UNSPECIFIED_ADDR) > ntohl(localIpAddr))
            {
               acceptable = FALSE;
            }
            else if(entry->port < localPort)
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
               localIpAddr = IPV4_UNSPECIFIED_ADDR;
               localPort = entry->port;
            }
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(localPort == 0)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //udpLocalAddress is used as 1st instance identifier
   error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, localIpAddr);
   //Any error to report?
   if(error)
      return error;

   //udpLocalPort is used as 2nd instance identifier
   error = mibEncodePort(nextOid, *nextOidLen, &n, localPort);
   //Any error to report?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}

#endif

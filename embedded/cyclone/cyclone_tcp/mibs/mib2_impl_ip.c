/**
 * @file mib2_impl_ip.c
 * @brief MIB-II module implementation (IP group)
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
#include "mibs/mib2_impl_ip.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (MIB2_SUPPORT == ENABLED && MIB2_IP_GROUP_SUPPORT == ENABLED)


/**
 * @brief Get ipAddrEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t mib2GetIpAddrEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t i;
   uint_t index;
   Ipv4Addr ipAddr;
   Ipv4AddrEntry *entry;
   NetInterface *interface;

   //Point to the instance identifier
   n = object->oidLen;

   //ipAdEntAddr is used as instance identifier
   error = mibDecodeIpv4Addr(oid, oidLen, &n, &ipAddr);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Loop through network interfaces
   for(index = 1; index <= NET_INTERFACE_COUNT; index++)
   {
      //Point to the current interface
      interface = &netInterface[index - 1];

      //Loop through the list of IPv4 addresses assigned to the interface
      for(i = 0; i < IPV4_ADDR_LIST_SIZE; i++)
      {
         //Point to the current entry
         entry = &interface->ipv4Context.addrList[i];

         //Compare the current address against the IP address used as
         //instance identifier
         if(entry->state == IPV4_ADDR_STATE_VALID &&
            entry->addr == ipAddr)
         {
            break;
         }
      }

      //IPv4 address found?
      if(i < IPV4_ADDR_LIST_SIZE)
         break;
   }

   //IP address not assigned to any interface?
   if(index > NET_INTERFACE_COUNT)
      return ERROR_INSTANCE_NOT_FOUND;

   //ipAdEntAddr object?
   if(!osStrcmp(object->name, "ipAdEntAddr"))
   {
      //Get object value
      ipv4CopyAddr(value->ipAddr, &entry->addr);
   }
   //ipAdEntIfIndex object?
   else if(!osStrcmp(object->name, "ipAdEntIfIndex"))
   {
      //Get object value
      value->integer = index;
   }
   //ipAdEntNetMask object?
   else if(!osStrcmp(object->name, "ipAdEntNetMask"))
   {
      //Get object value
      ipv4CopyAddr(value->ipAddr, &entry->subnetMask);
   }
   //ipAdEntBcastAddr object?
   else if(!osStrcmp(object->name, "ipAdEntBcastAddr"))
   {
      //Get object value
      value->integer = 1;
   }
   //ipAdEntReasmMaxSize object?
   else if(!osStrcmp(object->name, "ipAdEntReasmMaxSize"))
   {
      //Get object value
      value->integer = IPV4_MAX_FRAG_DATAGRAM_SIZE;
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
 * @brief Get next ipAddrEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t mib2GetNextIpAddrEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   uint_t index;
   bool_t acceptable;
   Ipv4Addr ipAddr;
   Ipv4AddrEntry *entry;
   NetInterface *interface;

   //Initialize IP address
   ipAddr = IPV4_UNSPECIFIED_ADDR;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through network interfaces
   for(index = 1; index <= NET_INTERFACE_COUNT; index++)
   {
      //Point to the current interface
      interface = &netInterface[index - 1];

      //Loop through the list of IPv4 addresses assigned to the interface
      for(i = 0; i < IPV4_ADDR_LIST_SIZE; i++)
      {
         //Point to the current entry
         entry = &interface->ipv4Context.addrList[i];

         //Valid IPv4 address?
         if(entry->state == IPV4_ADDR_STATE_VALID)
         {
            //Append the instance identifier to the OID prefix
            n = object->oidLen;

            //ipAdEntAddr is used as instance identifier
            error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, entry->addr);
            //Any error to report?
            if(error)
               return error;

            //Check whether the resulting object identifier lexicographically
            //follows the specified OID
            if(oidComp(nextOid, n, oid, oidLen) > 0)
            {
               //Perform lexicographic comparison
               if(ipAddr == IPV4_UNSPECIFIED_ADDR)
               {
                  acceptable = TRUE;
               }
               else if(ntohl(entry->addr) < ntohl(ipAddr))
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
                  ipAddr = entry->addr;
            }
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(ipAddr == IPV4_UNSPECIFIED_ADDR)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //ipAdEntAddr is used as instance identifier
   error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, ipAddr);
   //Any error to report?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}


/**
 * @brief Set ipNetToMediaEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t mib2SetIpNetToMediaEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
   //Not implemented
   return ERROR_WRITE_FAILED;
}


/**
 * @brief Get ipNetToMediaEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t mib2GetIpNetToMediaEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
#if (ETH_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint_t index;
   Ipv4Addr ipAddr;
   NetInterface *interface;
   ArpCacheEntry *entry;

   //Point to the instance identifier
   n = object->oidLen;

   //ipNetToMediaIfIndex is used as 1st instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &index);
   //Invalid instance identifier?
   if(error)
      return error;

   //ipNetToMediaNetAddress is used as 2nd instance identifier
   error = mibDecodeIpv4Addr(oid, oidLen, &n, &ipAddr);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Check index range
   if(index < 1 || index > NET_INTERFACE_COUNT)
      return ERROR_INSTANCE_NOT_FOUND;

   //Point to the network interface
   interface = &netInterface[index - 1];

   //Search the ARP cache for the specified IP address
   entry = arpFindEntry(interface, ipAddr);

   //No matching entry found?
   if(entry == NULL)
      return ERROR_INSTANCE_NOT_FOUND;

   //ipNetToMediaIfIndex object?
   if(!osStrcmp(object->name, "ipNetToMediaIfIndex"))
   {
      //Get object value
      value->integer = index;
   }
   //ipNetToMediaPhysAddress object?
   else if(!osStrcmp(object->name, "ipNetToMediaPhysAddress"))
   {
      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= MIB2_PHYS_ADDRESS_SIZE)
      {
         //Copy object value
         macCopyAddr(value->octetString, &entry->macAddr);
         //Return object length
         *valueLen = MIB2_PHYS_ADDRESS_SIZE;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   //ipNetToMediaNetAddress object?
   else if(!osStrcmp(object->name, "ipNetToMediaNetAddress"))
   {
      //Get object value
      ipv4CopyAddr(value->ipAddr, &entry->ipAddr);
   }
   //ipNetToMediaType object?
   else if(!osStrcmp(object->name, "ipNetToMediaType"))
   {
      //Get object value
      value->integer = MIB2_IP_NET_TO_MEDIA_TYPE_DYNAMIC;
   }
   //Unknown object?
   else
   {
      //The specified object does not exist
      error = ERROR_OBJECT_NOT_FOUND;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_OBJECT_NOT_FOUND;
#endif
}


/**
 * @brief Get next ipNetToMediaEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t mib2GetNextIpNetToMediaEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
#if (ETH_SUPPORT == ENABLED)
   error_t error;
   uint_t i;
   uint_t j;
   size_t n;
   uint_t index;
   bool_t acceptable;
   Ipv4Addr ipAddr;
   NetInterface *interface;
   ArpCacheEntry *entry;

   //Initialize variables
   index = 0;
   ipAddr = IPV4_UNSPECIFIED_ADDR;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through network interfaces
   for(i = 1; i <= NET_INTERFACE_COUNT; i++)
   {
      //Point to the current interface
      interface = &netInterface[i - 1];

      //Loop through ARP cache entries
      for(j = 0; j < ARP_CACHE_SIZE; j++)
      {
         //Point to the current entry
         entry = &interface->arpCache[j];

         //Valid entry?
         if(entry->state != ARP_STATE_NONE)
         {
            //Append the instance identifier to the OID prefix
            n = object->oidLen;

            //ipNetToMediaIfIndex is used as 1st instance identifier
            error = mibEncodeIndex(nextOid, *nextOidLen, &n, i);
            //Any error to report?
            if(error)
               return error;

            //ipNetToMediaNetAddress is used as 2nd instance identifier
            error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, entry->ipAddr);
            //Any error to report?
            if(error)
               return error;

            //Check whether the resulting object identifier lexicographically
            //follows the specified OID
            if(oidComp(nextOid, n, oid, oidLen) > 0)
            {
               //Perform lexicographic comparison
               if(index == 0)
               {
                  acceptable = TRUE;
               }
               else if(i < index)
               {
                  acceptable = TRUE;
               }
               else if(i > index)
               {
                  acceptable = FALSE;
               }
               else if(ntohl(entry->ipAddr) < ntohl(ipAddr))
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
                  index = i;
                  ipAddr = entry->ipAddr;
               }
            }
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(index == 0)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //ipNetToMediaIfIndex is used as 1st instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, index);
   //Any error to report?
   if(error)
      return error;

   //ipNetToMediaNetAddress is used as 2nd instance identifier
   error = mibEncodeIpv4Addr(nextOid, *nextOidLen, &n, ipAddr);
   //Any error to report?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_OBJECT_NOT_FOUND;
#endif
}

#endif

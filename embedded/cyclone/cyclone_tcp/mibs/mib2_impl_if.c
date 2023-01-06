/**
 * @file mib2_impl_if.c
 * @brief MIB-II module implementation (Interface group)
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
#include "mibs/mib2_impl_if.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (MIB2_SUPPORT == ENABLED && MIB2_IF_GROUP_SUPPORT == ENABLED)


/**
 * @brief Set ifEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t mib2SetIfEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
   //Not implemented
   return ERROR_WRITE_FAILED;
}


/**
 * @brief Get ifEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t mib2GetIfEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t index;
   Mib2IfEntry *entry;
   NetInterface *interface;
   NetInterface *physicalInterface;

   //Point to the instance identifier
   n = object->oidLen;

   //ifIndex is used as instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &index);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Check index range
   if(index < 1 || index > NET_INTERFACE_COUNT)
      return ERROR_INSTANCE_NOT_FOUND;

   //Point to the underlying interface
   interface = &netInterface[index - 1];
   //Point to the interface table entry
   entry = &mib2Base.ifGroup.ifTable[index - 1];

   //Point to the physical interface
   physicalInterface = nicGetPhysicalInterface(interface);

   //ifIndex object?
   if(!osStrcmp(object->name, "ifIndex"))
   {
      //Get object value
      value->integer = index;
   }
   //ifDescr object?
   else if(!osStrcmp(object->name, "ifDescr"))
   {
      //Retrieve the length of the interface name
      n = osStrlen(interface->name);

      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= n)
      {
         //Copy object value
         osMemcpy(value->octetString, interface->name, n);
         //Return object length
         *valueLen = n;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   //ifType object?
   else if(!osStrcmp(object->name, "ifType"))
   {
#if (ETH_VLAN_SUPPORT == ENABLED)
      //VLAN interface?
      if(interface->vlanId != 0)
      {
         //Layer 2 virtual LAN using 802.1Q
         value->integer = MIB2_IF_TYPE_L2_VLAN;
      }
      else
#endif
      {
         //Sanity check
         if(physicalInterface->nicDriver != NULL)
         {
            //Get interface type
            switch(physicalInterface->nicDriver->type)
            {
            //Ethernet interface
            case NIC_TYPE_ETHERNET:
               value->integer = MIB2_IF_TYPE_ETHERNET_CSMACD;
               break;
            //PPP interface
            case NIC_TYPE_PPP:
               value->integer = MIB2_IF_TYPE_PPP;
               break;
            //IEEE 802.15.4 WPAN interface
            case NIC_TYPE_6LOWPAN:
               value->integer = MIB2_IF_TYPE_IEEE_802_15_4;
               break;
            //Unknown interface type
            default:
               value->integer = MIB2_IF_TYPE_OTHER;
               break;
            }
         }
         else
         {
            //Unknown interface type
            value->integer = MIB2_IF_TYPE_OTHER;
         }
      }
   }
   //ifMtu object?
   else if(!osStrcmp(object->name, "ifMtu"))
   {
      //Get interface MTU
      if(physicalInterface->nicDriver != NULL)
      {
         value->integer = physicalInterface->nicDriver->mtu;
      }
      else
      {
         value->integer = 0;
      }
   }
   //ifSpeed object?
   else if(!osStrcmp(object->name, "ifSpeed"))
   {
      //Get interface's current bandwidth
      value->gauge32 = interface->linkSpeed;
   }
#if (ETH_SUPPORT == ENABLED)
   //ifPhysAddress object?
   else if(!osStrcmp(object->name, "ifPhysAddress"))
   {
      NetInterface *logicalInterface;

      //Point to the logical interface
      logicalInterface = nicGetLogicalInterface(interface);

      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= MIB2_PHYS_ADDRESS_SIZE)
      {
         //Copy object value
         macCopyAddr(value->octetString, &logicalInterface->macAddr);
         //Return object length
         *valueLen = MIB2_PHYS_ADDRESS_SIZE;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
#endif
   //ifAdminStatus object?
   else if(!osStrcmp(object->name, "ifAdminStatus"))
   {
      //Check whether the interface is enabled for operation
      if(physicalInterface->nicDriver != NULL)
      {
         value->integer = MIB2_IF_ADMIN_STATUS_UP;
      }
      else
      {
         value->integer = MIB2_IF_ADMIN_STATUS_DOWN;
      }
   }
   //ifOperStatus object?
   else if(!osStrcmp(object->name, "ifOperStatus"))
   {
      //Get the current operational state of the interface
      if(interface->linkState)
      {
         value->integer = MIB2_IF_OPER_STATUS_UP;
      }
      else
      {
         value->integer = MIB2_IF_OPER_STATUS_DOWN;
      }
   }
   //ifLastChange object?
   else if(!osStrcmp(object->name, "ifLastChange"))
   {
      //Get object value
      value->timeTicks = entry->ifLastChange;
   }
   //ifInOctets object?
   else if(!osStrcmp(object->name, "ifInOctets"))
   {
      //Get object value
      value->counter32 = entry->ifInOctets;
   }
   //ifInUcastPkts object?
   else if(!osStrcmp(object->name, "ifInUcastPkts"))
   {
      //Get object value
      value->counter32 = entry->ifInUcastPkts;
   }
   //ifInNUcastPkts object?
   else if(!osStrcmp(object->name, "ifInNUcastPkts"))
   {
      //Get object value
      value->counter32 = entry->ifInNUcastPkts;
   }
   //ifInDiscards object?
   else if(!osStrcmp(object->name, "ifInDiscards"))
   {
      //Get object value
      value->counter32 = entry->ifInDiscards;
   }
   //ifInErrors object?
   else if(!osStrcmp(object->name, "ifInErrors"))
   {
      //Get object value
      value->counter32 = entry->ifInErrors;
   }
   //ifInUnknownProtos object?
   else if(!osStrcmp(object->name, "ifInUnknownProtos"))
   {
      //Get object value
      value->counter32 = entry->ifInUnknownProtos;
   }
   //ifOutOctets object?
   else if(!osStrcmp(object->name, "ifOutOctets"))
   {
      //Get object value
      value->counter32 = entry->ifOutOctets;
   }
   //ifOutUcastPkts object?
   else if(!osStrcmp(object->name, "ifOutUcastPkts"))
   {
      //Get object value
      value->counter32 = entry->ifOutUcastPkts;
   }
   //ifOutNUcastPkts object?
   else if(!osStrcmp(object->name, "ifOutNUcastPkts"))
   {
      //Get object value
      value->counter32 = entry->ifOutNUcastPkts;
   }
   //ifOutDiscards object?
   else if(!osStrcmp(object->name, "ifOutDiscards"))
   {
      //Get object value
      value->counter32 = entry->ifOutDiscards;
   }
   //ifOutErrors object?
   else if(!osStrcmp(object->name, "ifOutErrors"))
   {
      //Get object value
      value->counter32 = entry->ifOutErrors;
   }
   //ifOutQLen object?
   else if(!osStrcmp(object->name, "ifOutQLen"))
   {
      //Get object value
      value->gauge32 = entry->ifOutQLen;
   }
   //ifSpecific object?
   else if(!osStrcmp(object->name, "ifSpecific"))
   {
      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= entry->ifSpecificLen)
      {
         //Copy object value
         osMemcpy(value->oid, entry->ifSpecific, entry->ifSpecificLen);
         //Return object length
         *valueLen = entry->ifSpecificLen;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
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
 * @brief Get next ifEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t mib2GetNextIfEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   size_t n;
   uint_t index;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through network interfaces
   for(index = 1; index <= NET_INTERFACE_COUNT; index++)
   {
      //Append the instance identifier to the OID prefix
      n = object->oidLen;

      //ifIndex is used as instance identifier
      error = mibEncodeIndex(nextOid, *nextOidLen, &n, index);
      //Any error to report?
      if(error)
         return error;

      //Check whether the resulting object identifier lexicographically
      //follows the specified OID
      if(oidComp(nextOid, n, oid, oidLen) > 0)
      {
         //Save the length of the resulting object identifier
         *nextOidLen = n;
         //Next object found
         return NO_ERROR;
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object
   return ERROR_OBJECT_NOT_FOUND;
}

#endif

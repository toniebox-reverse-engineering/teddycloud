/**
 * @file bridge_mib_impl.c
 * @brief Bridge MIB module implementation (dot1dStatic subtree)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSTP Open.
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
#include "bridge_mib_module.h"
#include "bridge_mib_impl.h"
#include "bridge_mib_impl_static.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (BRIDGE_MIB_SUPPORT == ENABLED)


/**
 * @brief Set dot1dStaticEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dStaticEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (BRIDGE_MIB_SET_SUPPORT == ENABLED)
   error_t error;
   uint_t i;
   size_t n;
   bool_t found;
   SwitchFdbEntry entry;
   MacAddr dot1dStaticAddress;
   uint16_t dot1dStaticReceivePort;
   NetInterface *interface;

   //Make sure the network interface is valid
   if(bridgeMibBase.interface == NULL)
      return ERROR_WRITE_FAILED;

   //Point to the underlying interface
   interface = bridgeMibBase.interface;

   //Point to the instance identifier
   n = object->oidLen;

   //dot1dStaticAddress is used as 1st instance identifier
   error = mibDecodeMacAddr(oid, oidLen, &n, &dot1dStaticAddress);
   //Invalid instance identifier?
   if(error)
      return error;

   //dot1dStaticReceivePort is used as 2nd instance identifier
   error = mibDecodePort(oid, oidLen, &n, &dot1dStaticReceivePort);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the static MAC table for a matching row
   for(found = FALSE, i = 0; !error; i++)
   {
      //Get the next entry
      error = interface->switchDriver->getStaticFdbEntry(interface, i, &entry);

      //Check status code
      if(error == NO_ERROR)
      {
         //Check whether the current entry matches the specified address and
         //port number
         if(macCompAddr(&entry.macAddr, &dot1dStaticAddress) &&
            entry.srcPort == dot1dStaticReceivePort)
         {
            found = TRUE;
            break;
         }
      }
      else if(error == ERROR_INVALID_ENTRY)
      {
         //Skip current entry
         error = NO_ERROR;
      }
      else
      {
         //Exit immediately
      }
   }

   //Initialize status code
   error = NO_ERROR;

   //Prepare phase?
   if(!commit)
   {
      //Reset the cached entry if necessary
      if(!macCompAddr(&bridgeMibBase.dot1dStaticAddress, &dot1dStaticAddress) ||
         bridgeMibBase.dot1dStaticReceivePort != dot1dStaticReceivePort)
      {
         bridgeMibBase.dot1dStaticAddress = dot1dStaticAddress;
         bridgeMibBase.dot1dStaticReceivePort = dot1dStaticReceivePort;
         bridgeMibBase.dot1dStaticAllowedToGoTo = 0;
      }
   }

   //dot1dStaticAddress object?
   if(!strcmp(object->name, "dot1dStaticAddress"))
   {
      //Ensure the length of the MAC address is valid
      if(valueLen != sizeof(MacAddr))
         return ERROR_WRONG_LENGTH;

      //This object indicates the destination MAC address in a frame to which
      //this entry's filtering information applies
      if(!macCompAddr(value->octetString, &dot1dStaticAddress))
         return ERROR_INCONSISTENT_VALUE;
   }
   //dot1dStaticReceivePort object?
   else if(!strcmp(object->name, "dot1dStaticReceivePort"))
   {
      //This object indicates the port number of the port from which a frame
      //must be received in order for this entry's filtering information to
      //apply. A value of zero indicates that this entry applies on all ports
      //of the bridge for which there is no other applicable entry
      if(value->integer != dot1dStaticReceivePort)
         return ERROR_INCONSISTENT_VALUE;
   }
   //dot1dStaticAllowedToGoTo object?
   else if(!strcmp(object->name, "dot1dStaticAllowedToGoTo"))
   {
      //Initialize the value of the dot1dStaticAllowedToGoTo object
      bridgeMibBase.dot1dStaticAllowedToGoTo = 0;

      //This object specifies the set of ports to which frames received from a
      //specific port and destined for a specific MAC address, are allowed to
      //be forwarded
      for(i = 0; i < 32 && i < (8 * valueLen); i++)
      {
         //Each port of the bridge is represented by a single bit within the
         //value of this object
         if((value->octetString[i / 8] & (1 << (7 - (i % 8)))) != 0)
         {
            bridgeMibBase.dot1dStaticAllowedToGoTo |= 1 << i;
         }
      }

      //Test if the matching row exists in the agent
      if(found && commit)
      {
         //Modify the forwarding database entry
         entry.destPorts = bridgeMibBase.dot1dStaticAllowedToGoTo;

         //Update the static MAC table
         error = interface->switchDriver->addStaticFdbEntry(interface, &entry);

         //Check status code
         if(error)
         {
            //Failed to modify the static MAC entry
            error = ERROR_WRITE_FAILED;
         }
      }
   }
   //dot1dStaticStatus object?
   else if(!strcmp(object->name, "dot1dStaticStatus"))
   {
      //This object indicates the status of this entry
      if(value->integer == BRIDGE_MIB_STATIC_STATUS_OTHER)
      {
         //Do not create any entry
      }
      else if(value->integer == BRIDGE_MIB_STATIC_STATUS_INVALID)
      {
         //Test if a matching row exists in the agent
         if(found && commit)
         {
            //Remove the entry from the static MAC table
            interface->switchDriver->deleteStaticFdbEntry(interface, &entry);
         }
      }
      else if(value->integer == BRIDGE_MIB_STATIC_STATUS_PERMANENT ||
         value->integer == BRIDGE_MIB_STATIC_STATUS_DELETE_ON_RESET ||
         value->integer == BRIDGE_MIB_STATIC_STATUS_DELETE_ON_TIMEOUT)
      {
         //No matching row found?
         if(!found && commit)
         {
            //Format forwarding database entry
            entry.macAddr = bridgeMibBase.dot1dStaticAddress;
            entry.srcPort = (uint8_t) bridgeMibBase.dot1dStaticReceivePort;
            entry.destPorts = bridgeMibBase.dot1dStaticAllowedToGoTo;
            entry.override = FALSE;

            //Add a new entry to the static MAC table
            error = interface->switchDriver->addStaticFdbEntry(interface, &entry);

            //Check status code
            if(error)
            {
               //Failed to create a new MAC entry
               error = ERROR_WRITE_FAILED;
            }
         }
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
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
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get dot1dStaticEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStaticEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t i;
   size_t n;
   SwitchFdbEntry entry;
   MacAddr dot1dStaticAddress;
   uint16_t dot1dStaticReceivePort;
   NetInterface *interface;

   //Make sure the network interface is valid
   if(bridgeMibBase.interface == NULL)
      return ERROR_READ_FAILED;

   //Point to the underlying interface
   interface = bridgeMibBase.interface;

   //Point to the instance identifier
   n = object->oidLen;

   //dot1dStaticAddress is used as 1st instance identifier
   error = mibDecodeMacAddr(oid, oidLen, &n, &dot1dStaticAddress);
   //Invalid instance identifier?
   if(error)
      return error;

   //dot1dStaticReceivePort is used as 2nd instance identifier
   error = mibDecodePort(oid, oidLen, &n, &dot1dStaticReceivePort);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the static MAC table for a matching row
   for(i = 0; !error; i++)
   {
      //Get the next entry
      error = interface->switchDriver->getStaticFdbEntry(interface, i, &entry);

      //Check status code
      if(error == NO_ERROR)
      {
         //Check whether the current entry matches the specified address and
         //port number
         if(macCompAddr(&entry.macAddr, &dot1dStaticAddress) &&
            entry.srcPort == dot1dStaticReceivePort)
         {
            break;
         }
      }
      else if(error == ERROR_INVALID_ENTRY)
      {
         //Skip current entry
         error = NO_ERROR;
      }
      else
      {
         //Exit immediately
      }
   }

   //No matching entry?
   if(error)
      return ERROR_INSTANCE_NOT_FOUND;

   //dot1dStaticAddress object?
   if(!strcmp(object->name, "dot1dStaticAddress"))
   {
      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= sizeof(MacAddr))
      {
         //This object indicates the destination MAC address in a frame to
         //which this entry's filtering information applies
         macCopyAddr(value->octetString, &entry.macAddr);

         //A MAC address shall be encoded as six octets
         *valueLen = sizeof(MacAddr);
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   //dot1dStaticReceivePort object?
   else if(!strcmp(object->name, "dot1dStaticReceivePort"))
   {
      //This object indicates the port number of the port from which a frame
      //must be received in order for this entry's filtering information to
      //apply. A value of zero indicates that this entry applies on all ports
      //of the bridge for which there is no other applicable entry
      value->integer = entry.srcPort;
   }
   //dot1dStaticAllowedToGoTo object?
   else if(!strcmp(object->name, "dot1dStaticAllowedToGoTo"))
   {
      uint8_t buffer[4];

      //Initialize buffer
      osMemset(buffer, 0, sizeof(buffer));

      //This object specifies the set of ports to which frames received from a
      //specific port and destined for a specific MAC address, are allowed to
      //be forwarded
      for(i = 0; i < 32 && entry.destPorts != 0; i++)
      {
         //Each port of the bridge is represented by a single bit within the
         //value of this object
         if((entry.destPorts & (1 << i)) != 0)
         {
            buffer[i / 8] |= 1 << (7 - (i % 8));
            entry.destPorts &= ~(1 << i);
         }
      }

      //Each octet within the value of this object specifies a set of eight
      //ports
      n = (i + 7) / 8;

      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= n)
      {
         //Copy object value
         osMemcpy(value->octetString, buffer, n);
         //Return object length
         *valueLen = n;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   //dot1dStaticStatus object?
   else if(!strcmp(object->name, "dot1dStaticStatus"))
   {
      //This object indicates the status of this entry
      value->integer = BRIDGE_MIB_STATIC_STATUS_PERMANENT;
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
 * @brief Get next dot1dStaticEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t bridgeMibGetNextDot1dStaticEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   bool_t acceptable;
   uint16_t srcPort;
   MacAddr macAddr;
   SwitchFdbEntry entry;
   NetInterface *interface;

   //Initialize variable
   macAddr = MAC_UNSPECIFIED_ADDR;
   srcPort = 0;

   //Make sure the network interface is valid
   if(bridgeMibBase.interface == NULL)
      return ERROR_OBJECT_NOT_FOUND;

   //Point to the underlying interface
   interface = bridgeMibBase.interface;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Initialize status code
   error = NO_ERROR;

   //Loop through the static MAC table
   for(i = 0; !error; i++)
   {
      //Get the next entry
      error = interface->switchDriver->getStaticFdbEntry(interface, i, &entry);

      //Check status code
      if(error == NO_ERROR)
      {
         //Append the instance identifier to the OID prefix
         n = object->oidLen;

         //dot1dStaticAddress is used as 1st instance identifier
         error = mibEncodeMacAddr(nextOid, *nextOidLen, &n, &entry.macAddr);
         //Invalid instance identifier?
         if(error)
            return error;

         //dot1dStaticReceivePort is used as 2nd instance identifier
         error = mibEncodePort(nextOid, *nextOidLen, &n, entry.srcPort);
         //Invalid instance identifier?
         if(error)
            return error;

         //Check whether the resulting object identifier lexicographically
         //follows the specified OID
         if(oidComp(nextOid, n, oid, oidLen) > 0)
         {
            //Perform lexicographic comparison
            if(mibCompMacAddr(&macAddr, &MAC_UNSPECIFIED_ADDR) == 0)
            {
               acceptable = TRUE;
            }
            else if(mibCompMacAddr(&entry.macAddr, &macAddr) < 0)
            {
               acceptable = TRUE;
            }
            else if(mibCompMacAddr(&entry.macAddr, &macAddr) > 0)
            {
               acceptable = FALSE;
            }
            else if(entry.srcPort < srcPort)
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
               macAddr = entry.macAddr;
               srcPort = entry.srcPort;
            }
         }
      }
      else if(error == ERROR_INVALID_ENTRY)
      {
         //Skip current entry
         error = NO_ERROR;
      }
      else
      {
         //Exit immediately
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(mibCompMacAddr(&macAddr, &MAC_UNSPECIFIED_ADDR) == 0)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //dot1dStaticAddress is used as 1st instance identifier
   error = mibEncodeMacAddr(nextOid, *nextOidLen, &n, &macAddr);
   //Invalid instance identifier?
   if(error)
      return error;

   //dot1dStaticReceivePort is used as 2nd instance identifier
   error = mibEncodePort(nextOid, *nextOidLen, &n, srcPort);
   //Invalid instance identifier?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}

#endif

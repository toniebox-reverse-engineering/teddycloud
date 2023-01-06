/**
 * @file bridge_mib_impl.c
 * @brief Bridge MIB module implementation (dot1dTp subtree)
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
#include "mibs/bridge_mib_module.h"
#include "mibs/bridge_mib_impl.h"
#include "mibs/bridge_mib_impl_tp.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "stp/stp.h"
#include "stp/stp_mgmt.h"
#include "rstp/rstp.h"
#include "rstp/rstp_mgmt.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (BRIDGE_MIB_SUPPORT == ENABLED)


/**
 * @brief Get dot1dTpLearnedEntryDiscards object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dTpLearnedEntryDiscards(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   //The total number of forwarding database entries that have been or would
   //have been learned, but have been discarded due to a lack of storage space
   //in the forwarding database
   value->counter32 = 0;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set dot1dTpAgingTime object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dTpAgingTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (BRIDGE_MIB_SET_SUPPORT == ENABLED)
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 0)
   {
#if (STP_SUPPORT == ENABLED)
      //Valid STP bridge context?
      if(bridgeMibBase.stpBridgeContext != NULL)
      {
         //This object specifies the timeout period in seconds for aging out
         //dynamically-learned forwarding information
         error = stpMgmtSetAgeingTime(bridgeMibBase.stpBridgeContext,
            value->integer, commit);
      }
      else
#endif
#if (RSTP_SUPPORT == ENABLED)
      //Valid RSTP bridge context?
      if(bridgeMibBase.rstpBridgeContext != NULL)
      {
         //This object specifies the timeout period in seconds for aging out
         //dynamically-learned forwarding information
         error = rstpMgmtSetAgeingTime(bridgeMibBase.rstpBridgeContext,
            value->integer, commit);
      }
      else
#endif
      //Invalid bridge context?
      {
         //Report an error
         error = ERROR_WRITE_FAILED;
      }
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_VALUE;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get dot1dTpAgingTime object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dTpAgingTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t ageingTime;

   //Initialize object value
   ageingTime = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the timeout period in seconds for aging out
      //dynamically-learned forwarding information
      error = stpMgmtGetAgeingTime(bridgeMibBase.stpBridgeContext,
         &ageingTime);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the timeout period in seconds for aging out
      //dynamically-learned forwarding information
      error = rstpMgmtGetAgeingTime(bridgeMibBase.rstpBridgeContext,
         &ageingTime);
   }
   else
#endif
   //Invalid bridge context?
   {
      //Report an error
      error = ERROR_READ_FAILED;
   }

   //Check status code
   if(!error)
   {
      //Return the value of the object
      value->integer = ageingTime;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dTpFdbEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dTpFdbEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t i;
   size_t n;
   SwitchFdbEntry entry;
   MacAddr dot1dTpFdbAddress;
   NetInterface *interface;

   //Make sure the network interface is valid
   if(bridgeMibBase.interface == NULL)
      return ERROR_READ_FAILED;

   //Point to the underlying interface
   interface = bridgeMibBase.interface;

   //Point to the instance identifier
   n = object->oidLen;

   //dot1dTpFdbAddress is used as instance identifier
   error = mibDecodeMacAddr(oid, oidLen, &n, &dot1dTpFdbAddress);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the dynamic MAC table for the specified address
   for(i = 0; !error; i++)
   {
      //Get the next entry
      error = interface->switchDriver->getDynamicFdbEntry(interface, i, &entry);

      //Check status code
      if(error == NO_ERROR)
      {
         //Check whether the current entry matches the specified address
         if(macCompAddr(&entry.macAddr, &dot1dTpFdbAddress))
            break;
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

   //dot1dTpFdbAddress object?
   if(!strcmp(object->name, "dot1dTpFdbAddress"))
   {
      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= sizeof(MacAddr))
      {
         //This object specifies a unicast MAC address for which the bridge has
         //forwarding and/or filtering information
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
   //dot1dTpFdbPort object?
   else if(!strcmp(object->name, "dot1dTpFdbPort"))
   {
      //This object indicates the port number of the port on which a frame
      //having a source address equal to the value of the corresponding
      //instance of dot1dTpFdbAddress has been seen
      value->integer = entry.srcPort;
   }
   //dot1dTpFdbStatus object?
   else if(!strcmp(object->name, "dot1dTpFdbStatus"))
   {
      //This object indicates the status of this entry
      value->integer = BRIDGE_MIB_FDB_STATUS_LEARNED;
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
 * @brief Get next dot1dTpFdbEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t bridgeMibGetNextDot1dTpFdbEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   MacAddr macAddr;
   SwitchFdbEntry entry;
   NetInterface *interface;

   //Initialize variable
   macAddr = MAC_UNSPECIFIED_ADDR;

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

   //Loop through the dynamic MAC table
   for(i = 0; !error; i++)
   {
      //Get the next entry
      error = interface->switchDriver->getDynamicFdbEntry(interface, i, &entry);

      //Check status code
      if(error == NO_ERROR)
      {
         //Append the instance identifier to the OID prefix
         n = object->oidLen;

         //dot1dTpFdbAddress is used as instance identifier
         error = mibEncodeMacAddr(nextOid, *nextOidLen, &n, &entry.macAddr);
         //Any error to report?
         if(error)
            return error;

         //Check whether the resulting object identifier lexicographically
         //follows the specified OID
         if(oidComp(nextOid, n, oid, oidLen) > 0)
         {
            //Save the closest object identifier that follows the specified
            //OID in lexicographic order
            if(mibCompMacAddr(&macAddr, &MAC_UNSPECIFIED_ADDR) == 0 ||
               mibCompMacAddr(&entry.macAddr, &macAddr) < 0)
            {
               macAddr = entry.macAddr;
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

   //dot1dTpFdbAddress is used as instance identifier
   error = mibEncodeMacAddr(nextOid, *nextOidLen, &n, &macAddr);
   //Any error to report?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}


/**
 * @brief Get dot1dTpPortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dTpPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint16_t dot1dTpPort;

   //Point to the instance identifier
   n = object->oidLen;

   //dot1dTpPort is used as instance identifier
   error = mibDecodePort(oid, oidLen, &n, &dot1dTpPort);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Invalid port number?
   if(bridgeMibGetPortIndex(dot1dTpPort) == 0)
      return ERROR_INSTANCE_NOT_FOUND;

   //dot1dTpPort object?
   if(!strcmp(object->name, "dot1dTpPort"))
   {
      //This object indicates the port number of the port for which this entry
      //contains transparent bridging management information
      value->integer = dot1dTpPort;
   }
   //dot1dTpPortMaxInfo object?
   else if(!strcmp(object->name, "dot1dTpPortMaxInfo"))
   {
      //The maximum size of the INFO (non-MAC) field that this port will
      //receive or transmit
      value->integer = ETH_MTU;
   }
   //dot1dTpPortInFrames object?
   else if(!strcmp(object->name, "dot1dTpPortInFrames"))
   {
      //The number of frames that have been received by this port from its
      //segment
      value->counter32 = 0;
   }
   //dot1dTpPortOutFrames object?
   else if(!strcmp(object->name, "dot1dTpPortOutFrames"))
   {
      //The number of frames that have been transmitted by this port to its
      //segment
      value->counter32 = 0;
   }
   //dot1dTpPortInDiscards object?
   else if(!strcmp(object->name, "dot1dTpPortInDiscards"))
   {
      //Count of received valid frames that were discarded by forwarding
      //process
      value->counter32 = 0;
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
 * @brief Get next dot1dTpPortEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t bridgeMibGetNextDot1dTpPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   uint_t numPorts;
   uint16_t portNum;
   uint16_t curPortNum;

   //Initialize variable
   portNum = 0;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Retrieve the number of ports
   numPorts = bridgeMibGetNumPorts();

   //Loop through the ports of the bridge
   for(i = 1; i <= numPorts; i++)
   {
      //Retrieve the port number associated with the current port
      curPortNum = bridgeMibGetPortNum(i);

      //Append the instance identifier to the OID prefix
      n = object->oidLen;

      //dot1dTpPort is used as instance identifier
      error = mibEncodeIndex(nextOid, *nextOidLen, &n, curPortNum);
      //Any error to report?
      if(error)
         return error;

      //Check whether the resulting object identifier lexicographically
      //follows the specified OID
      if(oidComp(nextOid, n, oid, oidLen) > 0)
      {
         //Save the closest object identifier that follows the specified
         //OID in lexicographic order
         if(portNum == 0 || curPortNum < portNum)
         {
            portNum = curPortNum;
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(portNum == 0)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //dot1dTpPort is used as instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, portNum);
   //Any error to report?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}

#endif

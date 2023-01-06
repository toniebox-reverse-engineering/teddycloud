/**
 * @file bridge_mib_impl.c
 * @brief Bridge MIB module implementation (dot1dBase subtree)
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
#include "mibs/bridge_mib_impl_base.h"
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
 * @brief Get dot1dBaseBridgeAddress object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dBaseBridgeAddress(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   MacAddr bridgeAddr;

   //Make sure the buffer is large enough to hold the entire object
   if(*valueLen < sizeof(MacAddr))
      return ERROR_BUFFER_OVERFLOW;

   //Initialize object value
   bridgeAddr = MAC_UNSPECIFIED_ADDR;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //Retrieve the MAC address assigned to the bridge
      error = stpMgmtGetBridgeAddr(bridgeMibBase.stpBridgeContext,
         &bridgeAddr);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //Retrieve the MAC address assigned to the bridge
      error = rstpMgmtGetBridgeAddr(bridgeMibBase.rstpBridgeContext,
         &bridgeAddr);
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
      //Copy the bridge MAC address
      macCopyAddr(value->octetString, &bridgeAddr);
      //A MAC address shall be encoded as six octets
      *valueLen = sizeof(MacAddr);
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dBaseNumPorts object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dBaseNumPorts(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t numPorts;

   //Initialize object value
   numPorts = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //Get the number of ports controlled by this bridging entity
      error = stpMgmtGetNumPorts(bridgeMibBase.stpBridgeContext, &numPorts);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //Get the number of ports controlled by this bridging entity
      error = rstpMgmtGetNumPorts(bridgeMibBase.rstpBridgeContext, &numPorts);
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
      value->integer = numPorts;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dBaseType object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dBaseType(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   //This object indicates what type of bridging this bridge can perform
   value->integer = bridgeMibBase.dot1dBaseType;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get dot1dBasePortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dBasePortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t portIndex;
   uint16_t dot1dBasePort;

   //Point to the instance identifier
   n = object->oidLen;

   //dot1dBasePort is used as instance identifier
   error = mibDecodePort(oid, oidLen, &n, &dot1dBasePort);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Retrieve the port that matches the specified port number
   portIndex = bridgeMibGetPortIndex(dot1dBasePort);
   //Invalid port number?
   if(portIndex == 0)
      return ERROR_INSTANCE_NOT_FOUND;

   //dot1dBasePort object?
   if(!strcmp(object->name, "dot1dBasePort"))
   {
      //This object specifies the port number of the port for which this entry
      //contains bridge management information
      value->integer = dot1dBasePort;
   }
   //dot1dBasePortIfIndex object?
   else if(!strcmp(object->name, "dot1dBasePortIfIndex"))
   {
      //This object specifies the value of the instance of the ifIndex object,
      //defined in IF-MIB, for the interface corresponding to this port
      value->integer = portIndex;
   }
   //dot1dBasePortCircuit object?
   else if(!strcmp(object->name, "dot1dBasePortCircuit"))
   {
      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= sizeof(uint8_t))
      {
         //This object contains the name of an object instance unique to this
         //port. For a port which has a unique value of dot1dBasePortIfIndex,
         //this object can have the value { 0 0 }
         value->oid[0] = 0;

         //Return object length
         *valueLen = sizeof(uint8_t);
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   //dot1dBasePortDelayExceededDiscards object?
   else if(!strcmp(object->name, "dot1dBasePortDelayExceededDiscards"))
   {
      //The number of frames discarded by this port due to excessive transit
      //delay through the bridge. It is incremented by both transparent and
      //source route bridges
      value->counter32 = 0;
   }
   //dot1dBasePortMtuExceededDiscards object?
   else if(!strcmp(object->name, "dot1dBasePortMtuExceededDiscards"))
   {
      //The number of frames discarded by this port due to an excessive size.
      //It is incremented by both transparent and source route bridges
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
 * @brief Get next dot1dBasePortEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t bridgeMibGetNextDot1dBasePortEntry(const MibObject *object, const uint8_t *oid,
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

      //dot1dBasePort is used as instance identifier
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

   //dot1dBasePort is used as instance identifier
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

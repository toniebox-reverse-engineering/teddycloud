/**
 * @file rstp_mib_impl.c
 * @brief RSTP MIB module implementation
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
#include "mibs/rstp_mib_module.h"
#include "mibs/rstp_mib_impl.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "rstp/rstp.h"
#include "rstp/rstp_mgmt.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_MIB_SUPPORT == ENABLED)


/**
 * @brief RSTP MIB module initialization
 * @return Error code
 **/

error_t rstpMibInit(void)
{
   //Debug message
   TRACE_INFO("Initializing RSTP MIB base...\r\n");

   //Clear RSTP MIB base
   memset(&rstpMibBase, 0, sizeof(rstpMibBase));

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Attach RSTP bridge context
 * @param[in] context Pointer to the RSTP bridge context
 * @return Error code
 **/

error_t rstpMibSetRstpBridgeContext(RstpBridgeContext *context)
{
   //Save the RSTP bridge context
   rstpMibBase.rstpBridgeContext = context;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set dot1dStpVersion object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t rstpMibSetDot1dStpVersion(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (RSTP_MIB_SET_SUPPORT == ENABLED)
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 0)
   {
      //This object specifies the version of Spanning Tree Protocol the bridge
      //is currently running
      error = rstpMgmtSetVersion(rstpMibBase.rstpBridgeContext, value->integer,
         commit);
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
 * @brief Get dot1dStpVersion object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t rstpMibGetDot1dStpVersion(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t version;

   //This object specifies the version of Spanning Tree Protocol the bridge
   //is currently running
   error = rstpMgmtGetVersion(rstpMibBase.rstpBridgeContext, &version);

   //Check status code
   if(!error)
   {
      //Return the value of the object
      value->integer = version;
   }

   //Return status code
   return error;
}


/**
 * @brief Set dot1dStpTxHoldCount object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t rstpMibSetDot1dStpTxHoldCount(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (RSTP_MIB_SET_SUPPORT == ENABLED)
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 0)
   {
      //This object specifies the value used by the Port Transmit state machine
      //to limit the maximum transmission rate
      error = rstpMgmtSetTxHoldCount(rstpMibBase.rstpBridgeContext,
         value->integer, commit);
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
 * @brief Get dot1dStpTxHoldCount object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t rstpMibGetDot1dStpTxHoldCount(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t txHoldCount;

   //This object specifies the value used by the Port Transmit state machine
   //to limit the maximum transmission rate
   error = rstpMgmtGetTxHoldCount(rstpMibBase.rstpBridgeContext, &txHoldCount);

   //Check status code
   if(!error)
   {
      //Return the value of the object
      value->integer = txHoldCount;
   }

   //Return status code
   return error;
}


/**
 * @brief Set dot1dStpExtPortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t rstpMibSetDot1dStpExtPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (RSTP_MIB_SET_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint16_t dot1dStpPort;

   //Point to the instance identifier
   n = object->oidLen;

   //dot1dStpPort is used as instance identifier
   error = mibDecodePort(oid, oidLen, &n, &dot1dStpPort);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //dot1dStpPortProtocolMigration object?
   if(!strcmp(object->name, "dot1dStpPortProtocolMigration"))
   {
      //This object can be be set by management to force the Port Protocol
      //Migration state machine to transmit RST BPDUs for a MigrateTime period
      if(value->integer == MIB_TRUTH_VALUE_TRUE)
      {
         //When operating in RSTP mode, writing true to this object forces this
         //port to transmit RSTP BPDUs
         error = rstpMgmtSetProtocolMigration(rstpMibBase.rstpBridgeContext,
            dot1dStpPort, TRUE, commit);
      }
      else if(value->integer == MIB_TRUTH_VALUE_FALSE)
      {
         //Any other operation on this object has no effect
         error = rstpMgmtSetProtocolMigration(rstpMibBase.rstpBridgeContext,
            dot1dStpPort, FALSE, commit);
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   //dot1dStpPortAdminEdgePort object?
   else if(!strcmp(object->name, "dot1dStpPortAdminEdgePort"))
   {
      //Set the administrative value of the Edge Port parameter
      if(value->integer == MIB_TRUTH_VALUE_TRUE)
      {
         //A value of true indicates that this port should be assumed as an
         //edge port
         error = rstpMgmtSetAdminEdgePort(rstpMibBase.rstpBridgeContext,
            dot1dStpPort, TRUE, commit);
      }
      else if(value->integer == MIB_TRUTH_VALUE_FALSE)
      {
         //A value of false indicates that this port should be assumed as a
         //non-edge port
         error = rstpMgmtSetAdminEdgePort(rstpMibBase.rstpBridgeContext,
            dot1dStpPort, FALSE, commit);
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   //dot1dStpPortAdminPointToPoint object?
   else if(!strcmp(object->name, "dot1dStpPortAdminPointToPoint"))
   {
      //Set the administrative point-to-point status of the LAN segment
      //attached to this port
      if(value->integer == RSTP_MIB_PORT_ADMIN_P2P_FORCE_TRUE)
      {
         //The administrator requires the MAC to be treated as if it is
         //connected to a point-to-point LAN, regardless of any indications
         //to the contrary that are generated by the MAC entity
         error = rstpMgmtSetAdminPointToPointMac(rstpMibBase.rstpBridgeContext,
            dot1dStpPort, RSTP_ADMIN_P2P_MAC_FORCE_TRUE, commit);
      }
      else if(value->integer == RSTP_MIB_PORT_ADMIN_P2P_FORCE_FALSE)
      {
         //The administrator requires the MAC to be treated as connected to a
         //non-point-to-point LAN, regardless of any indications to the contrary
         //that are generated by the MAC entity
         error = rstpMgmtSetAdminPointToPointMac(rstpMibBase.rstpBridgeContext,
            dot1dStpPort, RSTP_ADMIN_P2P_MAC_FORCE_FALSE, commit);
      }
      else if(value->integer == RSTP_MIB_PORT_ADMIN_P2P_AUTO)
      {
         //The administrator requires the point-to-point status of the MAC to
         //be determined in accordance with the specific MAC procedure
         error = rstpMgmtSetAdminPointToPointMac(rstpMibBase.rstpBridgeContext,
            dot1dStpPort, RSTP_ADMIN_P2P_MAC_AUTO, commit);
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   //dot1dStpPortAdminPathCost object?
   else if(!strcmp(object->name, "dot1dStpPortAdminPathCost"))
   {
      //Ensure that the supplied value is valid
      if(value->integer >= 0)
      {
         //This object specifies the administratively assigned value for the
         //contribution of this port to the path cost of paths toward the
         //spanning tree root
         error = rstpMgmtSetAdminPortPathCost(rstpMibBase.rstpBridgeContext,
            dot1dStpPort, value->integer, commit);
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
 * @brief Get dot1dStpExtPortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t rstpMibGetDot1dStpExtPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint16_t dot1dStpPort;

   //Point to the instance identifier
   n = object->oidLen;

   //dot1dStpPort is used as instance identifier
   error = mibDecodePort(oid, oidLen, &n, &dot1dStpPort);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //dot1dStpPortProtocolMigration object?
   if(!strcmp(object->name, "dot1dStpPortProtocolMigration"))
   {
      //This object always returns false when read
      value->integer = MIB_TRUTH_VALUE_FALSE;
   }
   //dot1dStpPortAdminEdgePort object?
   else if(!strcmp(object->name, "dot1dStpPortAdminEdgePort"))
   {
      bool_t adminEdgePort;

      //This object specifies the administrative value of the Edge Port
      //parameter
      error = rstpMgmtGetAdminEdgePort(rstpMibBase.rstpBridgeContext,
         dot1dStpPort, &adminEdgePort);

      //Check status code
      if(!error)
      {
         //Return the value of the object
         if(adminEdgePort)
         {
            value->integer = MIB_TRUTH_VALUE_TRUE;
         }
         else
         {
            value->integer = MIB_TRUTH_VALUE_FALSE;
         }
      }
   }
   //dot1dStpPortOperEdgePort object?
   else if(!strcmp(object->name, "dot1dStpPortOperEdgePort"))
   {
      bool_t operEdgePort;

      //This object specifies the operational value of the Edge Port parameter
      error = rstpMgmtGetOperEdgePort(rstpMibBase.rstpBridgeContext,
         dot1dStpPort, &operEdgePort);

      //Check status code
      if(!error)
      {
         //Return the value of the object
         if(operEdgePort)
         {
            value->integer = MIB_TRUTH_VALUE_TRUE;
         }
         else
         {
            value->integer = MIB_TRUTH_VALUE_FALSE;
         }
      }
   }
   //dot1dStpPortAdminPointToPoint object?
   else if(!strcmp(object->name, "dot1dStpPortAdminPointToPoint"))
   {
      RstpAdminPointToPointMac adminPointToPointMac;

      //This object specifies the administrative point-to-point status of the
      //LAN segment attached to this port
      error = rstpMgmtGetAdminPointToPointMac(rstpMibBase.rstpBridgeContext,
         dot1dStpPort, &adminPointToPointMac);

      //Check status code
      if(!error)
      {
         //Return the value of the object
         if(adminPointToPointMac == RSTP_ADMIN_P2P_MAC_FORCE_TRUE)
         {
            //The administrator requires the MAC to be treated as if it is
            //connected to a point-to-point LAN, regardless of any indications
            //to the contrary that are generated by the MAC entity
            value->integer = RSTP_MIB_PORT_ADMIN_P2P_FORCE_TRUE;
         }
         else if(adminPointToPointMac == RSTP_ADMIN_P2P_MAC_FORCE_FALSE)
         {
            //The administrator requires the MAC to be treated as connected to
            //a non-point-to-point LAN, regardless of any indications to the
            //contrary that are generated by the MAC entity
            value->integer = RSTP_MIB_PORT_ADMIN_P2P_FORCE_FALSE;
         }
         else
         {
            //The administrator requires the point-to-point status of the MAC
            //to be determined in accordance with the specific MAC procedure
            value->integer = RSTP_MIB_PORT_ADMIN_P2P_AUTO;
         }
      }
   }
   //dot1dStpPortOperPointToPoint object?
   else if(!strcmp(object->name, "dot1dStpPortOperPointToPoint"))
   {
      bool_t operPointToPointMac;

      //This object specifies the operational point-to-point status of the LAN
      //segment attached to this port
      error = rstpMgmtGetOperPointToPointMac(rstpMibBase.rstpBridgeContext,
         dot1dStpPort, &operPointToPointMac);

      //Check status code
      if(!error)
      {
         //Return the value of the object
         if(operPointToPointMac)
         {
            value->integer = MIB_TRUTH_VALUE_TRUE;
         }
         else
         {
            value->integer = MIB_TRUTH_VALUE_FALSE;
         }
      }
   }
   //dot1dStpPortAdminPathCost object?
   else if(!strcmp(object->name, "dot1dStpPortAdminPathCost"))
   {
      uint32_t adminPathCost;

      //This object specifies the administratively assigned value for the
      //contribution of this port to the path cost of paths toward the spanning
      //tree root. If the default Path Cost is being used, this object returns
      //0 when read
      error = rstpMgmtGetAdminPortPathCost(rstpMibBase.rstpBridgeContext,
         dot1dStpPort, &adminPathCost);

      //Check status code
      if(!error)
      {
         //Return the value of the object
         value->integer = adminPathCost;
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
 * @brief Get next dot1dStpExtPortEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t rstpMibGetNextDot1dStpExtPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   uint16_t portNum;
   uint16_t curPortNum;
   RstpBridgeContext *context;

   //Initialize variable
   portNum = 0;

   //Point to the RSTP bridge context
   context = rstpMibBase.rstpBridgeContext;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Retrieve the port number associated with the current port
      curPortNum = context->ports[i].portId & RSTP_PORT_NUM_MASK;

      //Append the instance identifier to the OID prefix
      n = object->oidLen;

      //dot1dStpPort is used as instance identifier
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

   //dot1dStpPort is used as instance identifier
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

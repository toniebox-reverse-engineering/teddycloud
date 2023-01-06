/**
 * @file bridge_mib_impl.c
 * @brief Bridge MIB module implementation (dot1dStp subtree)
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
#include "mibs/bridge_mib_impl_stp.h"
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
 * @brief Get dot1dStpProtocolSpecification object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpProtocolSpecification(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   //This object indicates what version of the Spanning Tree Protocol is
   //being run
   value->integer = bridgeMibBase.dot1dStpProtocolSpecification;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set dot1dStpPriority object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dStpPriority(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (BRIDGE_MIB_SET_SUPPORT == ENABLED)
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 0 && value->integer <= 65535)
   {
#if (STP_SUPPORT == ENABLED)
      //Valid STP bridge context?
      if(bridgeMibBase.stpBridgeContext != NULL)
      {
         //This object specifies the value of the write-able portion of the
         //Bridge ID
         error = stpMgmtSetBridgePriority(bridgeMibBase.stpBridgeContext,
            value->integer, commit);
      }
      else
#endif
#if (RSTP_SUPPORT == ENABLED)
      //Valid RSTP bridge context?
      if(bridgeMibBase.rstpBridgeContext != NULL)
      {
         //This object specifies the value of the write-able portion of the
         //Bridge ID
         error = rstpMgmtSetBridgePriority(bridgeMibBase.rstpBridgeContext,
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
 * @brief Get dot1dStpPriority object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPriority(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint16_t bridgePriority;

   //Initialize object value
   bridgePriority = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the value of the write-able portion of the
      //Bridge ID
      error = stpMgmtGetBridgePriority(bridgeMibBase.stpBridgeContext,
         &bridgePriority);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the value of the write-able portion of the
      //Bridge ID
      error = rstpMgmtGetBridgePriority(bridgeMibBase.rstpBridgeContext,
         &bridgePriority);
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
      value->integer = bridgePriority;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpTimeSinceTopologyChange object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpTimeSinceTopologyChange(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t timeSinceTopologyChange;

   //Initialize object value
   timeSinceTopologyChange = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //Retrieve the time since the last time a topology change was detected by
      //the bridge entity
      error = stpMgmtGetTimeSinceTopologyChange(bridgeMibBase.stpBridgeContext,
         &timeSinceTopologyChange);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //Retrieve the time since the last time a topology change was detected by
      //the bridge entity
      error = rstpMgmtGetTimeSinceTopologyChange(bridgeMibBase.rstpBridgeContext,
         &timeSinceTopologyChange);
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
      //Return the value of the object (in hundredths of a second)
      value->integer = timeSinceTopologyChange * 100;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpTopChanges object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpTopChanges(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t topologyChanges;

   //Initialize object value
   topologyChanges = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //Get the total number of topology changes detected by this bridge since
      //the management entity was last reset or initialized
      error = stpMgmtGetTopologyChanges(bridgeMibBase.stpBridgeContext,
         &topologyChanges);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //Get the total number of topology changes detected by this bridge since
      //the management entity was last reset or initialized
      error = rstpMgmtGetTopologyChanges(bridgeMibBase.rstpBridgeContext,
         &topologyChanges);
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
      value->integer = topologyChanges;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpDesignatedRoot object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpDesignatedRoot(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   StpBridgeId designatedRoot;

   //Make sure the buffer is large enough to hold the entire object
   if(*valueLen < sizeof(StpBridgeId))
      return ERROR_BUFFER_OVERFLOW;

   //Initialize object value
   designatedRoot.priority = 0;
   designatedRoot.addr = MAC_UNSPECIFIED_ADDR;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //Get the bridge identifier of the root of the spanning tree
      error = stpMgmtGetDesignatedRoot(bridgeMibBase.stpBridgeContext,
         &designatedRoot);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //Get the bridge identifier of the root of the spanning tree
      error = rstpMgmtGetDesignatedRoot(bridgeMibBase.rstpBridgeContext,
         &designatedRoot);
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
      //Convert the priority field to network byte order
      designatedRoot.priority = htons(designatedRoot.priority);
      //Copy the bridge identifier
      osMemcpy(value->octetString, &designatedRoot, sizeof(StpBridgeId));
      //A bridge identifier shall be encoded as eight octets
      *valueLen = sizeof(StpBridgeId);
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpRootCost object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpRootCost(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint32_t rootPathCost;

   //Initialize object value
   rootPathCost = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //Get the cost of the path to the root as seen from this bridge
      error = stpMgmtGetRootPathCost(bridgeMibBase.stpBridgeContext,
         &rootPathCost);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //Get the cost of the path to the root as seen from this bridge
      error = rstpMgmtGetRootPathCost(bridgeMibBase.rstpBridgeContext,
         &rootPathCost);
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
      value->integer = rootPathCost;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpRootPort object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpRootPort(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint16_t rootPort;

   //Initialize object value
   rootPort = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This parameter is used to identify the port through which the path to
      //the Root is established. It is not significant when the bridge is the
      //Root, and is set to zero
      error = stpMgmtGetRootPort(bridgeMibBase.stpBridgeContext, &rootPort);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This parameter is used to identify the port through which the path to
      //the Root is established. It is not significant when the bridge is the
      //Root, and is set to zero
      error = rstpMgmtGetRootPort(bridgeMibBase.rstpBridgeContext, &rootPort);
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
      value->integer = rootPort;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpMaxAge object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpMaxAge(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t maxAge;

   //Initialize object value
   maxAge = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the maximum age of Spanning Tree Protocol
      //information learned from the network on any port before it is discarded
      error = stpMgmtGetMaxAge(bridgeMibBase.stpBridgeContext, &maxAge);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the maximum age of Spanning Tree Protocol
      //information learned from the network on any port before it is discarded
      error = rstpMgmtGetMaxAge(bridgeMibBase.rstpBridgeContext, &maxAge);
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
      //Return the value of the object (in hundredths of a second)
      value->integer = maxAge * 100;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpHelloTime object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpHelloTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t helloTime;

   //Initialize object value
   helloTime = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the amount of time between the transmission of
      //Configuration bridge PDUs by this node on any port when it is the root
      //of the spanning tree, or trying to become so
      error = stpMgmtGetHelloTime(bridgeMibBase.stpBridgeContext, &helloTime);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the amount of time between the transmission of
      //Configuration bridge PDUs by this node on any port when it is the root
      //of the spanning tree, or trying to become so
      error = rstpMgmtGetHelloTime(bridgeMibBase.rstpBridgeContext, &helloTime);
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
      //Return the value of the object (in hundredths of a second)
      value->integer = helloTime * 100;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpHoldTime object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpHoldTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      uint_t holdTime;

      //This time value determines the interval length during which no more
      //than two Configuration bridge PDUs shall be transmitted by this node
      error = stpMgmtGetHoldTime(bridgeMibBase.stpBridgeContext, &holdTime);

      //Check status code
      if(!error)
      {
         //The hold time value is expressed in hundredths of a second
         value->integer = holdTime * 100;
      }
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      uint_t txHoldCount;
      RstpBridgeContext *context;

      //Point to the RSTP bridge context
      context = bridgeMibBase.rstpBridgeContext;

      //The Transmit Hold Count parameter specifies the number or BPDUs that
      //can be transmitted during every hello time period ranges
      error = rstpMgmtGetTxHoldCount(context, &txHoldCount);

      //Check status code
      if(!error)
      {
         //The hold time value is expressed in hundredths of a second
         if(txHoldCount > 0)
         {
            value->integer = (context->params.bridgeHelloTime * 100) /
               txHoldCount;
         }
         else
         {
            value->integer = 0;
         }
      }
   }
   else
#endif
   //Invalid bridge context?
   {
      //Report an error
      error = ERROR_READ_FAILED;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpForwardDelay object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpForwardDelay(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t forwardDelay;

   //Initialize object value
   forwardDelay = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This time value controls how fast a port changes its spanning state
      //when moving towards the Forwarding state. The value determines how
      //long the port stays in each of the Listening and Learning states, which
      //precede the Forwarding state
      error = stpMgmtGetForwardDelay(bridgeMibBase.stpBridgeContext,
         &forwardDelay);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This time value controls how fast a port changes its spanning state
      //when moving towards the Forwarding state. The value determines how
      //long the port stays in each of the Listening and Learning states, which
      //precede the Forwarding state
      error = rstpMgmtGetForwardDelay(bridgeMibBase.rstpBridgeContext,
         &forwardDelay);
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
      //Return the value of the object (in hundredths of a second)
      value->integer = forwardDelay * 100;
   }

   //Return status code
   return error;
}


/**
 * @brief Set dot1dStpBridgeMaxAge object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dStpBridgeMaxAge(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (BRIDGE_MIB_SET_SUPPORT == ENABLED)
   error_t error;
   uint_t bridgeMaxAge;

   //The granularity of this timer is specified by 802.1D-1998 to be 1 second.
   //An agent may return a badValue error if a set is attempted to a value that
   //is not a whole number of seconds
   if((value->integer % 100) != 0)
      return ERROR_WRONG_VALUE;

   //The value is expressed in hundredths of a second
   bridgeMaxAge = value->integer / 100;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for MaxAge when
      //this bridge is acting as the root
      error = stpMgmtSetBridgeMaxAge(bridgeMibBase.stpBridgeContext,
         bridgeMaxAge, commit);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for MaxAge when
      //this bridge is acting as the root
      error = rstpMgmtSetBridgeMaxAge(bridgeMibBase.rstpBridgeContext,
         bridgeMaxAge, commit);
   }
   else
#endif
   //Invalid bridge context?
   {
      //Report an error
      error = ERROR_WRITE_FAILED;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get dot1dStpBridgeMaxAge object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpBridgeMaxAge(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t bridgeMaxAge;

   //Initialize object value
   bridgeMaxAge = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for MaxAge when
      //this bridge is acting as the root
      error = stpMgmtGetBridgeMaxAge(bridgeMibBase.stpBridgeContext,
         &bridgeMaxAge);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for MaxAge when
      //this bridge is acting as the root
      error = rstpMgmtGetBridgeMaxAge(bridgeMibBase.rstpBridgeContext,
         &bridgeMaxAge);
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
      //Return the value of the object (in hundredths of a second)
      value->integer = bridgeMaxAge * 100;
   }

   //Return status code
   return error;
}


/**
 * @brief Set dot1dStpBridgeHelloTime object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dStpBridgeHelloTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (BRIDGE_MIB_SET_SUPPORT == ENABLED)
   error_t error;
   uint_t bridgeHelloTime;

   //The granularity of this timer is specified by 802.1D-1998 to be 1 second.
   //An agent may return a badValue error if a set is attempted to a value that
   //is not a whole number of seconds
   if((value->integer % 100) != 0)
      return ERROR_WRONG_VALUE;

   //The value is expressed in hundredths of a second
   bridgeHelloTime = value->integer / 100;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for HelloTime when
      //this bridge is acting as the root
      error = stpMgmtSetBridgeHelloTime(bridgeMibBase.stpBridgeContext,
         bridgeHelloTime, commit);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for HelloTime when
      //this bridge is acting as the root
      error = rstpMgmtSetBridgeHelloTime(bridgeMibBase.rstpBridgeContext,
         bridgeHelloTime, commit);
   }
   else
#endif
   //Invalid bridge context?
   {
      //Report an error
      error = ERROR_WRITE_FAILED;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get dot1dStpBridgeHelloTime object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpBridgeHelloTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t bridgeHelloTime;

   //Initialize object value
   bridgeHelloTime = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for HelloTime when
      //this bridge is acting as the root
      error = stpMgmtGetBridgeHelloTime(bridgeMibBase.stpBridgeContext,
         &bridgeHelloTime);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for HelloTime when
      //this bridge is acting as the root
      error = rstpMgmtGetBridgeHelloTime(bridgeMibBase.rstpBridgeContext,
         &bridgeHelloTime);
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
      //Return the value of the object (in hundredths of a second)
      value->integer = bridgeHelloTime * 100;
   }

   //Return status code
   return error;
}


/**
 * @brief Set dot1dStpBridgeForwardDelay object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dStpBridgeForwardDelay(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (BRIDGE_MIB_SET_SUPPORT == ENABLED)
   error_t error;
   uint_t bridgeForwardDelay;

   //The granularity of this timer is specified by 802.1D-1998 to be 1 second.
   //An agent may return a badValue error if a set is attempted to a value that
   //is not a whole number of seconds
   if((value->integer % 100) != 0)
      return ERROR_WRONG_VALUE;

   //The value is expressed in hundredths of a second
   bridgeForwardDelay = value->integer / 100;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for ForwardDelay
      //when this bridge is acting as the root
      error = stpMgmtSetBridgeForwardDelay(bridgeMibBase.stpBridgeContext,
         bridgeForwardDelay, commit);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for ForwardDelay
      //when this bridge is acting as the root
      error = rstpMgmtSetBridgeForwardDelay(bridgeMibBase.rstpBridgeContext,
         bridgeForwardDelay, commit);
   }
   else
#endif
   //Invalid bridge context?
   {
      //Report an error
      error = ERROR_WRITE_FAILED;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get dot1dStpBridgeForwardDelay object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpBridgeForwardDelay(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t bridgeForwardDelay;

   //Initialize object value
   bridgeForwardDelay = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for ForwardDelay
      //when this bridge is acting as the root
      error = stpMgmtGetBridgeForwardDelay(bridgeMibBase.stpBridgeContext,
         &bridgeForwardDelay);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the value that all bridges use for ForwardDelay
      //when this bridge is acting as the root
      error = rstpMgmtGetBridgeForwardDelay(bridgeMibBase.rstpBridgeContext,
         &bridgeForwardDelay);
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
      //Return the value of the object (in hundredths of a second)
      value->integer = bridgeForwardDelay * 100;
   }

   //Return status code
   return error;
}


/**
 * @brief Set dot1dStpPortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dStpPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (BRIDGE_MIB_SET_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint_t portIndex;
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

   //Retrieve the port that matches the specified port number
   portIndex = bridgeMibGetPortIndex(dot1dStpPort);
   //Invalid port number?
   if(portIndex == 0)
      return ERROR_INSTANCE_NOT_FOUND;

   //dot1dStpPortPriority object?
   if(!strcmp(object->name, "dot1dStpPortPriority"))
   {
      //This object specifies the value of the priority field that is
      //contained in the first octet of the Port Identifier
      error = bridgeMibSetDot1dStpPortPriority(portIndex, value, valueLen,
         commit);
   }
   //dot1dStpPortEnable object?
   else if(!strcmp(object->name, "dot1dStpPortEnable"))
   {
      //This object specifies the enabled/disabled status of the port
      error = bridgeMibSetDot1dStpPortEnable(portIndex, value, valueLen,
         commit);
   }
   //dot1dStpPortPathCost object?
   else if(!strcmp(object->name, "dot1dStpPortPathCost"))
   {
      //This object specifies the contribution of this port to the path
      //cost of paths towards the spanning tree root which include this
      //port
      error = bridgeMibSetDot1dStpPortPathCost(portIndex, value, valueLen,
         commit);
   }
   //dot1dStpPortPathCost32 object?
   else if(!strcmp(object->name, "dot1dStpPortPathCost32"))
   {
      //This object specifies the contribution of this port to the path
      //cost of paths towards the spanning tree root which include this
      //port
      error = bridgeMibSetDot1dStpPortPathCost32(portIndex, value, valueLen,
         commit);
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
 * @brief Get dot1dStpPortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t portIndex;
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

   //Retrieve the port that matches the specified port number
   portIndex = bridgeMibGetPortIndex(dot1dStpPort);
   //Invalid port number?
   if(portIndex == 0)
      return ERROR_INSTANCE_NOT_FOUND;

   //dot1dStpPort object?
   if(!strcmp(object->name, "dot1dStpPort"))
   {
      //This object specifies the port number of the port for which this
      //entry contains Spanning Tree Protocol management information
      value->integer = dot1dStpPort;
   }
   //dot1dStpPortPriority object?
   else if(!strcmp(object->name, "dot1dStpPortPriority"))
   {
      //This object specifies the value of the priority field that is contained
      //in the first octet of the Port Identifier
      error = bridgeMibGetDot1dStpPortPriority(portIndex, value, valueLen);
   }
   //dot1dStpPortState object?
   else if(!strcmp(object->name, "dot1dStpPortState"))
   {
      //This object specifies the port's current state, as defined by
      //application of the Spanning Tree Protocol
      error = bridgeMibGetDot1dStpPortState(portIndex, value, valueLen);
   }
   //dot1dStpPortEnable object?
   else if(!strcmp(object->name, "dot1dStpPortEnable"))
   {
      //This object specifies the enabled/disabled status of the port
      error = bridgeMibGetDot1dStpPortEnable(portIndex, value, valueLen);
   }
   //dot1dStpPortPathCost object?
   else if(!strcmp(object->name, "dot1dStpPortPathCost"))
   {
      //This object specifies the contribution of this port to the path cost
      //of paths towards the spanning tree root which include this port
      error = bridgeMibGetDot1dStpPortPathCost(portIndex, value, valueLen);
   }
   //dot1dStpPortDesignatedRoot object?
   else if(!strcmp(object->name, "dot1dStpPortDesignatedRoot"))
   {
      //This object specifies the unique Bridge Identifier of the bridge
      //recorded as the Root in the Configuration BPDUs transmitted by the
      //Designated Bridge for the segment to which the port is attached
      error = bridgeMibGetDot1dStpPortDesignatedRoot(portIndex, value,
         valueLen);
   }
   //dot1dStpPortDesignatedCost object?
   else if(!strcmp(object->name, "dot1dStpPortDesignatedCost"))
   {
      //This object specifies the path cost of the Designated Port of the
      //segment connected to this port
      error = bridgeMibGetDot1dStpPortDesignatedCost(portIndex, value,
         valueLen);
   }
   //dot1dStpPortDesignatedBridge object?
   else if(!strcmp(object->name, "dot1dStpPortDesignatedBridge"))
   {
      //This object specifies the Bridge Identifier of the bridge that this
      //port considers to be the Designated Bridge for this port's segment
      error = bridgeMibGetDot1dStpPortDesignatedBridge(portIndex, value,
         valueLen);
   }
   //dot1dStpPortDesignatedPort object?
   else if(!strcmp(object->name, "dot1dStpPortDesignatedPort"))
   {
      //This object specifies the Port Identifier of the port on the
      //Designated Bridge for this port's segment
      error = bridgeMibGetDot1dStpPortDesignatedPort(portIndex, value,
         valueLen);
   }
   //dot1dStpPortForwardTransitions object?
   else if(!strcmp(object->name, "dot1dStpPortForwardTransitions"))
   {
      //The number of times this port has transitioned from the Learning state
      //to the Forwarding state
      error = bridgeMibGetDot1dStpPortForwardTransitions(portIndex, value,
         valueLen);
   }
   //dot1dStpPortPathCost32 object?
   else if(!strcmp(object->name, "dot1dStpPortPathCost32"))
   {
      //This object specifies the contribution of this port to the path cost
      //of paths towards the spanning tree root which include this port
      error = bridgeMibGetDot1dStpPortPathCost32(portIndex, value,
         valueLen);
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
 * @brief Get next dot1dStpPortEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t bridgeMibGetNextDot1dStpPortEntry(const MibObject *object, const uint8_t *oid,
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


/**
 * @brief Set dot1dStpPortPriority object value
 * @param[in] portNum Port number
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dStpPortPriority(uint16_t portNum,
   const MibVariant *value, size_t valueLen, bool_t commit)
{
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 0 && value->integer <= 255)
   {
#if (STP_SUPPORT == ENABLED)
      //Valid STP bridge context?
      if(bridgeMibBase.stpBridgeContext != NULL)
      {
         //This object specifies the value of the priority field that is
         //contained in the first octet of the Port Identifier
         error = stpMgmtSetPortPriority(bridgeMibBase.stpBridgeContext,
            portNum, value->integer, commit);
      }
      else
#endif
#if (RSTP_SUPPORT == ENABLED)
      //Valid RSTP bridge context?
      if(bridgeMibBase.rstpBridgeContext != NULL)
      {
         //This object specifies the value of the priority field that is
         //contained in the first octet of the Port Identifier
         error = rstpMgmtSetPortPriority(bridgeMibBase.rstpBridgeContext,
            portNum, value->integer, commit);
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
}


/**
 * @brief Get dot1dStpPortPriority object value
 * @param[in] portNum Port number
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortPriority(uint16_t portNum,
   MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint8_t portPriority;

   //Initialize object value
   portPriority = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the value of the priority field that is contained
      //in the first octet of the Port Identifier
      error = stpMgmtGetPortPriority(bridgeMibBase.stpBridgeContext,
         portNum, &portPriority);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the value of the priority field that is contained
      //in the first octet of the Port Identifier
      error = rstpMgmtGetPortPriority(bridgeMibBase.rstpBridgeContext,
         portNum, &portPriority);
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
      value->integer = portPriority;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpPortState object value
 * @param[in] portNum Port number
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortState(uint16_t portNum,
   MibVariant *value, size_t *valueLen)
{
   error_t error;
   StpPortState portState;

   //Initialize object value
   portState = STP_PORT_STATE_DISABLED;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the port's current state, as defined by
      //application of the Spanning Tree Protocol
      error = stpMgmtGetPortState(bridgeMibBase.stpBridgeContext,
         portNum, &portState);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the port's current state, as defined by
      //application of the Spanning Tree Protocol
      error = rstpMgmtGetPortState(bridgeMibBase.rstpBridgeContext,
         portNum, &portState);
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
      switch(portState)
      {
      case STP_PORT_STATE_DISABLED:
         value->integer = BRIDGE_MIB_PORT_STATE_DISABLED;
         break;
      case STP_PORT_STATE_BROKEN:
         value->integer = BRIDGE_MIB_PORT_STATE_BROKEN;
         break;
      case STP_PORT_STATE_BLOCKING:
         value->integer = BRIDGE_MIB_PORT_STATE_BLOCKING;
         break;
      case STP_PORT_STATE_LISTENING:
         value->integer = BRIDGE_MIB_PORT_STATE_LISTENING;
         break;
      case STP_PORT_STATE_LEARNING:
         value->integer = BRIDGE_MIB_PORT_STATE_LEARNING;
         break;
      case STP_PORT_STATE_FORWARDING:
         value->integer = BRIDGE_MIB_PORT_STATE_FORWARDING;
         break;
      default:
         value->integer = BRIDGE_MIB_PORT_STATE_UNKNOWN;
         break;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Set dot1dStpPortEnable object value
 * @param[in] portNum Port number
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dStpPortEnable(uint16_t portNum,
   const MibVariant *value, size_t valueLen, bool_t commit)
{
   error_t error;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the enabled/disabled status of the port
      if(value->integer == BRIDGE_MIB_PORT_STATUS_ENABLED)
      {
         //Enable the port
         error = stpMgmtSetAdminPortState(bridgeMibBase.stpBridgeContext,
            portNum, TRUE, commit);
      }
      else if(value->integer == BRIDGE_MIB_PORT_STATUS_DISABLED)
      {
         //Disable the port
         error = stpMgmtSetAdminPortState(bridgeMibBase.stpBridgeContext,
            portNum, FALSE, commit);
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the enabled/disabled status of the port
      if(value->integer == BRIDGE_MIB_PORT_STATUS_ENABLED)
      {
         //Enable the port
         error = rstpMgmtSetAdminPortState(bridgeMibBase.rstpBridgeContext,
            portNum, TRUE, commit);
      }
      else if(value->integer == BRIDGE_MIB_PORT_STATUS_DISABLED)
      {
         //Disable the port
         error = rstpMgmtSetAdminPortState(bridgeMibBase.rstpBridgeContext,
            portNum, FALSE, commit);
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   else
#endif
   //Invalid bridge context?
   {
      //Report an error
      error = ERROR_WRITE_FAILED;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpPortEnable object value
 * @param[in] portNum Port number
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortEnable(uint16_t portNum,
   MibVariant *value, size_t *valueLen)
{
   error_t error;
   bool_t adminPortState;

   //Initialize object value
   adminPortState = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the enabled/disabled status of the port
      error = stpMgmtGetAdminPortState(bridgeMibBase.stpBridgeContext,
         portNum, &adminPortState);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the enabled/disabled status of the port
      error = rstpMgmtGetAdminPortState(bridgeMibBase.rstpBridgeContext,
         portNum, &adminPortState);
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
      if(adminPortState)
      {
         value->integer = BRIDGE_MIB_PORT_STATUS_ENABLED;
      }
      else
      {
         value->integer = BRIDGE_MIB_PORT_STATUS_DISABLED;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Set dot1dStpPortPathCost object value
 * @param[in] portNum Port number
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dStpPortPathCost(uint16_t portNum,
   const MibVariant *value, size_t valueLen, bool_t commit)
{
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 1 && value->integer <= 65535)
   {
#if (STP_SUPPORT == ENABLED)
      //Valid STP bridge context?
      if(bridgeMibBase.stpBridgeContext != NULL)
      {
         //This object specifies the contribution of this port to the path cost
         //of paths towards the spanning tree root which include this port
         error = stpMgmtSetPortPathCost(bridgeMibBase.stpBridgeContext,
            portNum, value->integer, commit);
      }
      else
#endif
#if (RSTP_SUPPORT == ENABLED)
      //Valid RSTP bridge context?
      if(bridgeMibBase.rstpBridgeContext != NULL)
      {
         //This object specifies the contribution of this port to the path cost
         //of paths towards the spanning tree root which include this port
         error = rstpMgmtSetAdminPortPathCost(bridgeMibBase.rstpBridgeContext,
            portNum, value->integer, commit);
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
}


/**
 * @brief Get dot1dStpPortPathCost object value
 * @param[in] portNum Port number
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortPathCost(uint16_t portNum,
   MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint32_t portPathCost;

   //Initialize object value
   portPathCost = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the contribution of this port to the path cost
      //of paths towards the spanning tree root which include this port
      error = stpMgmtGetPortPathCost(bridgeMibBase.stpBridgeContext,
         portNum, &portPathCost);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the contribution of this port to the path cost
      //of paths towards the spanning tree root which include this port
      error = rstpMgmtGetPortPathCost(bridgeMibBase.rstpBridgeContext,
         portNum, &portPathCost);
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
      //If the port path costs exceeds the maximum value of this object then
      //this object should report the maximum value, namely 65535
      value->integer = MIN(portPathCost, 65535);
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpPortDesignatedRoot object value
 * @param[in] portNum Port number
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortDesignatedRoot(uint16_t portNum,
   MibVariant *value, size_t *valueLen)
{
   error_t error;
   StpBridgeId designatedRoot;

   //Make sure the buffer is large enough to hold the entire object
   if(*valueLen < sizeof(StpBridgeId))
      return ERROR_BUFFER_OVERFLOW;

   //Initialize object value
   designatedRoot.priority = 0;
   designatedRoot.addr = MAC_UNSPECIFIED_ADDR;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the unique Bridge Identifier of the bridge
      //recorded as the Root in the Configuration BPDUs transmitted by the
      //Designated Bridge for the segment to which the port is attached
      error = stpMgmtGetPortDesignatedRoot(bridgeMibBase.stpBridgeContext,
         portNum, &designatedRoot);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the unique Bridge Identifier of the bridge
      //recorded as the Root in the Configuration BPDUs transmitted by the
      //Designated Bridge for the segment to which the port is attached
      error = rstpMgmtGetPortDesignatedRoot(bridgeMibBase.rstpBridgeContext,
         portNum, &designatedRoot);
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
      //Convert the priority field to network byte order
      designatedRoot.priority = htons(designatedRoot.priority);
      //Copy the bridge identifier
      osMemcpy(value->octetString, &designatedRoot, sizeof(StpBridgeId));
      //A bridge identifier shall be encoded as eight octets
      *valueLen = sizeof(StpBridgeId);
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpPortDesignatedCost object value
 * @param[in] portNum Port number
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortDesignatedCost(uint16_t portNum,
   MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint32_t designatedCost;

   //Initialize object value
   designatedCost = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the path cost of the Designated Port of the
      //segment connected to this port
      error = stpMgmtGetPortDesignatedCost(bridgeMibBase.stpBridgeContext,
         portNum, &designatedCost);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the path cost of the Designated Port of the
      //segment connected to this port
      error = rstpMgmtGetPortDesignatedCost(bridgeMibBase.rstpBridgeContext,
         portNum, &designatedCost);
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
      value->integer = designatedCost;
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpPortDesignatedBridge object value
 * @param[in] portNum Port number
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortDesignatedBridge(uint16_t portNum,
   MibVariant *value, size_t *valueLen)
{
   error_t error;
   StpBridgeId designatedBridge;

   //Make sure the buffer is large enough to hold the entire object
   if(*valueLen < sizeof(StpBridgeId))
      return ERROR_BUFFER_OVERFLOW;

   //Initialize object value
   designatedBridge.priority = 0;
   designatedBridge.addr = MAC_UNSPECIFIED_ADDR;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the Bridge Identifier of the bridge that this
      //port considers to be the Designated Bridge for this port's segment
      error = stpMgmtGetPortDesignatedBridge(bridgeMibBase.stpBridgeContext,
         portNum, &designatedBridge);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the Bridge Identifier of the bridge that this
      //port considers to be the Designated Bridge for this port's segment
      error = rstpMgmtGetPortDesignatedBridge(bridgeMibBase.rstpBridgeContext,
         portNum, &designatedBridge);
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
      //Convert the priority field to network byte order
      designatedBridge.priority = htons(designatedBridge.priority);
      //Copy the bridge identifier
      osMemcpy(value->octetString, &designatedBridge, sizeof(StpBridgeId));
      //A bridge identifier shall be encoded as eight octets
      *valueLen = sizeof(StpBridgeId);
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpPortDesignatedPort object value
 * @param[in] portNum Port number
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortDesignatedPort(uint16_t portNum,
   MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint16_t designatedPort;

   //Make sure the buffer is large enough to hold the entire object
   if(*valueLen < sizeof(uint16_t))
      return ERROR_BUFFER_OVERFLOW;

   //Initialize object value
   designatedPort = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the Port Identifier of the port on the Designated
      //Bridge for this port's segment
      error = stpMgmtGetPortDesignatedPort(bridgeMibBase.stpBridgeContext,
         portNum, &designatedPort);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the Port Identifier of the port on the Designated
      //Bridge for this port's segment
      error = rstpMgmtGetPortDesignatedPort(bridgeMibBase.rstpBridgeContext,
         portNum, &designatedPort);
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
      STORE16BE(designatedPort, value->octetString);
      //A Port Identifier shall be encoded as two octets
      *valueLen = sizeof(uint16_t);
   }

   //Return status code
   return error;
}


/**
 * @brief Get dot1dStpPortForwardTransitions object value
 * @param[in] portNum Port number
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortForwardTransitions(uint16_t portNum,
   MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t forwardTransitions;

   //Initialize object value
   forwardTransitions = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //The number of times this port has transitioned from the Learning state
      //to the Forwarding state
      error = stpMgmtGetForwardTransitions(bridgeMibBase.stpBridgeContext,
         portNum, &forwardTransitions);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //The number of times this port has transitioned from the Learning state
      //to the Forwarding state
      error = rstpMgmtGetForwardTransitions(bridgeMibBase.rstpBridgeContext,
         portNum, &forwardTransitions);
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
      value->integer = forwardTransitions;
   }

   //Return status code
   return error;
}


/**
 * @brief Set dot1dStpPortPathCost32 object value
 * @param[in] portNum Port number
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t bridgeMibSetDot1dStpPortPathCost32(uint16_t portNum,
   const MibVariant *value, size_t valueLen, bool_t commit)
{
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 1)
   {
#if (STP_SUPPORT == ENABLED)
      //Valid STP bridge context?
      if(bridgeMibBase.stpBridgeContext != NULL)
      {
         //This object specifies the contribution of this port to the path cost
         //of paths towards the spanning tree root which include this port
         error = stpMgmtSetPortPathCost(bridgeMibBase.stpBridgeContext,
            portNum, value->integer, commit);
      }
      else
#endif
#if (RSTP_SUPPORT == ENABLED)
      //Valid RSTP bridge context?
      if(bridgeMibBase.rstpBridgeContext != NULL)
      {
         //This object specifies the contribution of this port to the path cost
         //of paths towards the spanning tree root which include this port
         error = rstpMgmtSetAdminPortPathCost(bridgeMibBase.rstpBridgeContext,
            portNum, value->integer, commit);
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
}


/**
 * @brief Get dot1dStpPortPathCost32 object value
 * @param[in] portNum Port number
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t bridgeMibGetDot1dStpPortPathCost32(uint16_t portNum,
   MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint32_t portPathCost;

   //Initialize object value
   portPathCost = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //This object specifies the contribution of this port to the path cost
      //of paths towards the spanning tree root which include this port
      error = stpMgmtGetPortPathCost(bridgeMibBase.stpBridgeContext,
         portNum, &portPathCost);
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //This object specifies the contribution of this port to the path cost
      //of paths towards the spanning tree root which include this port
      error = rstpMgmtGetPortPathCost(bridgeMibBase.rstpBridgeContext,
         portNum, &portPathCost);
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
      value->integer = portPathCost;
   }

   //Return status code
   return error;
}

#endif

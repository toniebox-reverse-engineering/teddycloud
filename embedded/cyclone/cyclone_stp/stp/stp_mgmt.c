/**
 * @file stp_mgmt.c
 * @brief Management of the STP bridge
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
#define TRACE_LEVEL STP_TRACE_LEVEL

//Dependencies
#include "stp/stp.h"
#include "stp/stp_procedures.h"
#include "stp/stp_conditions.h"
#include "stp/stp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (STP_SUPPORT == ENABLED)


/**
 * @brief Set bridge priority
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Bridge priority
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t stpMgmtSetBridgePriority(StpBridgeContext *context, uint16_t value,
   bool_t commit)
{
   uint_t i;
   bool_t rootBridge;
   StpBridgeId newBridgeId;

   //Make sure the STP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->bridgeId.priority)
      {
         //Test whether the bridge is currently the Root
         rootBridge = stpRootBridge(context);

         //The new value of the Bridge Identifier is calculated
         newBridgeId.addr = context->bridgeId.addr;
         newBridgeId.priority = value;

         //The value of the Designated Bridge parameter held for each port that
         //has been selected as the Designated port for the LAN to which it is
         //attached is set to the new value of the Bridge Identifier
         for(i = 0; i < context->numPorts; i++)
         {
            //Designated port?
            if(stpDesignatedPort(&context->ports[i]))
            {
               context->ports[i].designatedBridge = newBridgeId;
            }
         }

         //The Bridge Identifier held by the bridge is set to the new value
         context->bridgeId = newBridgeId;
         //The Configuration Update procedure is used
         stpConfigUpdate(context);
         //The Port State Selection procedure is used
         stpPortStateSelection(context);

         //Check if the bridge has been selected as the Root following
         //Configuration Update
         if(!rootBridge && stpRootBridge(context))
         {
            //The Max Age, Hello Time, and Forward Delay parameters held by the
            //bridge are set to the values of the Bridge Max Age, Bridge Hello
            //Time, and Bridge Forward Delay parameters
            context->maxAge = context->bridgeMaxAge;
            context->helloTime = context->bridgeHelloTime;
            context->forwardDelay = context->bridgeForwardDelay;

            //The Topology Change Detection procedure is used
            stpTopologyChangeDetection(context);
            //The Topology Change Notification Timer is stopped
            stpStopTimer(&context->tcnTimer);

            //The Configuration BPDU Generation procedure is invoked and the
            //Hello Timer is started
            stpConfigBpduGeneration(context);
            stpStartTimer(&context->helloTimer, 0);
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set Bridge Max Age parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Value of the Bridge Max Age parameter, in seconds
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t stpMgmtSetBridgeMaxAge(StpBridgeContext *context, uint_t value,
   bool_t commit)
{
   //Make sure the STP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //If the value of the Bridge Max Age is outside the specified range, then
   //no action shall be taken
   if(value < STP_MIN_BRIDGE_MAX_AGE || value > STP_MAX_BRIDGE_MAX_AGE)
      return ERROR_WRONG_VALUE;

   //A bridge shall enforce the following relationships (refer to IEEE Std
   //802.1D-1998, section 8.10.2)
   if(!stpCheckBridgeParams(value, context->bridgeHelloTime,
      context->bridgeForwardDelay))
   {
      return ERROR_INCONSISTENT_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->bridgeMaxAge)
      {
         //The Bridge Max Age parameter specifies the value that all bridges use
         //for MaxAge when this bridge is acting as the root
         context->bridgeMaxAge = value;

         //Check if the bridge has been selected as the Root
         if(stpRootBridge(context))
         {
            //The value of the Topology Change Time parameter is equal to the
            //sum of the values of the bridge's Bridge Max Age and Bridge
            //Forward Delay parameters
            context->topologyChangeTime = context->bridgeMaxAge +
               context->bridgeForwardDelay;

            //The Max Age parameter held by the bridge is set to the value of
            //the Bridge Max Age parameter
            context->maxAge = context->bridgeMaxAge;
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set Bridge Hello Time parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Value of the Bridge Hello Time parameter, in seconds
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t stpMgmtSetBridgeHelloTime(StpBridgeContext *context, uint_t value,
   bool_t commit)
{
   //Make sure the STP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //If the value of the Bridge Hello Time is outside the specified range, then
   //no action shall be taken
   if(value < STP_MIN_BRIDGE_HELLO_TIME || value > STP_MAX_BRIDGE_HELLO_TIME)
      return ERROR_WRONG_VALUE;

   //A bridge shall enforce the following relationships (refer to IEEE Std
   //802.1D-1998, section 8.10.2)
   if(!stpCheckBridgeParams(context->bridgeMaxAge, value,
      context->bridgeForwardDelay))
   {
      return ERROR_INCONSISTENT_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->bridgeHelloTime)
      {
         //The Bridge Hello Time parameter specifies the value that all bridges
         //use for HelloTime when this bridge is acting as the root
         context->bridgeHelloTime = value;

         //Check if the bridge has been selected as the Root
         if(stpRootBridge(context))
         {
            //The Hello Time parameter held by the bridge is set to the value of
            //the Bridge Hello Time parameter
            context->helloTime = context->bridgeHelloTime;
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set Bridge Forward Delay parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Value of the Bridge Forward Delay parameter, in seconds
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t stpMgmtSetBridgeForwardDelay(StpBridgeContext *context, uint_t value,
   bool_t commit)
{
   //Make sure the STP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //If the value of the Bridge Forward Delay is outside the specified range,
   //then no action shall be taken
   if(value < STP_MIN_BRIDGE_FORWARD_DELAY || value > STP_MAX_BRIDGE_FORWARD_DELAY)
      return ERROR_WRONG_VALUE;

   //A bridge shall enforce the following relationships (refer to IEEE Std
   //802.1D-1998, section 8.10.2)
   if(!stpCheckBridgeParams(context->bridgeMaxAge, context->bridgeHelloTime,
      value))
   {
      return ERROR_INCONSISTENT_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->bridgeForwardDelay)
      {
         //The Bridge Forward Delay parameter specifies the value that all
         //bridges use for ForwardDelay when this bridge is acting as the root
         context->bridgeForwardDelay = value;

         //Check if the bridge has been selected as the Root
         if(stpRootBridge(context))
         {
            //The value of the Topology Change Time parameter is equal to the
            //sum of the values of the bridge's Bridge Max Age and Bridge
            //Forward Delay parameters
            context->topologyChangeTime = context->bridgeMaxAge +
               context->bridgeForwardDelay;

            //The Forward Delay parameter held by the bridge is set to the
            //value of the Bridge Forward Delay parameter
            context->forwardDelay = context->bridgeForwardDelay;
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set Ageing Time parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Value of the Ageing Time parameter
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t stpMgmtSetAgeingTime(StpBridgeContext *context, uint_t value,
   bool_t commit)
{
   //Make sure the STP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //If the value of the Ageing Time is outside the specified range, then no
   //action shall be taken
   if(value < STP_MIN_AGEING_TIME || value > STP_MAX_AGEING_TIME)
      return ERROR_WRONG_VALUE;

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->ageingTime)
      {
         //The Ageing Time parameter is updated using the supplied value
         context->ageingTime = value;

         //Check whether the rapid ageing timer is stopped
         if(!context->rapidAgeingTimer.active)
         {
            //Set the ageing time for dynamic filtering entries
            stpUpdateAgeingTime(context, context->ageingTime);
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the number of ports
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Number of ports
 * @return Error code
 **/

error_t stpMgmtGetNumPorts(StpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the number of ports
   *value = context->numPorts;

   //Successful processing
   return NO_ERROR;
}

/**
 * @brief Get the MAC address assigned to the bridge
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value MAC address of the bridge
 * @return Error code
 **/

error_t stpMgmtGetBridgeAddr(StpBridgeContext *context, MacAddr *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the bridge identifier
   *value = context->bridgeId.addr;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned bridge priority
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Bridge priority
 * @return Error code
 **/

error_t stpMgmtGetBridgePriority(StpBridgeContext *context, uint16_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the bridge priority
   *value = context->bridgeId.priority;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned value of the Bridge Max Age parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Value of the Bridge Max Age parameter, in seconds
 * @return Error code
 **/

error_t stpMgmtGetBridgeMaxAge(StpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the value of the Bridge Max Age parameter
   *value = context->bridgeMaxAge;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned value of the Bridge Hello Time parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Value of the Bridge Hello Time parameter, in seconds
 * @return Error code
 **/

error_t stpMgmtGetBridgeHelloTime(StpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the value of the Bridge Hello Time parameter
   *value = context->bridgeHelloTime;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned value of the Bridge Forward Delay parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Value of the Bridge Forward Delay parameter, in seconds
 * @return Error code
 **/

error_t stpMgmtGetBridgeForwardDelay(StpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the value of the Bridge Forward Delay parameter
   *value = context->bridgeForwardDelay;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned value of the Hold Time parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Value of the Transmit Hold Count parameter
 * @return Error code
 **/

error_t stpMgmtGetHoldTime(StpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the value of the Hold Time parameter
   *value = context->holdTime;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned value of the Ageing Time parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Value of the Ageing Time parameter
 * @return Error code
 **/

error_t stpMgmtGetAgeingTime(StpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the value of the Ageing Time parameter
   *value = context->ageingTime;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the bridge identifier of the root of the spanning tree
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t stpMgmtGetDesignatedRoot(StpBridgeContext *context, StpBridgeId *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the bridge identifier of the root of the spanning tree, as
   //determined by the Spanning Tree Protocol
   *value = context->designatedRoot;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current cost of the path to the root
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Root path cost
 * @return Error code
 **/

error_t stpMgmtGetRootPathCost(StpBridgeContext *context, uint32_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the cost of the path to the root as seen from this bridge
   *value = context->rootPathCost;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current root port
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Port number
 * @return Error code
 **/

error_t stpMgmtGetRootPort(StpBridgeContext *context, uint16_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the port through which the path to the Root is established. This
   //value not significant when the bridge is the Root, and is set to zero
   *value = context->rootPort & STP_PORT_NUM_MASK;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current Max Age value
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Max Age value, in seconds
 * @return Error code
 **/

error_t stpMgmtGetMaxAge(StpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the maximum age of Spanning Tree Protocol information learned
   //from the network on any port before it is discarded
   *value = context->maxAge;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current Hello Time value
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Hello Time value, in seconds
 * @return Error code
 **/

error_t stpMgmtGetHelloTime(StpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the amount of time between the transmission of Configuration
   //bridge PDUs by this node on any port when it is the root of the spanning
   //tree, or trying to become so
   *value = context->helloTime;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current Forward Delay value
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Forward Delay value, in seconds
 * @return Error code
 **/

error_t stpMgmtGetForwardDelay(StpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //The Forward Delay value determines how long the port stays in each of the
   //Listening and Learning states, which precede the Forwarding state
   *value = context->forwardDelay;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the number of topology changes
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Number of topology changes
 * @return Error code
 **/

error_t stpMgmtGetTopologyChanges(StpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the number of topology changes
   *value = context->topologyChangeCount;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the time since a topology change was last detected
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Time since a topology change was last detected
 * @return Error code
 **/

error_t stpMgmtGetTimeSinceTopologyChange(StpBridgeContext *context,
   uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the time since a topology change was last detected by the bridge
   *value = context->timeSinceTopologyChange;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set port priority
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Port priority
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t stpMgmtSetPortPriority(StpBridgeContext *context, uint_t portIndex,
   uint8_t value, bool_t commit)
{
   uint16_t newPortId;
   StpBridgePort *port;

   //Make sure the STP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != ((port->portId & STP_PORT_PRIORITY_MASK) >> 8))
      {
         //The new value of the Port Identifier is calculated
         newPortId = (port->portId & STP_PORT_NUM_MASK) | (value << 8);

         //Check if the Port has been selected as the Designated Port for the LAN
         //to which it is attached
         if(stpDesignatedPort(port))
         {
            //The Designated Port parameter held for the port is set to the new
            //value of the Port Identifier
            port->designatedPort = newPortId;
         }

         //The Port Identifier parameter held for the port is set to the new value
         port->portId = newPortId;

         //Check if the value of the Designated Bridge parameter held for the
         //port is equal to that of the bridge's Bridge Identifier, and the new
         //value of the Port Identifier is of higher priority than that recorded
         //as the Designated Port
         if(stpCompareBridgeId(&port->designatedBridge, &context->bridgeId) == 0 &&
            port->portId < port->designatedPort)
         {
            //The Become Designated Port procedure is used to assign values to
            //the Designated Root, Designated Cost, Designated Bridge, and
            //Designated Port parameters for the port
            stpBecomeDesignatedPort(port);

            //The Port State Selection procedure is used
            stpPortStateSelection(context);
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set administrative bridge port state
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative bridge port state
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t stpMgmtSetAdminPortState(StpBridgeContext *context, uint_t portIndex,
   bool_t value, bool_t commit)
{
   bool_t rootBridge;
   StpBridgePort *port;

   //Make sure the STP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value && port->state == STP_PORT_STATE_DISABLED)
      {
         //The Become Designated Port procedure is used to assign values to the
         //Designated Root, Designated Cost, Designated Bridge, and Designated
         //Port parameters for the port
         stpBecomeDesignatedPort(port);

         //The Port State is set to Blocking
         stpUpdatePortState(port, STP_PORT_STATE_BLOCKING);
         //The Topology Change Acknowledge flag parameter is reset
         port->topologyChangeAck = FALSE;
         //The Configuration Pending flag parameter is reset
         port->configPending = FALSE;
         //The Message Age Timer is stopped, if running
         stpStopTimer(&port->messageAgeTimer);
         //The Forward Delay Timer is stopped, if running
         stpStopTimer(&port->forwardDelayTimer);
         //The Hold Timer is stopped, if running
         stpStopTimer(&port->holdTimer);
         //The Port State Selection procedure is used
         stpPortStateSelection(context);
      }
      else if(!value && port->state != STP_PORT_STATE_DISABLED)
      {
         //Test whether the bridge is currently the Root
         rootBridge = stpRootBridge(context);

         //The Become Designated Port procedure is used to assign values to the
         //Designated Root, Designated Cost, Designated Bridge, and Designated
         //Port parameters for the port
         stpBecomeDesignatedPort(port);

         //The Port State is set to Disabled
         stpUpdatePortState(port, STP_PORT_STATE_DISABLED);
         //The Topology Change Acknowledge flag parameter is reset
         port->topologyChangeAck = FALSE;
         //The Configuration Pending flag parameter is reset
         port->configPending = FALSE;
         //The Message Age Timer is stopped, if running
         stpStopTimer(&port->messageAgeTimer);
         //The Forward Delay Timer is stopped, if running
         stpStopTimer(&port->forwardDelayTimer);
         //The Configuration Update procedure is used
         stpConfigUpdate(context);
         //The Port State Selection procedure is used
         stpPortStateSelection(context);

         //Check if the Bridge has been selected as the Root following
         //Configuration Update
         if(!rootBridge && stpRootBridge(context))
         {
            //The Max Age, Hello Time, and Forward Delay parameters held by the
            //bridge are set to the values of the Bridge Max Age, Bridge Hello
            //Time, and Bridge Forward Delay parameters
            context->maxAge = context->bridgeMaxAge;
            context->helloTime = context->bridgeHelloTime;
            context->forwardDelay = context->bridgeForwardDelay;

            //The Topology Change Detection procedure is used
            stpTopologyChangeDetection(context);
            //The Topology Change Notification Timer is stopped
            stpStopTimer(&context->tcnTimer);

            //The Configuration BPDU Generation procedure is invoked and the
            //Hello Timer is started
            stpConfigBpduGeneration(context);
            stpStartTimer(&context->helloTimer, 0);
         }
      }
      else
      {
         //The bridge does not take action
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set administrative port path cost
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative port path cost
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t stpMgmtSetPortPathCost(StpBridgeContext *context, uint_t portIndex,
   uint32_t value, bool_t commit)
{
   StpBridgePort *port;

   //Make sure the STP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Check the value of the parameter
   if(value > STP_MAX_PORT_PATH_COST)
      return ERROR_WRONG_VALUE;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != port->pathCost)
      {
         //The Path Cost parameter for the port is set to the new value
         port->pathCost = value;

         //The Configuration Update procedure is used
         stpConfigUpdate(context);
         //The Port State Selection procedure is used
         stpPortStateSelection(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the MAC address assigned to the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value MAC address of the individual MAC entity for the port
 * @return Error code
 **/

error_t stpMgmtGetPortAddr(StpBridgeContext *context, uint_t portIndex,
   MacAddr *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the MAC address of the individual MAC entity for the port
   *value = port->macAddr;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the priority assigned to the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port priority
 * @return Error code
 **/

error_t stpMgmtGetPortPriority(StpBridgeContext *context, uint_t portIndex,
   uint8_t *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the priority assigned to the port
   *value = (port->portId & STP_PORT_PRIORITY_MASK) >> 8;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the administrative port state
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Administrative port state
 * @return Error code
 **/

error_t stpMgmtGetAdminPortState(StpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the administrative port state
   *value = (port->state != STP_PORT_STATE_DISABLED) ? TRUE : FALSE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current MAC operational state
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value MAC operational state
 * @return Error code
 **/

error_t stpMgmtGetMacOperState(StpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the operational state of the MAC entity
   *value = port->macOperState;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current value of the port path cost
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port path cost
 * @return Error code
 **/

error_t stpMgmtGetPortPathCost(StpBridgeContext *context, uint_t portIndex,
   uint32_t *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the contribution of this port to the path cost of paths towards
   //the spanning tree root which include this port
   *value = port->pathCost;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current state of the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port state
 * @return Error code
 **/

error_t stpMgmtGetPortState(StpBridgeContext *context, uint_t portIndex,
   StpPortState *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the port's current state, as defined by application of the
   //Spanning Tree Protocol
   if(port->state == STP_PORT_STATE_DISABLED)
   {
      //Disabled represents exclusion of the port from the active topology by
      //management setting of the Administrative Port State to disabled
      *value = STP_PORT_STATE_DISABLED;
   }
   else if(!port->macOperState)
   {
      //The broken state represents the failure or unavailability of the port's
      //MAC as indicated by MAC_Operational FALSE
      *value = STP_PORT_STATE_BROKEN;
   }
   else if(port->state == STP_PORT_STATE_BLOCKING)
   {
      //Blocking represents exclusion of the port from the active topology by
      //the spanning tree algorithm
      *value = STP_PORT_STATE_BLOCKING;
   }
   else if(port->state == STP_PORT_STATE_LISTENING)
   {
      //Listening represents a port that the spanning tree algorithm has
      //selected to be part of the active topology (computing a Root or
      //Designated port role) but is temporarily discarding frames to guard
      //against loops or incorrect learning
      *value = STP_PORT_STATE_LISTENING;
   }
   else if(port->state == STP_PORT_STATE_LEARNING)
   {
      //Any port that has learning enabled but forwarding disabled has the
      //port state Learning
      *value = STP_PORT_STATE_LEARNING;
   }
   else if(port->state == STP_PORT_STATE_FORWARDING)
   {
      //A port that both learns and forwards frames has the port state
      //Forwarding
      *value = STP_PORT_STATE_FORWARDING;
   }
   else
   {
      //Just for sanity
      *value = STP_PORT_STATE_DISABLED;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned role of the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port role
 * @return Error code
 **/

error_t stpMgmtGetPortRole(StpBridgeContext *context, uint_t portIndex,
   StpPortRole *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the assigned port role
   if(port->state == STP_PORT_STATE_DISABLED)
   {
      //The port is disabled
      *value = STP_PORT_ROLE_DISABLED;
   }
   else if(stpRootPort(port))
   {
      //The port acts as Root port
      *value = STP_PORT_ROLE_ROOT;
   }
   else if(stpDesignatedPort(port))
   {
      //The port acts as Designated port
      *value = STP_PORT_ROLE_DESIGNATED;
   }
   else
   {
      //An alternate port acts as a backup port in a redundantly connected
      //bridged LAN
      *value = STP_PORT_ROLE_ALTERNATE;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the bridge identifier of the designated root bridge
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t stpMgmtGetPortDesignatedRoot(StpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the unique Bridge Identifier of the bridge recorded as the Root
   //in the Configuration BPDUs transmitted by the Designated Bridge for the
   //segment to which the port is attached
   *value = port->designatedRoot;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the designated cost of the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Designated cost of the port
 * @return Error code
 **/

error_t stpMgmtGetPortDesignatedCost(StpBridgeContext *context,
   uint_t portIndex, uint32_t *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the path cost of the Designated Port of the segment connected
   //to this port
   *value = port->designatedCost;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the bridge identifier of the designated bridge
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t stpMgmtGetPortDesignatedBridge(StpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the Bridge Identifier of the bridge that this port considers to
   //be the Designated Bridge for this port's segment
   *value = port->designatedBridge;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the port identifier of the designated bridge
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port identifier
 * @return Error code
 **/

error_t stpMgmtGetPortDesignatedPort(StpBridgeContext *context,
   uint_t portIndex, uint16_t *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the Port Identifier of the port on the Designated Bridge for
   //this port's segment
   *value = port->designatedPort;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the number of times the port has transitioned to Forwarding state
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Number of transitions to Forwarding state
 * @return Error code
 **/

error_t stpMgmtGetForwardTransitions(StpBridgeContext *context,
   uint_t portIndex, uint_t *value)
{
   StpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the number of times this port has transitioned from the Learning
   //state to the Forwarding state
   *value = port->forwardTransitions;

   //Successful processing
   return NO_ERROR;
}

#endif

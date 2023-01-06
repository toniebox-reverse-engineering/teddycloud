/**
 * @file rstp_mgmt.c
 * @brief Management of the RSTP bridge
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
#define TRACE_LEVEL RSTP_TRACE_LEVEL

//Dependencies
#include "rstp/rstp.h"
#include "rstp/rstp_fsm.h"
#include "rstp/rstp_conditions.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)


/**
 * @brief Set protocol version
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Protocol version
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetVersion(RstpBridgeContext *context, uint_t value,
   bool_t commit)
{
   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Check parameter
   if(value != STP_PROTOCOL_VERSION && value != RSTP_PROTOCOL_VERSION)
      return ERROR_WRONG_VALUE;

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->params.forceProtocolVersion)
      {
         //Set the Force Protocol Version variable
         context->params.forceProtocolVersion = value;

         //The Spanning Tree Protocol entity shall be reinitialized if the Force
         //Protocol Version is modified
         rstpFsmInit(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set bridge priority
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Bridge priority
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetBridgePriority(RstpBridgeContext *context, uint16_t value,
   bool_t commit)
{
   uint_t i;

   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Permissible values are 0-61440, in steps of 4096
   if(value > 61440 || (value % 4096) != 0)
      return ERROR_WRONG_VALUE;

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->bridgeId.priority)
      {
         //The Bridge Priority parameter is updated using the supplied value
         context->bridgeId.priority = value;

         //The first (RootBridgeID) and third (DesignatedBridgeID) components
         //of the bridge priority vector are both equal to the value of the
         //Bridge Identifier. The other components are zero
         context->bridgePriority.rootBridgeId = context->bridgeId;
         context->bridgePriority.rootPathCost = 0;
         context->bridgePriority.designatedBridgeId = context->bridgeId;
         context->bridgePriority.designatedPortId = 0;
         context->bridgePriority.bridgePortId = 0;

         //The spanning tree priority vectors and port role assignments for a
         //bridge shall be recomputed by clearing selected and setting reselect
         //(refer to IEEE Std 802.1D-2004, section 17.13)
         for(i = 0; i < context->numPorts; i++)
         {
            context->ports[i].selected = FALSE;
            context->ports[i].reselect = TRUE;
         }

         //Update RSTP state machine
         rstpFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set Bridge Max Age parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Value of the Bridge Max Age parameter, in seconds
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetBridgeMaxAge(RstpBridgeContext *context, uint_t value,
   bool_t commit)
{
   uint_t i;

   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //If the value of the Bridge Max Age is outside the specified range, then
   //no action shall be taken
   if(value < RSTP_MIN_BRIDGE_MAX_AGE || value > RSTP_MAX_BRIDGE_MAX_AGE)
      return ERROR_WRONG_VALUE;

   //To support interoperability with legacy bridges, a bridge shall enforce
   //the following relationships (refer to IEEE Std 802.1D-2004, section 17.14)
   if(!rstpCheckBridgeParams(value, context->params.bridgeHelloTime,
      context->params.bridgeForwardDelay))
   {
      return ERROR_INCONSISTENT_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->params.bridgeMaxAge)
      {
         //The Bridge Max Age parameter specifies the value that all bridges use
         //for MaxAge when this bridge is acting as the root
         context->params.bridgeMaxAge = value;
         context->bridgeTimes.maxAge = value;

         //Recompute the designatedTimes for each port
         for(i = 0; i < context->numPorts; i++)
         {
            context->ports[i].selected = FALSE;
            context->ports[i].reselect = TRUE;
         }

         //Update RSTP state machine
         rstpFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set Bridge Hello Time parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Value of the Bridge Hello Time parameter, in seconds
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetBridgeHelloTime(RstpBridgeContext *context, uint_t value,
   bool_t commit)
{
   uint_t i;

   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //If the value of the Bridge Hello Time is outside the specified range, then
   //no action shall be taken
   if(value < RSTP_MIN_BRIDGE_HELLO_TIME || value > RSTP_MAX_BRIDGE_HELLO_TIME)
      return ERROR_WRONG_VALUE;

   //To support interoperability with legacy bridges, a bridge shall enforce
   //the following relationship (refer to IEEE Std 802.1D-2004, section 17.14)
   if(!rstpCheckBridgeParams(context->params.bridgeMaxAge, value,
      context->params.bridgeForwardDelay))
   {
      return ERROR_INCONSISTENT_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->params.bridgeHelloTime)
      {
         //The Bridge Hello Time parameter specifies the value that all bridges
         //use for HelloTime when this bridge is acting as the root
         context->params.bridgeHelloTime = value;
         context->bridgeTimes.helloTime = value;

         //Recompute the designatedTimes for each port
         for(i = 0; i < context->numPorts; i++)
         {
            context->ports[i].selected = FALSE;
            context->ports[i].reselect = TRUE;
         }

         //Update RSTP state machine
         rstpFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set Bridge Forward Delay parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Value of the Bridge Forward Delay parameter, in seconds
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetBridgeForwardDelay(RstpBridgeContext *context, uint_t value,
   bool_t commit)
{
   uint_t i;

   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //If the value of the Bridge Forward Delay is outside the specified range,
   //then no action shall be taken
   if(value < RSTP_MIN_BRIDGE_FORWARD_DELAY ||
      value > RSTP_MAX_BRIDGE_FORWARD_DELAY)
   {
      return ERROR_WRONG_VALUE;
   }

   //To support interoperability with legacy bridges, a bridge shall enforce
   //the following relationship (refer to IEEE Std 802.1D-2004, section 17.14)
   if(!rstpCheckBridgeParams(context->params.bridgeMaxAge,
      context->params.bridgeHelloTime, value))
   {
      return ERROR_INCONSISTENT_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->params.bridgeForwardDelay)
      {
         //The Bridge Forward Delay parameter specifies the value that all
         //bridges use for ForwardDelay when this bridge is acting as the root
         context->params.bridgeForwardDelay = value;
         context->bridgeTimes.forwardDelay = value;

         //Recompute the designatedTimes for each port
         for(i = 0; i < context->numPorts; i++)
         {
            context->ports[i].selected = FALSE;
            context->ports[i].reselect = TRUE;
         }

         //Update RSTP state machine
         rstpFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set Transmit Hold Count parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Value of the Transmit Hold Count parameter
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetTxHoldCount(RstpBridgeContext *context, uint_t value,
   bool_t commit)
{
   uint_t i;

   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //If the value of the Transmit Hold Count is outside the specified range,
   //then no action shall be taken
   if(value < RSTP_MIN_TRANSMIT_HOLD_COUNT ||
      value > RSTP_MAX_TRANSMIT_HOLD_COUNT)
   {
      return ERROR_WRONG_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->params.transmitHoldCount)
      {
         //The Transmit Hold Count parameter specifies the value used by the
         //Port Transmit state machine to limit the maximum transmission rate
         context->params.transmitHoldCount = value;

         //If the Transmit Hold Count is modified the value of txCount for all
         //ports shall be set to zero (refer to IEEE Std 802.1D-2004, section
         //17.13)
         for(i = 0; i < context->numPorts; i++)
         {
            context->ports[i].txCount = 0;
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set Ageing Time parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Value of the Ageing Time parameter
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetAgeingTime(RstpBridgeContext *context, uint_t value,
   bool_t commit)
{
   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //If the value of the Ageing Time is outside the specified range, then no
   //action shall be taken
   if(value < RSTP_MIN_AGEING_TIME || value > RSTP_MAX_AGEING_TIME)
      return ERROR_WRONG_VALUE;

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != context->params.ageingTime)
      {
         //The Ageing Time parameter is updated using the supplied value
         context->params.ageingTime = value;

         //Check whether the rapid ageing timer is stopped
         if(context->rapidAgeingWhile == 0)
         {
            //The value of the ageingTime parameter is normally Ageing Time
            context->ageingTime = context->params.ageingTime;
            //Set ageing time for dynamic filtering entries
            rstpUpdateAgeingTime(context, context->ageingTime);
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the number of ports
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Number of ports
 * @return Error code
 **/

error_t rstpMgmtGetNumPorts(RstpBridgeContext *context, uint_t *value)
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
 * @brief Get assigned protocol version
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Protocol version
 * @return Error code
 **/

error_t rstpMgmtGetVersion(RstpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the version of Spanning Tree Protocol the bridge is currently
   //running
   *value = context->params.forceProtocolVersion;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the MAC address assigned to the bridge
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value MAC address of the bridge
 * @return Error code
 **/

error_t rstpMgmtGetBridgeAddr(RstpBridgeContext *context, MacAddr *value)
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Bridge priority
 * @return Error code
 **/

error_t rstpMgmtGetBridgePriority(RstpBridgeContext *context, uint16_t *value)
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Value of the Bridge Max Age parameter, in seconds
 * @return Error code
 **/

error_t rstpMgmtGetBridgeMaxAge(RstpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the value of the Bridge Max Age parameter
   *value = context->params.bridgeMaxAge;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned value of the Bridge Hello Time parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Value of the Bridge Hello Time parameter, in seconds
 * @return Error code
 **/

error_t rstpMgmtGetBridgeHelloTime(RstpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the value of the Bridge Hello Time parameter
   *value = context->params.bridgeHelloTime;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned value of the Bridge Forward Delay parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Value of the Bridge Forward Delay parameter, in seconds
 * @return Error code
 **/

error_t rstpMgmtGetBridgeForwardDelay(RstpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the value of the Bridge Forward Delay parameter
   *value = context->params.bridgeForwardDelay;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned value of the Transmit Hold Count parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Value of the Transmit Hold Count parameter
 * @return Error code
 **/

error_t rstpMgmtGetTxHoldCount(RstpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the value of the Transmit Hold Count parameter
   *value = context->params.transmitHoldCount;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the assigned value of the Ageing Time parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Value of the Ageing Time parameter
 * @return Error code
 **/

error_t rstpMgmtGetAgeingTime(RstpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the value of the Ageing Time parameter
   *value = context->params.ageingTime;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the bridge identifier of the root of the spanning tree
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t rstpMgmtGetDesignatedRoot(RstpBridgeContext *context, StpBridgeId *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the bridge identifier of the root of the spanning tree, as
   //determined by the Spanning Tree Protocol
   *value = context->rootPriority.rootBridgeId;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current cost of the path to the root
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Root path cost
 * @return Error code
 **/

error_t rstpMgmtGetRootPathCost(RstpBridgeContext *context, uint32_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the cost of the path to the root as seen from this bridge
   *value = context->rootPriority.rootPathCost;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current root port
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Port number
 * @return Error code
 **/

error_t rstpMgmtGetRootPort(RstpBridgeContext *context, uint16_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the port through which the path to the Root is established. This
   //value not significant when the bridge is the Root, and is set to zero
   *value = context->rootPortId & RSTP_PORT_NUM_MASK;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current Max Age value
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Max Age value, in seconds
 * @return Error code
 **/

error_t rstpMgmtGetMaxAge(RstpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the maximum age of Spanning Tree Protocol information learned
   //from the network on any port before it is discarded
   *value = context->rootTimes.maxAge;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current Hello Time value
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Hello Time value, in seconds
 * @return Error code
 **/

error_t rstpMgmtGetHelloTime(RstpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the amount of time between the transmission of Configuration
   //bridge PDUs by this node on any port when it is the root of the spanning
   //tree, or trying to become so
   *value = context->rootTimes.helloTime;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current Forward Delay value
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Forward Delay value, in seconds
 * @return Error code
 **/

error_t rstpMgmtGetForwardDelay(RstpBridgeContext *context, uint_t *value)
{
   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //The Forward Delay value determines how long the port stays in each of the
   //Listening and Learning states, which precede the Forwarding state
   *value = context->bridgeTimes.forwardDelay;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the number of topology changes
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Number of topology changes
 * @return Error code
 **/

error_t rstpMgmtGetTopologyChanges(RstpBridgeContext *context, uint_t *value)
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Time since a topology change was last detected
 * @return Error code
 **/

error_t rstpMgmtGetTimeSinceTopologyChange(RstpBridgeContext *context,
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Port priority
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetPortPriority(RstpBridgeContext *context, uint_t portIndex,
   uint8_t value, bool_t commit)
{
   RstpBridgePort *port;

   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Valid port priorities are in the range 0 through 240, in steps of 16
   if(value > 240 || (value % 16) != 0)
      return ERROR_WRONG_VALUE;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != ((port->portId & RSTP_PORT_PRIORITY_MASK) >> 8))
      {
         //The port identifier is updated using the supplied value
         port->portId = (port->portId & RSTP_PORT_NUM_MASK) | (value << 8);

         //The spanning tree priority vectors and port role assignments for
         //a bridge shall be recomputed by clearing selected and setting
         //reselect (refer to IEEE Std 802.1D-2004, section 17.13)
         port->selected = FALSE;
         port->reselect = TRUE;

         //Update RSTP state machine
         rstpFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set administrative bridge port state
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative bridge port state
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetAdminPortState(RstpBridgeContext *context, uint_t portIndex,
   bool_t value, bool_t commit)
{
   RstpBridgePort *port;

   //Make sure the RSTP bridge context is valid
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
      if(value != port->params.adminPortState)
      {
         //Update the administrative bridge port state
         port->params.adminPortState = value;

         //The portEnabled variable is set if the MAC entity can transmit and
         //receive frames to and from the attached LAN
         port->portEnabled = port->macOperState && port->params.adminPortState;

         //Update RSTP state machine
         rstpFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set administrative port path cost
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative port path cost
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetAdminPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t value, bool_t commit)
{
   RstpBridgePort *port;

   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Check the value of the parameter
   if(value > RSTP_MAX_PORT_PATH_COST)
      return ERROR_WRONG_VALUE;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != port->params.adminPathCost)
      {
         //The Admin Path Cost parameter is updated using the supplied value
         port->params.adminPathCost = value;

         //Writing a value of 0 assigns the automatically calculated default
         //Path Cost value to the port
         rstpUpdatePortPathCost(port);

         //The spanning tree priority vectors and port role assignments for
         //a bridge shall be recomputed by clearing selected and setting
         //reselect (refer to IEEE Std 802.1D-2004, section 17.13)
         port->selected = FALSE;
         port->reselect = TRUE;

         //Update RSTP state machine
         rstpFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set administrative point-to-point status of the LAN segment
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative point-to-point status of the LAN segment
 *   attached to this port
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetAdminPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, RstpAdminPointToPointMac value, bool_t commit)
{
   RstpBridgePort *port;

   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Check the value of the parameter
   if(value != RSTP_ADMIN_P2P_MAC_FORCE_TRUE &&
      value != RSTP_ADMIN_P2P_MAC_FORCE_FALSE &&
      value != RSTP_ADMIN_P2P_MAC_AUTO)
   {
      return ERROR_WRONG_VALUE;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Any parameter change?
      if(value != port->params.adminPointToPointMac)
      {
         //Set the administrative point-to-point status of the LAN segment
         //attached to this port
         port->params.adminPointToPointMac = value;

         //Update the value of the operPointToPointMac variable
         rstpUpdateOperPointToPointMac(port);

         //Update RSTP state machine
         rstpFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set administrative value of the Edge Port parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative value of the Edge Port parameter
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetAdminEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t value, bool_t commit)
{
   RstpBridgePort *port;

   //Make sure the RSTP bridge context is valid
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
      if(value != port->params.adminEdgePort)
      {
         //A value of true indicates that this port should be assumed as an
         //edge-port
         port->params.adminEdgePort = value;

         //Update RSTP state machine
         port->portEnabled = FALSE;
         rstpFsm(context);
         port->portEnabled = port->macOperState && port->params.adminPortState;
         rstpFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set AutoEdgePort parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value AutoEdgePort parameter for the port
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetAutoEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t value, bool_t commit)
{
   RstpBridgePort *port;

   //Make sure the RSTP bridge context is valid
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
      if(value != port->params.autoEdgePort)
      {
         //Each port be configured to automatically determine if it an edge port
         //by setting the AutoEdgePort parameter
         port->params.autoEdgePort = value;

         //Update RSTP state machine
         rstpFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Force protocol migration
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Value of the mcheck parameter. Setting mcheck variable to
 *   FALSE has no effect
 * @param[in] commit If this flag is TRUE, the bridge verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the bridge
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t rstpMgmtSetProtocolMigration(RstpBridgeContext *context, uint_t portIndex,
   bool_t value, bool_t commit)
{
   RstpBridgePort *port;

   //Make sure the RSTP bridge context is valid
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
      //Setting mcheck variable to FALSE has no effect
      if(value)
      {
         //Check whether the bridge is operating in STP compatibility mode
         if(stpVersion(context))
         {
            //Setting mcheck has no effect when stpVersion is TRUE (refer
            //IEEE Std 802.1D-2004, section 17.19.13)
         }
         else
         {
            //When operating in RSTP mode, writing true to this object forces
            //this port to transmit RSTP BPDUs
            port->mcheck = TRUE;

            //Update RSTP state machine
            rstpFsm(context);
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the MAC address assigned to the port
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value MAC address of the individual MAC entity for the port
 * @return Error code
 **/

error_t rstpMgmtGetPortAddr(RstpBridgeContext *context, uint_t portIndex,
   MacAddr *value)
{
   RstpBridgePort *port;

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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port priority
 * @return Error code
 **/

error_t rstpMgmtGetPortPriority(RstpBridgeContext *context, uint_t portIndex,
   uint8_t *value)
{
   RstpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the priority assigned to the port
   *value = (port->portId & RSTP_PORT_PRIORITY_MASK) >> 8;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the administrative port state
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Administrative port state
 * @return Error code
 **/

error_t rstpMgmtGetAdminPortState(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   RstpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the administrative port state
   *value = port->params.adminPortState;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current MAC operational state
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value MAC operational state
 * @return Error code
 **/

error_t rstpMgmtGetMacOperState(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   RstpBridgePort *port;

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
 * @brief Get the administrative port path cost
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Administrative port path cost
 * @return Error code
 **/

error_t rstpMgmtGetAdminPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t *value)
{
   RstpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the value of the Admin Path Cost parameter
   *value = port->params.adminPathCost;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current value of the port path cost
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port path cost
 * @return Error code
 **/

error_t rstpMgmtGetPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t *value)
{
   RstpBridgePort *port;

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
   *value = port->portPathCost;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the administrative point-to-point status of the LAN segment
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Administrative point-to-point status of the LAN segment
 *   attached to this port
 * @return Error code
 **/

error_t rstpMgmtGetAdminPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, RstpAdminPointToPointMac *value)
{
   RstpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the administrative point-to-point status of the LAN segment
   //attached to this port
   *value = port->params.adminPointToPointMac;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the operational point-to-point status of the LAN segment
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Operational point-to-point status of the LAN segment
 *   attached to this port
 * @return Error code
 **/

error_t rstpMgmtGetOperPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, bool_t *value)
{
   RstpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the operational point-to-point status of the LAN segment
   *value = port->operPointToPointMac;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the administrative value of the Edge Port parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Administrative value of the Edge Port parameter
 * @return Error code
 **/

error_t rstpMgmtGetAdminEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   RstpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //A value of true indicates that this port should be assumed as an edge-port
   *value = port->params.adminEdgePort;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the value of the AutoEdgePort parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Value of the AutoEdgePort parameter for the port
 * @return Error code
 **/

error_t rstpMgmtGetAutoEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   RstpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the value of the AutoEdgePort parameter
   *value = port->params.autoEdgePort;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the operational value of the Edge Port parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Operational value of the Edge Port parameter
 * @return Error code
 **/

error_t rstpMgmtGetOperEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   RstpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the operational value of the Edge Port parameter
   *value = port->operEdge;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current state of the port
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port state
 * @return Error code
 **/

error_t rstpMgmtGetPortState(RstpBridgeContext *context, uint_t portIndex,
   StpPortState *value)
{
   RstpBridgePort *port;

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
   if(port->pstState == RSTP_PST_STATE_DISCARDING)
   {
      //Disabled, blocking, listening, and broken all correspond to the
      //Discarding port state (refer to IEEE Std 802.1D-2004, section 17.4)
      if(!port->params.adminPortState)
      {
         //Disabled represents exclusion of the port from the active topology
         //by management setting of the Administrative Port State to disabled
         *value = STP_PORT_STATE_DISABLED;
      }
      else if(!port->macOperState)
      {
         //The broken state represents the failure or unavailability of
         //the port's MAC as indicated by MAC_Operational FALSE
         *value = STP_PORT_STATE_BROKEN;
      }
      else if(port->role == STP_PORT_ROLE_ALTERNATE ||
         port->role == STP_PORT_ROLE_BACKUP)
      {
         //Blocking represents exclusion of the port from the active topology
         //by the spanning tree algorithm (computing an Alternate or Backup
         //port role)
         *value = STP_PORT_STATE_BLOCKING;
      }
      else if(port->role == STP_PORT_ROLE_ROOT ||
         port->role == STP_PORT_ROLE_DESIGNATED)
      {
         //Listening represents a port that the spanning tree algorithm has
         //selected to be part of the active topology (computing a Root or
         //Designated port role) but is temporarily discarding frames to
         //guard against loops or incorrect learning
         *value = STP_PORT_STATE_LISTENING;
      }
      else
      {
         //Just for sanity
         *value = STP_PORT_STATE_DISABLED;
      }
   }
   else if(port->pstState == RSTP_PST_STATE_LEARNING)
   {
      //Any port that has learning enabled but forwarding disabled has the
      //port state Learning
      *value = STP_PORT_STATE_LEARNING;
   }
   else if(port->pstState == RSTP_PST_STATE_FORWARDING)
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port role
 * @return Error code
 **/

error_t rstpMgmtGetPortRole(RstpBridgeContext *context, uint_t portIndex,
   StpPortRole *value)
{
   RstpBridgePort *port;

   //Check parameters
   if(context == NULL || value == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the assigned port role
   *value = port->role;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the bridge identifier of the designated root bridge
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t rstpMgmtGetPortDesignatedRoot(RstpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value)
{
   RstpBridgePort *port;

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
   *value = port->portPriority.rootBridgeId;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the designated cost of the port
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Designated cost of the port
 * @return Error code
 **/

error_t rstpMgmtGetPortDesignatedCost(RstpBridgeContext *context,
   uint_t portIndex, uint32_t *value)
{
   RstpBridgePort *port;

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
   *value = port->portPriority.rootPathCost;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the bridge identifier of the designated bridge
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t rstpMgmtGetPortDesignatedBridge(RstpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value)
{
   RstpBridgePort *port;

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
   *value = port->portPriority.designatedBridgeId;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the port identifier of the designated bridge
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port identifier
 * @return Error code
 **/

error_t rstpMgmtGetPortDesignatedPort(RstpBridgeContext *context,
   uint_t portIndex, uint16_t *value)
{
   RstpBridgePort *port;

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
   *value = port->portPriority.designatedPortId;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the number of times the port has transitioned to Forwarding state
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Number of transitions to Forwarding state
 * @return Error code
 **/

error_t rstpMgmtGetForwardTransitions(RstpBridgeContext *context,
   uint_t portIndex, uint_t *value)
{
   RstpBridgePort *port;

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

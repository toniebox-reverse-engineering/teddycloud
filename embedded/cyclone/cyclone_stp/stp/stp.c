/**
 * @file stp.c
 * @brief STP (Spanning Tree Protocol)
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
#include "stp/stp_mgmt.h"
#include "stp/stp_procedures.h"
#include "stp/stp_conditions.h"
#include "stp/stp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (STP_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains STP bridge settings
 **/

void stpGetDefaultSettings(StpBridgeSettings *settings)
{
   //Underlying network interface
   settings->interface = NULL;

   //Number of ports
   settings->numPorts = 0;
   //Bridge's ports
   settings->ports = NULL;
}


/**
 * @brief Initialize STP bridge context
 * @param[in] context Pointer to the STP bridge context
 * @param[in] settings STP bridge specific settings
 * @return Error code
 **/

error_t stpInit(StpBridgeContext *context, StpBridgeSettings *settings)
{
   uint_t i;
   StpBridgePort *port;

   //Debug message
   TRACE_INFO("Initializing STP bridge...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //The bridge must be bound to a valid interface
   if(settings->interface == NULL)
      return ERROR_INVALID_PARAMETER;

   //Sanity check
   if(settings->numPorts < 1 || settings->ports == NULL)
      return ERROR_INVALID_PARAMETER;

   //Get exclusive access
   stpLock(context);

   //Clear STP bridge context
   osMemset(context, 0, sizeof(StpBridgeContext));

   //Initialize STP bridge context
   context->interface = settings->interface;
   context->bridgeId.addr = settings->interface->macAddr;
   context->bridgeId.priority = STP_DEFAULT_BRIDGE_PRIORITY;
   context->numPorts = settings->numPorts;
   context->ports = settings->ports;

   //Default bridge parameters
   context->bridgeMaxAge = STP_DEFAULT_BRIDGE_MAX_AGE;
   context->bridgeHelloTime = STP_DEFAULT_BRIDGE_HELLO_TIME;
   context->bridgeForwardDelay = STP_DEFAULT_BRIDGE_FORWARD_DELAY;
   context->holdTime = STP_DEFAULT_HOLD_TIME;
   context->ageingTime = STP_DEFAULT_AGEING_TIME;

   //The value of the Topology Change Time parameter is equal to the sum of the
   //values of the bridge's Bridge Max Age and Bridge Forward Delay parameters
   context->topologyChangeTime = context->bridgeMaxAge +
      context->bridgeForwardDelay;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //Attach STP bridge context to each port
      port->context = context;

      //Set port index
      port->portIndex = i + 1;
      //Default port identifier
      port->portId = (STP_DEFAULT_PORT_PRIORITY << 8) | port->portIndex;

      //Each port must assigned a unique MAC address
      stpGeneratePortAddr(port);

      //Default MAC operational state
      port->macOperState = FALSE;
      //Default port path cost
      port->pathCost = STP_DEFAULT_PORT_PATH_COST;
      //Default port state
      port->state = STP_PORT_STATE_DISABLED;
   }

   //Initialization procedure
   stpInitProc(context);

   //Release exclusive access
   stpUnlock(context);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start STP bridge operation
 * @param[in] context Pointer to the STP bridge context
 * @return Error code
 **/

error_t stpStart(StpBridgeContext *context)
{
   error_t error;
   NetInterface *interface;

   //Make sure the STP bridge context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting STP bridge...\r\n");

   //Get exclusive access
   stpLock(context);

   //Check RSTP bridge operation state
   if(!context->running)
   {
      //Point to the underlying network interface
      interface = context->interface;

      //Start of exception handling block
      do
      {
         //The Bridge Group Address is used as destination MAC address to
         //carry BPDUs between STP entities
         error = ethAcceptMacAddr(interface, &STP_BRIDGE_GROUP_ADDR);
         //Any error to report?
         if(error)
            break;

         //Configure the permanent database
         error = stpConfigurePermanentDatabase(context);
         //Any error to report?
         if(error)
            break;

         //Register a callback to process incoming LLC frames
         error = ethAttachLlcRxCalback(interface, stpProcessLlcFrame, context);
         //Any error to report?
         if(error)
            break;

         //Register timer callback
         error = netAttachTimerCallback(STP_TICK_INTERVAL,
            (NetTimerCallback) stpTick, context);
         //Any error to report?
         if(error)
            break;

         //The STP bridge is now running
         context->running = TRUE;
         //Initialization procedure
         stpInitProc(context);

         //End of exception handling block
      } while(0);

      //Check status code
      if(error)
      {
         //Clean up side effects
         ethDropMacAddr(interface, &STP_BRIDGE_GROUP_ADDR);
         stpUnconfigurePermanentDatabase(context);
         ethDetachLlcRxCalback(interface);
         netDetachTimerCallback((NetTimerCallback) stpTick, context);
      }
   }
   else
   {
      //The STP bridge is already running
      error = ERROR_ALREADY_RUNNING;
   }

   //Release exclusive access
   stpUnlock(context);

   //Return status code
   return error;
}


/**
 * @brief Stop STP bridge operation
 * @param[in] context Pointer to the STP bridge context
 * @return Error code
 **/

error_t stpStop(StpBridgeContext *context)
{
   uint_t i;
   NetInterface *interface;

   //Make sure the STP bridge context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping STP bridge...\r\n");

   //Get exclusive access
   stpLock(context);

   //Check RSTP bridge operation state
   if(context->running)
   {
      //Point to the underlying network interface
      interface = context->interface;

      //Remove the Bridge Group Address from the MAC filter table
      ethDropMacAddr(interface, &STP_BRIDGE_GROUP_ADDR);
      //Unconfigure the permanent database
      stpUnconfigurePermanentDatabase(context);

      //Unregister LLC receive callback function
      ethDetachLlcRxCalback(interface);
      //Unregister timer callback
      netDetachTimerCallback((NetTimerCallback) stpTick, context);

      //Restore default ageing time
      stpUpdateAgeingTime(context, STP_DEFAULT_AGEING_TIME);

      //Loop through the ports of the bridge
      for(i = 0; i < context->numPorts; i++)
      {
         //Restore default port state
         stpUpdatePortState(&context->ports[i], STP_PORT_STATE_FORWARDING);
      }

      //The STP bridge is not running anymore
      context->running = FALSE;
   }

   //Release exclusive access
   stpUnlock(context);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set bridge priority
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Bridge priority
 * @return Error code
 **/

error_t stpSetBridgePriority(StpBridgeContext *context, uint16_t value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtSetBridgePriority(context, value, TRUE);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set Bridge Max Age parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Value of the Bridge Max Age parameter, in seconds
 * @return Error code
 **/

error_t stpSetBridgeMaxAge(StpBridgeContext *context, uint_t value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtSetBridgeMaxAge(context, value, TRUE);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set Bridge Hello Time parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Value of the Bridge Hello Time parameter, in seconds
 * @return Error code
 **/

error_t stpSetBridgeHelloTime(StpBridgeContext *context, uint_t value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtSetBridgeHelloTime(context, value, TRUE);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set Bridge Forward Delay parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Value of the Bridge Forward Delay parameter, in seconds
 * @return Error code
 **/

error_t stpSetBridgeForwardDelay(StpBridgeContext *context, uint_t value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtSetBridgeForwardDelay(context, value, TRUE);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set Ageing Time parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Value of the Ageing Time parameter
 * @return Error code
 **/

error_t stpSetAgeingTime(StpBridgeContext *context, uint_t value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtSetAgeingTime(context, value, TRUE);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the number of ports
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Number of ports
 * @return Error code
 **/

error_t stpGetNumPorts(StpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetNumPorts(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the MAC address assigned to the bridge
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value MAC address of the bridge
 * @return Error code
 **/

error_t stpGetBridgeAddr(StpBridgeContext *context, MacAddr *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetBridgeAddr(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the assigned bridge priority
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Bridge priority
 * @return Error code
 **/

error_t stpGetBridgePriority(StpBridgeContext *context, uint16_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetBridgePriority(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the assigned value of the Bridge Max Age parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Value of the Bridge Max Age parameter, in seconds
 * @return Error code
 **/

error_t stpGetBridgeMaxAge(StpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetBridgeMaxAge(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the assigned value of the Bridge Hello Time parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Value of the Bridge Hello Time parameter, in seconds
 * @return Error code
 **/

error_t stpGetBridgeHelloTime(StpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetBridgeHelloTime(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the assigned value of the Bridge Forward Delay parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Value of the Bridge Forward Delay parameter, in seconds
 * @return Error code
 **/

error_t stpGetBridgeForwardDelay(StpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetBridgeForwardDelay(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the assigned value of the Hold Time parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Value of the Transmit Hold Count parameter
 * @return Error code
 **/

error_t stpGetHoldTime(StpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetHoldTime(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the assigned value of the Ageing Time parameter
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Value of the Ageing Time parameter
 * @return Error code
 **/

error_t stpGetAgeingTime(StpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetAgeingTime(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the bridge identifier of the root of the spanning tree
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t stpGetDesignatedRoot(StpBridgeContext *context, StpBridgeId *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetDesignatedRoot(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the current cost of the path to the root
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Root path cost
 * @return Error code
 **/

error_t stpGetRootPathCost(StpBridgeContext *context, uint32_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetRootPathCost(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the current root port
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Port number
 * @return Error code
 **/

error_t stpGetRootPort(StpBridgeContext *context, uint16_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetRootPort(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the current Max Age value
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Max Age value, in seconds
 * @return Error code
 **/

error_t stpGetMaxAge(StpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetMaxAge(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the current Hello Time value
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Hello Time value, in seconds
 * @return Error code
 **/

error_t stpGetHelloTime(StpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetHelloTime(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the current Forward Delay value
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Forward Delay value, in seconds
 * @return Error code
 **/

error_t stpGetForwardDelay(StpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetForwardDelay(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the number of topology changes
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Number of topology changes
 * @return Error code
 **/

error_t stpGetTopologyChanges(StpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetTopologyChanges(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the time since a topology change was last detected
 * @param[in] context Pointer to the STP bridge context
 * @param[out] value Time since a topology change was last detected
 * @return Error code
 **/

error_t stpGetTimeSinceTopologyChange(StpBridgeContext *context,
   uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetTimeSinceTopologyChange(context, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set port number
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Port number
 * @return Error code
 **/

error_t stpSetPortNum(StpBridgeContext *context, uint_t portIndex,
   uint16_t value)
{
   error_t error;
   StpBridgePort *port;

   //Initialize status code
   error = NO_ERROR;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);

      //Valid port index?
      if(portIndex >= 1 && portIndex <= context->numPorts)
      {
         //Point to the port that matches the specified port index
         port = &context->ports[portIndex - 1];

         //Check the value of the parameter
         if(value <= 255)
         {
            //The port identifier is updated using the supplied value
            port->portId = (port->portId & STP_PORT_PRIORITY_MASK) | value;
         }
         else
         {
            //The parameter value is not valid
            error = ERROR_INVALID_VALUE;
         }
      }
      else
      {
         //The port index is out of range
         error = ERROR_INVALID_PORT;
      }

      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set port address
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[in] value MAC address of the individual MAC entity for the port
 * @return Error code
 **/

error_t stpSetPortAddr(StpBridgeContext *context, uint_t portIndex,
   const MacAddr *value)
{
   error_t error;
   StpBridgePort *port;

   //Initialize status code
   error = NO_ERROR;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);

      //Valid port index?
      if(portIndex >= 1 && portIndex <= context->numPorts)
      {
         //Point to the port that matches the specified port index
         port = &context->ports[portIndex - 1];
         //Set the MAC address of the individual MAC entity for the port
         port->macAddr = *value;
      }
      else
      {
         //The port index is out of range
         error = ERROR_INVALID_PORT;
      }

      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set port priority
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Port priority
 * @return Error code
 **/

error_t stpSetPortPriority(StpBridgeContext *context, uint_t portIndex,
   uint8_t value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtSetPortPriority(context, portIndex, value, TRUE);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set administrative bridge port state
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative bridge port state
 * @return Error code
 **/

error_t stpSetAdminPortState(StpBridgeContext *context, uint_t portIndex,
   bool_t value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtSetAdminPortState(context, portIndex, value, TRUE);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set administrative port path cost
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative port path cost
 * @return Error code
 **/

error_t stpSetPortPathCost(StpBridgeContext *context, uint_t portIndex,
   uint32_t value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtSetPortPathCost(context, portIndex, value, TRUE);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the port number assigned to the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port number
 * @return Error code
 **/

error_t stpGetPortNum(StpBridgeContext *context, uint_t portIndex,
   uint16_t *value)
{
   error_t error;
   StpBridgePort *port;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);

      //Valid port index?
      if(portIndex >= 1 && portIndex <= context->numPorts)
      {
         //Point to the port that matches the specified port index
         port = &context->ports[portIndex - 1];
         //Retrieve the assigned port number
         *value = port->portId & STP_PORT_NUM_MASK;
      }
      else
      {
         //The port index is out of range
         error = ERROR_INVALID_PORT;
      }

      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the MAC address assigned to the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value MAC address of the individual MAC entity for the port
 * @return Error code
 **/

error_t stpGetPortAddr(StpBridgeContext *context, uint_t portIndex,
   MacAddr *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetPortAddr(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the priority assigned to the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port priority
 * @return Error code
 **/

error_t stpGetPortPriority(StpBridgeContext *context, uint_t portIndex,
   uint8_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetPortPriority(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the administrative port state
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Administrative port state
 * @return Error code
 **/

error_t stpGetAdminPortState(StpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetAdminPortState(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the current MAC operational state
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value MAC operational state
 * @return Error code
 **/

error_t stpGetMacOperState(StpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetMacOperState(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the current value of the port path cost
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port path cost
 * @return Error code
 **/

error_t stpGetPortPathCost(StpBridgeContext *context, uint_t portIndex,
   uint32_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetPortPathCost(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the current state of the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port state
 * @return Error code
 **/

error_t stpGetPortState(StpBridgeContext *context, uint_t portIndex,
   StpPortState *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetPortState(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the assigned role of the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port role
 * @return Error code
 **/

error_t stpGetPortRole(StpBridgeContext *context, uint_t portIndex,
   StpPortRole *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetPortRole(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the bridge identifier of the designated root bridge
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t stpGetPortDesignatedRoot(StpBridgeContext *context, uint_t portIndex,
   StpBridgeId *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetPortDesignatedRoot(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the designated cost of the port
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Designated cost of the port
 * @return Error code
 **/

error_t stpGetPortDesignatedCost(StpBridgeContext *context, uint_t portIndex,
   uint32_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetPortDesignatedCost(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the bridge identifier of the designated bridge
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t stpGetPortDesignatedBridge(StpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetPortDesignatedBridge(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the port identifier of the designated bridge
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port identifier
 * @return Error code
 **/

error_t stpGetPortDesignatedPort(StpBridgeContext *context, uint_t portIndex,
   uint16_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetPortDesignatedPort(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the number of times the port has transitioned to Forwarding state
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Number of transitions to Forwarding state
 * @return Error code
 **/

error_t stpGetForwardTransitions(StpBridgeContext *context, uint_t portIndex,
   uint_t *value)
{
   error_t error;

   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the STP bridge context
      stpLock(context);
      //Perform management operation
      error = stpMgmtGetForwardTransitions(context, portIndex, value);
      //Release exclusive access to the STP bridge context
      stpUnlock(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Release STP bridge context
 * @param[in] context Pointer to the STP bridge context
 **/

void stpDeinit(StpBridgeContext *context)
{
   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      //Clear STP bridge context
      osMemset(context, 0, sizeof(StpBridgeContext));
   }
}

#endif

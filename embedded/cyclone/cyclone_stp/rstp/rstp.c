/**
 * @file rstp.c
 * @brief RSTP (Rapid Spanning Tree Protocol)
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
#include "rstp/rstp_mgmt.h"
#include "rstp/rstp_fsm.h"
#include "rstp/rstp_conditions.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains RSTP bridge settings
 **/

void rstpGetDefaultSettings(RstpBridgeSettings *settings)
{
   //Underlying network interface
   settings->interface = NULL;

   //Number of ports
   settings->numPorts = 0;
   //Bridge's ports
   settings->ports = NULL;
}


/**
 * @brief Initialize RSTP bridge context
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] settings RSTP bridge specific settings
 * @return Error code
 **/

error_t rstpInit(RstpBridgeContext *context, RstpBridgeSettings *settings)
{
   uint_t i;
   RstpBridgePort *port;

   //Debug message
   TRACE_INFO("Initializing RSTP bridge...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //The bridge must be bound to a valid interface
   if(settings->interface == NULL)
      return ERROR_INVALID_PARAMETER;

   //Sanity check
   if(settings->numPorts < 1 || settings->ports == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear RSTP bridge context
   osMemset(context, 0, sizeof(RstpBridgeContext));

   //Initialize RSTP bridge context
   context->interface = settings->interface;
   context->bridgeId.addr = settings->interface->macAddr;
   context->bridgeId.priority = RSTP_DEFAULT_BRIDGE_PRIORITY;
   context->numPorts = settings->numPorts;
   context->ports = settings->ports;

   //Default bridge parameters
   context->params.forceProtocolVersion = RSTP_PROTOCOL_VERSION;
   context->params.migrateTime = RSTP_DEFAULT_MIGRATE_TIME;
   context->params.bridgeMaxAge = RSTP_DEFAULT_BRIDGE_MAX_AGE;
   context->params.bridgeHelloTime = RSTP_DEFAULT_BRIDGE_HELLO_TIME;
   context->params.bridgeForwardDelay = RSTP_DEFAULT_BRIDGE_FORWARD_DELAY;
   context->params.transmitHoldCount = RSTP_DEFAULT_TRANSMIT_HOLD_COUNT;
   context->params.ageingTime = RSTP_DEFAULT_AGEING_TIME;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //Attach RSTP bridge context to each port
      port->context = context;

      //Set port index
      port->portIndex = i + 1;
      //Default port identifier
      port->portId = (RSTP_DEFAULT_PORT_PRIORITY << 8) | port->portIndex;

      //Each port must assigned a unique MAC address
      rstpGeneratePortAddr(port);

      //Default port parameters
      port->params.adminPortState = FALSE;
      port->params.adminPathCost = RSTP_DEFAULT_PORT_PATH_COST;
      port->params.adminPointToPointMac = RSTP_ADMIN_P2P_MAC_FORCE_TRUE;
      port->params.adminEdgePort = FALSE;
      port->params.autoEdgePort = TRUE;

      //Default operation mode
      port->macOperState = FALSE;
      port->linkSpeed = NIC_LINK_SPEED_UNKNOWN;
      port->duplexMode = NIC_UNKNOWN_DUPLEX_MODE;

      //The portEnabled variable is set if the MAC entity can transmit and
      //receive frames to and from the attached LAN
      port->portEnabled = port->macOperState && port->params.adminPortState;

      //Recalculate the contribution of the port to the root path cost
      rstpUpdatePortPathCost(port);

      //The MAC is considered to be connected to a point-to-point LAN if the
      //MAC entity is configured for full duplex operation
      rstpUpdateOperPointToPointMac(port);
   }

   //Get exclusive access
   rstpLock(context);
   //Initialize RSTP state machine
   rstpFsmInit(context);
   //Release exclusive access
   rstpUnlock(context);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start RSTP bridge operation
 * @param[in] context Pointer to the RSTP bridge context
 * @return Error code
 **/

error_t rstpStart(RstpBridgeContext *context)
{
   error_t error;
   NetInterface *interface;

   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting RSTP bridge...\r\n");

   //Get exclusive access
   rstpLock(context);

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
         error = ethAcceptMacAddr(interface, &RSTP_BRIDGE_GROUP_ADDR);
         //Any error to report?
         if(error)
            break;

         //Configure the permanent database
         error = rstpConfigurePermanentDatabase(context);
         //Any error to report?
         if(error)
            break;

         //Register a callback to process incoming LLC frames
         error = ethAttachLlcRxCalback(interface, rstpProcessLlcFrame,
            context);
         //Any error to report?
         if(error)
            break;

         //Register timer callback
         error = netAttachTimerCallback(RSTP_TICK_INTERVAL,
            (NetTimerCallback) rstpTick, context);
         //Any error to report?
         if(error)
            break;

         //The RSTP bridge is now running
         context->running = TRUE;
         //Reinitialize RSTP state machine
         rstpFsmInit(context);

         //End of exception handling block
      } while(0);

      //Check status code
      if(error)
      {
         //Clean up side effects
         ethDropMacAddr(interface, &RSTP_BRIDGE_GROUP_ADDR);
         rstpUnconfigurePermanentDatabase(context);
         ethDetachLlcRxCalback(interface);
         netDetachTimerCallback((NetTimerCallback) rstpTick, context);
      }
   }
   else
   {
      //The RSTP bridge is already running
      error = ERROR_ALREADY_RUNNING;
   }

   //Release exclusive access
   rstpUnlock(context);

   //Return status code
   return error;
}


/**
 * @brief Stop RSTP bridge operation
 * @param[in] context Pointer to the RSTP bridge context
 * @return Error code
 **/

error_t rstpStop(RstpBridgeContext *context)
{
   uint_t i;
   NetInterface *interface;

   //Make sure the RSTP bridge context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping RSTP bridge...\r\n");

   //Get exclusive access
   rstpLock(context);

   //Check RSTP bridge operation state
   if(context->running)
   {
      //Point to the underlying network interface
      interface = context->interface;

      //Remove the Bridge Group Address from the MAC filter table
      ethDropMacAddr(interface, &RSTP_BRIDGE_GROUP_ADDR);
      //Unconfigure the permanent database
      rstpUnconfigurePermanentDatabase(context);

      //Unregister LLC receive callback function
      ethDetachLlcRxCalback(interface);
      //Unregister timer callback
      netDetachTimerCallback((NetTimerCallback) rstpTick, context);

      //Restore default ageing time
      rstpUpdateAgeingTime(context, RSTP_DEFAULT_AGEING_TIME);

      //Loop through the ports of the bridge
      for(i = 0; i < context->numPorts; i++)
      {
         //Restore default port state
         rstpUpdatePortState(&context->ports[i], SWITCH_PORT_STATE_FORWARDING);
      }

      //The RSTP bridge is not running anymore
      context->running = FALSE;
   }

   //Release exclusive access
   rstpUnlock(context);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set protocol version
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Protocol version
 * @return Error code
 **/

error_t rstpSetVersion(RstpBridgeContext *context, uint_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetVersion(context, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Set bridge priority
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Bridge priority
 * @return Error code
 **/

error_t rstpSetBridgePriority(RstpBridgeContext *context, uint16_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetBridgePriority(context, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Value of the Bridge Max Age parameter, in seconds
 * @return Error code
 **/

error_t rstpSetBridgeMaxAge(RstpBridgeContext *context, uint_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetBridgeMaxAge(context, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Value of the Bridge Hello Time parameter, in seconds
 * @return Error code
 **/

error_t rstpSetBridgeHelloTime(RstpBridgeContext *context, uint_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetBridgeHelloTime(context, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Value of the Bridge Forward Delay parameter, in seconds
 * @return Error code
 **/

error_t rstpSetBridgeForwardDelay(RstpBridgeContext *context, uint_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetBridgeForwardDelay(context, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Set Transmit Hold Count parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Value of the Transmit Hold Count parameter
 * @return Error code
 **/

error_t rstpSetTxHoldCount(RstpBridgeContext *context, uint_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetTxHoldCount(context, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] value Value of the Ageing Time parameter
 * @return Error code
 **/

error_t rstpSetAgeingTime(RstpBridgeContext *context, uint_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetAgeingTime(context, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Number of ports
 * @return Error code
 **/

error_t rstpGetNumPorts(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetNumPorts(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Get assigned protocol version
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Protocol version
 * @return Error code
 **/

error_t rstpGetVersion(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetVersion(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value MAC address of the bridge
 * @return Error code
 **/

error_t rstpGetBridgeAddr(RstpBridgeContext *context, MacAddr *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetBridgeAddr(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Bridge priority
 * @return Error code
 **/

error_t rstpGetBridgePriority(RstpBridgeContext *context, uint16_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetBridgePriority(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Value of the Bridge Max Age parameter, in seconds
 * @return Error code
 **/

error_t rstpGetBridgeMaxAge(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetBridgeMaxAge(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Value of the Bridge Hello Time parameter, in seconds
 * @return Error code
 **/

error_t rstpGetBridgeHelloTime(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetBridgeHelloTime(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Value of the Bridge Forward Delay parameter, in seconds
 * @return Error code
 **/

error_t rstpGetBridgeForwardDelay(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetBridgeForwardDelay(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Get the assigned value of the Transmit Hold Count parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Value of the Transmit Hold Count parameter
 * @return Error code
 **/

error_t rstpGetTxHoldCount(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetTxHoldCount(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Value of the Ageing Time parameter
 * @return Error code
 **/

error_t rstpGetAgeingTime(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetAgeingTime(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t rstpGetDesignatedRoot(RstpBridgeContext *context, StpBridgeId *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetDesignatedRoot(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Root path cost
 * @return Error code
 **/

error_t rstpGetRootPathCost(RstpBridgeContext *context, uint32_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetRootPathCost(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Port number
 * @return Error code
 **/

error_t rstpGetRootPort(RstpBridgeContext *context, uint16_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetRootPort(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Max Age value, in seconds
 * @return Error code
 **/

error_t rstpGetMaxAge(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetMaxAge(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Hello Time value, in seconds
 * @return Error code
 **/

error_t rstpGetHelloTime(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetHelloTime(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Forward Delay value, in seconds
 * @return Error code
 **/
error_t rstpGetForwardDelay(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetForwardDelay(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Number of topology changes
 * @return Error code
 **/

error_t rstpGetTopologyChanges(RstpBridgeContext *context, uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetTopologyChanges(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[out] value Time since a topology change was last detected
 * @return Error code
 **/

error_t rstpGetTimeSinceTopologyChange(RstpBridgeContext *context,
   uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetTimeSinceTopologyChange(context, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Port number
 * @return Error code
 **/

error_t rstpSetPortNum(RstpBridgeContext *context, uint_t portIndex,
   uint16_t value)
{
   error_t error;
   RstpBridgePort *port;

   //Initialize status code
   error = NO_ERROR;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);

      //Valid port index?
      if(portIndex >= 1 && portIndex <= context->numPorts)
      {
         //Point to the port that matches the specified port index
         port = &context->ports[portIndex - 1];

         //Check the value of the parameter
         if(value <= 4095)
         {
            //The port identifier is updated using the supplied value
            port->portId = (port->portId & RSTP_PORT_PRIORITY_MASK) | value;
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

      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value MAC address of the individual MAC entity for the port
 * @return Error code
 **/

error_t rstpSetPortAddr(RstpBridgeContext *context, uint_t portIndex,
   const MacAddr *value)
{
   error_t error;
   RstpBridgePort *port;

   //Initialize status code
   error = NO_ERROR;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);

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

      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Port priority
 * @return Error code
 **/

error_t rstpSetPortPriority(RstpBridgeContext *context, uint_t portIndex,
   uint8_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetPortPriority(context, portIndex, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative bridge port state
 * @return Error code
 **/

error_t rstpSetAdminPortState(RstpBridgeContext *context, uint_t portIndex,
   bool_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetAdminPortState(context, portIndex, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative port path cost
 * @return Error code
 **/

error_t rstpSetAdminPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetAdminPortPathCost(context, portIndex, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Set administrative point-to-point status of the LAN segment
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative point-to-point status of the LAN segment
 *   attached to this port
 * @return Error code
 **/

error_t rstpSetAdminPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, RstpAdminPointToPointMac value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetAdminPointToPointMac(context, portIndex, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Set administrative value of the Edge Port parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Administrative value of the Edge Port parameter
 * @return Error code
 **/

error_t rstpSetAdminEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetAdminEdgePort(context, portIndex, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Set AutoEdgePort parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value AutoEdgePort parameter for the port
 * @return Error code
 **/

error_t rstpSetAutoEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetAutoEdgePort(context, portIndex, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Force protocol migration
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[in] value Value of the mcheck parameter. Setting mcheck variable to
 *   FALSE has no effect
 * @return Error code
 **/

error_t rstpSetProtocolMigration(RstpBridgeContext *context, uint_t portIndex,
   bool_t value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtSetProtocolMigration(context, portIndex, value, TRUE);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port number
 * @return Error code
 **/

error_t rstpGetPortNum(RstpBridgeContext *context, uint_t portIndex,
   uint16_t *value)
{
   error_t error;
   RstpBridgePort *port;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);

      //Valid port index?
      if(portIndex >= 1 && portIndex <= context->numPorts)
      {
         //Point to the port that matches the specified port index
         port = &context->ports[portIndex - 1];
         //Retrieve the assigned port number
         *value = port->portId & RSTP_PORT_NUM_MASK;
      }
      else
      {
         //The port index is out of range
         error = ERROR_INVALID_PORT;
      }

      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value MAC address of the individual MAC entity for the port
 * @return Error code
 **/

error_t rstpGetPortAddr(RstpBridgeContext *context, uint_t portIndex,
   MacAddr *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetPortAddr(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port priority
 * @return Error code
 **/

error_t rstpGetPortPriority(RstpBridgeContext *context, uint_t portIndex,
   uint8_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetPortPriority(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Administrative port state
 * @return Error code
 **/

error_t rstpGetAdminPortState(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetAdminPortState(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value MAC operational state
 * @return Error code
 **/

error_t rstpGetMacOperState(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetMacOperState(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Get the administrative port path cost
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Administrative port path cost
 * @return Error code
 **/

error_t rstpGetAdminPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetAdminPortPathCost(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port path cost
 * @return Error code
 **/

error_t rstpGetPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetPortPathCost(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Get the administrative point-to-point status of the LAN segment
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Administrative point-to-point status of the LAN segment
 *   attached to this port
 * @return Error code
 **/

error_t rstpGetAdminPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, RstpAdminPointToPointMac *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetAdminPointToPointMac(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Get the operational point-to-point status of the LAN segment
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Operational point-to-point status of the LAN segment
 *   attached to this port
 * @return Error code
 **/

error_t rstpGetOperPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, bool_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetOperPointToPointMac(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Get the administrative value of the Edge Port parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Administrative value of the Edge Port parameter
 * @return Error code
 **/

error_t rstpGetAdminEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetAdminEdgePort(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Get the value of the AutoEdgePort parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Value of the AutoEdgePort parameter for the port
 * @return Error code
 **/

error_t rstpGetAutoEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetAutoEdgePort(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Get the operational value of the Edge Port parameter
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Operational value of the Edge Port parameter
 * @return Error code
 **/

error_t rstpGetOperEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetOperEdgePort(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port state
 * @return Error code
 **/

error_t rstpGetPortState(RstpBridgeContext *context, uint_t portIndex,
   StpPortState *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetPortState(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port role
 * @return Error code
 **/

error_t rstpGetPortRole(RstpBridgeContext *context, uint_t portIndex,
   StpPortRole *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetPortRole(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t rstpGetPortDesignatedRoot(RstpBridgeContext *context, uint_t portIndex,
   StpBridgeId *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetPortDesignatedRoot(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Designated cost of the port
 * @return Error code
 **/

error_t rstpGetPortDesignatedCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetPortDesignatedCost(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Bridge identifier
 * @return Error code
 **/

error_t rstpGetPortDesignatedBridge(RstpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetPortDesignatedBridge(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Port identifier
 * @return Error code
 **/

error_t rstpGetPortDesignatedPort(RstpBridgeContext *context, uint_t portIndex,
   uint16_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetPortDesignatedPort(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portIndex Port index
 * @param[out] value Number of transitions to Forwarding state
 * @return Error code
 **/

error_t rstpGetForwardTransitions(RstpBridgeContext *context, uint_t portIndex,
   uint_t *value)
{
   error_t error;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the RSTP bridge context
      rstpLock(context);
      //Perform management operation
      error = rstpMgmtGetForwardTransitions(context, portIndex, value);
      //Release exclusive access to the RSTP bridge context
      rstpUnlock(context);
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
 * @brief Release RSTP bridge context
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpDeinit(RstpBridgeContext *context)
{
   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Clear RSTP bridge context
      osMemset(context, 0, sizeof(RstpBridgeContext));
   }
}

#endif

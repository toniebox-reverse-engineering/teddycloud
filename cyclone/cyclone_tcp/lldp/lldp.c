/**
 * @file lldp.c
 * @brief LLDP (Link Layer Discovery Protocol)
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
#define TRACE_LEVEL LLDP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"
#include "lldp/lldp_mgmt.h"
#include "lldp/lldp_fsm.h"
#include "lldp/lldp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains LLDP agent settings
 **/

void lldpGetDefaultSettings(LldpAgentSettings *settings)
{
   //Use default interface
   settings->interface = netGetDefaultInterface();

   //Number of ports
   settings->numPorts = 0;
   //Port table
   settings->ports = NULL;

   //Maximum number of entries in the neighbor table
   settings->numNeighbors = 0;
   //Neighbor table
   settings->neighbors = NULL;

   //LLDP frame transmission callback function
   settings->sendCallback = NULL;
   //LLDP frame reception callback function
   settings->receiveCallback = NULL;
   //Tick callback function
   settings->tickCallback = NULL;
}


/**
 * @brief LLDP agent initialization
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] settings LLDP agent specific settings
 * @return Error code
 **/

error_t lldpInit(LldpAgentContext *context,
   const LldpAgentSettings *settings)
{
   error_t error;
   uint_t i;
   size_t n;
   LldpPortEntry *port;
   LldpChassisIdTlv *chassisIdTlv;
   LldpPortIdTlv *portIdTlv;

   //Debug message
   TRACE_INFO("Initializing LLDP agent...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //The LLDP agent must be bound to a valid interface
   if(settings->interface == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the port table
   if(settings->numPorts == 0 || settings->ports == NULL)
      return ERROR_INVALID_PARAMETER;

   //The neighbor table is not used in TX-only mode
   if(settings->numNeighbors != 0 && settings->neighbors == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the LLDP agent context
   osMemset(context, 0, sizeof(LldpAgentContext));

   //Initialize LLDP agent context
   context->interface = settings->interface;
   context->numPorts = settings->numPorts;
   context->ports = settings->ports;
   context->numNeighbors = settings->numNeighbors;
   context->neighbors = settings->neighbors;
   context->sendCallback = settings->sendCallback;
   context->receiveCallback = settings->receiveCallback;
   context->tickCallback = settings->tickCallback;

#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //Appropriate values shall be set for the timing parameters
   context->reinitDelay = LLDP_DEFAULT_REINIT_DELAY;
   context->msgTxHold = LLDP_DEFAULT_MSG_TX_HOLD;
   context->msgTxInterval = LLDP_DEFAULT_MSG_TX_INTERVAL;
   context->txDelay = LLDP_DEFAULT_TX_DELAY;

   //Initialize local system MIB
   lldpSetTlv(&context->txInfo, LLDP_TLV_TYPE_END_OF_LLDPDU, 0, NULL, 0, TRUE);

   //Point to the buffer where to format the Chassis ID TLV
   chassisIdTlv = (LldpChassisIdTlv *) context->lldpdu.data;

   //By default, the chassis ID is the MAC address of the underlying interface
   chassisIdTlv->chassisIdSubtype = LLDP_CHASSIS_ID_SUBTYPE_MAC_ADDR;
   macCopyAddr(chassisIdTlv->chassisId, &context->interface->macAddr);

   //Set the value of the Chassis ID TLV
   lldpSetTlv(&context->txInfo, LLDP_TLV_TYPE_CHASSIS_ID, 0,
      (uint8_t *) chassisIdTlv, sizeof(LldpChassisIdTlv) + sizeof(MacAddr),
      TRUE);
#endif

#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //If notification transmission is enabled for particular ports, the
   //suggested default throttling period is 5 seconds.
   context->notificationInterval = LLDP_DEFAULT_NOTIFICATION_INTERVAL;
#endif

   //Initialize port table
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current entry
      port = &context->ports[i];

      //Clear port entry
      osMemset(port, 0, sizeof(LldpPortEntry));

      //Attach LLDP agent context to each port
      port->context = context;
      //Set port index
      port->portIndex = i + 1;

#if (LLDP_TX_MODE_SUPPORT == ENABLED && LLDP_RX_MODE_SUPPORT == ENABLED)
      //The local LLDP agent can both transmit and receive LLDP frames
      port->adminStatus = LLDP_ADMIN_STATUS_ENABLED_TX_RX;
#elif (LLDP_TX_MODE_SUPPORT == ENABLED)
      //The local LLDP agent can only transmit LLDP frames
      port->adminStatus = LLDP_ADMIN_STATUS_ENABLED_TX_ONLY;
#elif (LLDP_RX_MODE_SUPPORT == ENABLED)
      //The local LLDP agent can only receive LLDP frames
      port->adminStatus = LLDP_ADMIN_STATUS_ENABLED_RX_ONLY;
#else
      //The local LLDP agent can neither transmit or receive LLDP frames
      port->adminStatus = LLDP_ADMIN_STATUS_DISABLED;
#endif

      //Set operational state
      port->portEnabled = FALSE;

#if (LLDP_TX_MODE_SUPPORT == ENABLED)
      //Each port must assigned a unique MAC address
      lldpGeneratePortAddr(port);

      //Bit-map indicating the basic TLVs enabled for transmission
      port->basicTlvFilter = LLDP_BASIC_TLV_FILTER_ALL;
      //Bit-map indicating the management addresses enabled for transmission
      port->mgmtAddrFilter = LLDP_MGMT_ADDR_FILTER_ALL;

      //Point to the buffer where to format the Port ID TLV
      portIdTlv = (LldpPortIdTlv *) context->lldpdu.data;

      //By default, the port identifier is locally assigned
      portIdTlv->portIdSubtype = LLDP_PORT_ID_SUBTYPE_LOCALLY_ASSIGNED;
      n = osSprintf((char_t *) portIdTlv->portId, "%u", port->portIndex);

      //Set the value of the Port ID TLV
      lldpSetTlv(&port->txInfo, LLDP_TLV_TYPE_PORT_ID, 0,
         (uint8_t *) portIdTlv, sizeof(LldpPortIdTlv) + n, TRUE);
#endif
   }

   //Initialize neighbor table
   for(i = 0; i < context->numNeighbors; i++)
   {
      //Clear neighbor entry
      osMemset(&context->neighbors[i], 0, sizeof(LldpNeighborEntry));
   }

   //Initialize LLDP state machine
   lldpInitFsm(context);

   //Start of exception handling block
   do
   {
      //Create a mutex to prevent simultaneous access to LLDP agent context
      if(!osCreateMutex(&context->mutex))
      {
         //Failed to create mutex
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //Create an event object to poll the state of the raw socket
      if(!osCreateEvent(&context->event))
      {
         //Failed to create event
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //Successful initialization
      error = NO_ERROR;

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      lldpDeinit(context);
   }

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start LLDP agent
 * @param[in] context Pointer to the LLDP agent context
 * @return Error code
 **/

error_t lldpStart(LldpAgentContext *context)
{
   error_t error;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting LLDP agent...\r\n");

   //Make sure the LLDP agent is not already running
   if(context->running)
      return ERROR_ALREADY_RUNNING;

   //Start of exception handling block
   do
   {
      //Open a raw socket
      context->socket = socketOpen(SOCKET_TYPE_RAW_ETH, ETH_TYPE_LLDP);
      //Failed to open socket?
      if(context->socket == NULL)
      {
         //Report an error
         error = ERROR_OPEN_FAILED;
         break;
      }

      //Force the socket to operate in non-blocking mode
      error = socketSetTimeout(context->socket, 0);
      //Any error to report?
      if(error)
         return error;

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->socket, context->interface);
      //Unable to bind the socket to the desired interface?
      if(error)
         break;

      //Add the LLDP multicast address to the static MAC table
      error = lldpAcceptMulticastAddr(context);
      //Any error to report?
      if(error)
         return error;

      //Start the LLDP agent
      context->stop = FALSE;
      context->running = TRUE;

      //Save current time
      context->timestamp = osGetSystemTime();

#if (OS_STATIC_TASK_SUPPORT == ENABLED)
      //Create a task using statically allocated memory
      context->taskId = osCreateStaticTask("LLDP Agent",
         (OsTaskCode) lldpTask, context, &context->taskTcb,
         context->taskStack, LLDP_TASK_STACK_SIZE, LLDP_TASK_PRIORITY);
#else
      //Create a task
      context->taskId = osCreateTask("LLDP Agent", (OsTaskCode) lldpTask,
         context, LLDP_TASK_STACK_SIZE, LLDP_TASK_PRIORITY);
#endif

      //Failed to create task?
      if(context->taskId == OS_INVALID_TASK_ID)
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      context->running = FALSE;

      //Remove the LLDP multicast address from the static MAC table
      lldpDropMulticastAddr(context);

      //Close the UDP socket
      socketClose(context->socket);
      context->socket = NULL;
   }

   //Return status code
   return error;
}


/**
 * @brief Stop LLDP agent
 * @param[in] context Pointer to the LLDP agent context
 * @return Error code
 **/

error_t lldpStop(LldpAgentContext *context)
{
   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping LLDP agent...\r\n");

   //Check whether the LLDP agent is running
   if(context->running)
   {
      //Stop the LLDP agent
      context->stop = TRUE;
      //Send a signal to the task to abort any blocking operation
      osSetEvent(&context->event);

      //Wait for the task to terminate
      while(context->running)
      {
         osDelayTask(1);
      }

      //Remove the LLDP multicast address from the static MAC table
      lldpDropMulticastAddr(context);

      //Close the UDP socket
      socketClose(context->socket);
      context->socket = NULL;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set port address
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] macAddr MAC address of the individual MAC entity for the port
 * @return Error code
 **/

error_t lldpSetPortAddr(LldpAgentContext *context, uint_t portIndex,
   const MacAddr *macAddr)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || macAddr == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Set the MAC address of the individual MAC entity for the port
   port->macAddr = *macAddr;

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set transmit interval
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] msgTxInterval Time interval between successive transmit
 *   cycles, in seconds
 * @return Error code
 **/

error_t lldpSetMsgTxInterval(LldpAgentContext *context, uint_t msgTxInterval)
{
   error_t error;

   //Make sure the LLDP agent context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the LLDP agent context
      osAcquireMutex(&context->mutex);
      //Perform management operation
      error = lldpMgmtSetMsgTxInterval(context, msgTxInterval, TRUE);
      //Release exclusive access to the LLDP agent context
      osReleaseMutex(&context->mutex);
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
 * @brief Set transmit hold multiplier
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] msgTxHold Multiplier on the msgTxInterval that determines the
 *   actual TTL value used in an LLDPDU
 * @return Error code
 **/

error_t lldpSetMsgTxHold(LldpAgentContext *context, uint_t msgTxHold)
{
   error_t error;

   //Make sure the LLDP agent context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the LLDP agent context
      osAcquireMutex(&context->mutex);
      //Perform management operation
      error = lldpMgmtSetMsgTxHold(context, msgTxHold, TRUE);
      //Release exclusive access to the LLDP agent context
      osReleaseMutex(&context->mutex);
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
 * @brief Set re-initialization delay
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] reinitDelay Delay before re-initialization will be attempted
 * @return Error code
 **/

error_t lldpSetReinitDelay(LldpAgentContext *context, uint_t reinitDelay)
{
   error_t error;

   //Make sure the LLDP agent context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the LLDP agent context
      osAcquireMutex(&context->mutex);
      //Perform management operation
      error = lldpMgmtSetReinitDelay(context, reinitDelay, TRUE);
      //Release exclusive access to the LLDP agent context
      osReleaseMutex(&context->mutex);
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
 * @brief Set transmit delay
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] txDelay Delay between successive LLDP frame transmissions
 * @return Error code
 **/

error_t lldpSetTxDelay(LldpAgentContext *context, uint_t txDelay)
{
   error_t error;

   //Make sure the LLDP agent context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the LLDP agent context
      osAcquireMutex(&context->mutex);
      //Perform management operation
      error = lldpMgmtSetTxDelay(context, txDelay, TRUE);
      //Release exclusive access to the LLDP agent context
      osReleaseMutex(&context->mutex);
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
 * @brief Set administrative status
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] adminStatus The administrative status indicates whether or not
 *   the local LLDP agent is enabled
 * @return Error code
 **/

error_t lldpSetAdminStatus(LldpAgentContext *context, uint_t portIndex,
   LldpAdminStatus adminStatus)
{
   error_t error;

   //Make sure the LLDP agent context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the LLDP agent context
      osAcquireMutex(&context->mutex);
      //Perform management operation
      error = lldpMgmtSetAdminStatus(context, portIndex, adminStatus, TRUE);
      //Release exclusive access to the LLDP agent context
      osReleaseMutex(&context->mutex);
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
 * @brief Set the list of TLVs enabled for transmission
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] mask Bit-map indicating the TLVs enabled for transmission
 * @return Error code
 **/

error_t lldpSetBasicTlvFilter(LldpAgentContext *context, uint_t portIndex,
   uint8_t mask)
{
   error_t error;

   //Make sure the LLDP agent context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the LLDP agent context
      osAcquireMutex(&context->mutex);
      //Perform management operation
      error = lldpMgmtSetBasicTlvFilter(context, portIndex, mask, TRUE);
      //Release exclusive access to the LLDP agent context
      osReleaseMutex(&context->mutex);
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
 * @brief Set the list of management addresses enabled for transmission
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] mask Bit-map indicating the management addresses enabled for
 *   transmission
 * @return Error code
 **/

error_t lldpSetMgmtAddrFilter(LldpAgentContext *context, uint_t portIndex,
   uint32_t mask)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Each bit in the bitmap corresponds to a given management address
   port->mgmtAddrFilter = mask & LLDP_MGMT_ADDR_FILTER_ALL;

   //The somethingChangedLocal flag must be set whenever the value of an
   //object has changed in the local system MIB
   lldpSomethingChangedLocal(context);

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set chassis ID
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] chassisIdSubtype Type of identifier used for the chassis
 * @param[in] chassisId Administratively assigned name that identifies the chassis
 * @param[in] chassisIdLen Length of the chassis ID, in bytes
 * @return Error code
 **/

error_t lldpSetLocalChassisId(LldpAgentContext *context,
   LldpChassisIdSubtype chassisIdSubtype, const void *chassisId,
   size_t chassisIdLen)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   LldpChassisIdTlv *tlv;

   //Check parameters
   if(context == NULL || chassisId == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the chassis ID
   if(chassisIdLen < LLDP_MIN_CHASSIS_ID_LEN ||
      chassisIdLen > LLDP_MAX_CHASSIS_ID_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the buffer where to format the TLV
   tlv = (LldpChassisIdTlv *) context->lldpdu.data;

   //Set chassis ID subtype
   tlv->chassisIdSubtype = chassisIdSubtype;
   //Copy chassis ID
   osMemcpy(tlv->chassisId, chassisId, chassisIdLen);

   //Calculate the length of the TLV
   n = sizeof(LldpChassisIdTlv) + chassisIdLen;

   //Set the value of the specified TLV
   error = lldpSetTlv(&context->txInfo, LLDP_TLV_TYPE_CHASSIS_ID, 0,
      (uint8_t *) tlv, n, TRUE);

   //Check status code
   if(!error)
   {
      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
#else
   //TX mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set port ID
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] portIdSubtype Type of identifier used for the port
 * @param[in] portId Administratively assigned name that identifies the port
 * @param[in] portIdLen Length of the port ID, in bytes
 * @return Error code
 **/

error_t lldpSetLocalPortId(LldpAgentContext *context, uint_t portIndex,
   LldpPortIdSubtype portIdSubtype, const void *portId, size_t portIdLen)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   LldpPortEntry *port;
   LldpPortIdTlv *tlv;

   //Check parameters
   if(context == NULL || portId == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Check the length of the port ID
   if(portIdLen < LLDP_MIN_PORT_ID_LEN || portIdLen > LLDP_MAX_PORT_ID_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Point to the buffer where to format the TLV
   tlv = (LldpPortIdTlv *) context->lldpdu.data;

   //Set port ID subtype
   tlv->portIdSubtype = portIdSubtype;
   //Copy port ID
   osMemcpy(tlv->portId, portId, portIdLen);

   //Calculate the length of the TLV
   n = sizeof(LldpPortIdTlv) + portIdLen;

   //Set the value of the specified TLV
   error = lldpSetTlv(&port->txInfo, LLDP_TLV_TYPE_PORT_ID, 0,
      (uint8_t *) tlv, n, TRUE);

   //Check status code
   if(!error)
   {
      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
#else
   //TX mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set port description
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] portDesc Station port's description
 * @return Error code
 **/

error_t lldpSetLocalPortDesc(LldpAgentContext *context, uint_t portIndex,
   const char_t *portDesc)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || portDesc == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Get the length of the port's description
   n = osStrlen(portDesc);

   //Check the length of the string
   if(n < LLDP_MIN_PORT_DESC_LEN || n > LLDP_MAX_PORT_DESC_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Set the value of the specified TLV
   error = lldpSetTlv(&port->txInfo, LLDP_TLV_TYPE_PORT_DESC, 0,
      (uint8_t *) portDesc, n, TRUE);

   //Check status code
   if(!error)
   {
      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
#else
   //TX mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set system name
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] sysName System's administratively assigned name
 * @return Error code
 **/

error_t lldpSetLocalSysName(LldpAgentContext *context, const char_t *sysName)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Check parameters
   if(context == NULL || sysName == NULL)
      return ERROR_INVALID_PARAMETER;

   //Get the length of the system name
   n = osStrlen(sysName);

   //Check the length of the string
   if(n < LLDP_MIN_SYS_NAME_LEN ||
      n > LLDP_MAX_SYS_NAME_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Set the value of the specified TLV
   error = lldpSetTlv(&context->txInfo, LLDP_TLV_TYPE_SYS_NAME, 0,
      (uint8_t *) sysName, n, TRUE);

   //Check status code
   if(!error)
   {
      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
#else
   //TX mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set system description
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] sysDesc Textual description of the network entity
 * @return Error code
 **/

error_t lldpSetLocalSysDesc(LldpAgentContext *context, const char_t *sysDesc)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Check parameters
   if(context == NULL || sysDesc == NULL)
      return ERROR_INVALID_PARAMETER;

   //Get the length of the system description
   n = osStrlen(sysDesc);

   //Check the length of the string
   if(n < LLDP_MIN_SYS_DESC_LEN ||
      n > LLDP_MAX_SYS_DESC_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Set the value of the specified TLV
   error = lldpSetTlv(&context->txInfo, LLDP_TLV_TYPE_SYS_DESC, 0,
      (uint8_t *) sysDesc, n, TRUE);

   //Check status code
   if(!error)
   {
      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
#else
   //TX mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set system capabilities
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] supportedCap Bit-map of the capabilities supported by the system
 * @param[in] enabledCap Bit-map of the capabilities currently enabled
 * @return Error code
 **/

error_t lldpSetLocalSysCap(LldpAgentContext *context, uint16_t supportedCap,
   uint16_t enabledCap)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   LldpSysCapTlv *tlv;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the buffer where to format the TLV
   tlv = (LldpSysCapTlv *) context->lldpdu.data;

   //Set supported capabilities
   tlv->supportedCap = htons(supportedCap);
   //Set enabled capabilities
   tlv->enabledCap = htons(enabledCap);

   //Calculate the length of the TLV
   n = sizeof(LldpSysCapTlv);

   //Set the value of the specified TLV
   error = lldpSetTlv(&context->txInfo, LLDP_TLV_TYPE_SYS_CAP, 0,
      (uint8_t *) tlv, n, TRUE);

   //Check status code
   if(!error)
   {
      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
#else
   //TX mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set management address
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] index Zero-based index identifying a management address
 * @param[in] mgmtAddrSubtype Type of management address
 * @param[in] mgmtAddr Octet string indicating a particular management
 *   address
 * @param[in] mgmtAddrLen Length of the management address, in bytes
 * @param[in] ifNumSubtype Numbering method used for defining the interface
 *   number
 * @param[in] ifNum Number within the system that identifies the specific
 *   interface associated with this management address
 * @param[in] oid OID that identifies the type of hardware component or
 *   protocol entity associated with the indicated management address
 * @param[in] oidLen Length of the OID, in bytes
 * @return Error code
 **/

error_t lldpSetLocalMgmtAddr(LldpAgentContext *context, uint_t index,
   LldpMgmtAddrSubtype mgmtAddrSubtype, const void *mgmtAddr,
   size_t mgmtAddrLen, LldpIfNumSubtype ifNumSubtype, uint32_t ifNum,
   const uint8_t *oid, size_t oidLen)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   uint_t i;
   uint_t k;
   size_t n;
   LldpMgmtAddrTlv1 *tlv1;
   LldpMgmtAddrTlv2 *tlv2;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check index value
   if(index > LLDP_MAX_MGMT_ADDRS)
      return ERROR_INVALID_PARAMETER;

   //Make sure the management address is valid
   if(mgmtAddr == NULL && mgmtAddrLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the management address
   if(mgmtAddrLen > LLDP_MAX_MGMT_ADDR_LEN)
      return ERROR_INVALID_LENGTH;

   //Make sure the object identifier is valid
   if(oid == NULL && oidLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the object identifier
   if(oidLen > LLDP_MAX_OID_LEN)
      return ERROR_INVALID_LENGTH;

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //An individual LLDPDU may contain more than one Management Address
   //TLV (refer to IEEE 802.1AB-2005, section 9.5.9.9)
   for(i = 0, k = 0; i < index; i++)
   {
      //Check whether the current management address is configured
      if((context->mgmtAddrMap & (1U << i)) != 0)
      {
         k++;
      }
   }

   //Valid management address?
   if(mgmtAddrLen > 0)
   {
      //Point to the buffer where to format the first part of the TLV
      tlv1 = (LldpMgmtAddrTlv1 *) context->lldpdu.data;

      //The management address string length shall contain the length management
      //address subtype and management address fields
      tlv1->mgmtAddrLen = mgmtAddrLen + 1;

      //Set management address subtype
      tlv1->mgmtAddrSubtype = mgmtAddrSubtype;
      //Copy management address
      osMemcpy(tlv1->mgmtAddr, mgmtAddr, mgmtAddrLen);

      //Point to the buffer where to format the second part of the TLV
      tlv2 = (LldpMgmtAddrTlv2 *) (tlv1->mgmtAddr + mgmtAddrLen);

      //Set interface numbering subtype
      tlv2->ifNumSubtype = ifNumSubtype;
      //Set interface number
      tlv2->ifNum = htonl(ifNum);
      //Set OID string length
      tlv2->oidLen = oidLen;
      //Copy object identifier
      osMemcpy(tlv2->oid, oid, oidLen);

      //Calculate the length of the TLV
      n = sizeof(LldpMgmtAddrTlv1) + mgmtAddrLen + sizeof(LldpMgmtAddrTlv2) +
         oidLen;

      //Check whether the TLV already exists
      if((context->mgmtAddrMap & (1U << index)) != 0)
      {
         //Replace existing TLV
         error = lldpSetTlv(&context->txInfo, LLDP_TLV_TYPE_MGMT_ADDR, k,
            (uint8_t *) tlv1, n, TRUE);
      }
      else
      {
         //Add a new TLV
         error = lldpSetTlv(&context->txInfo, LLDP_TLV_TYPE_MGMT_ADDR, k,
            (uint8_t *) tlv1, n, FALSE);
      }

      //Check status code
      if(!error)
      {
         //The management address is now configured
         context->mgmtAddrMap |= (1U << index);
      }
   }
   else
   {
      //Remove the specified TLV from the local system information
      error = lldpDeleteTlv(&context->txInfo, LLDP_TLV_TYPE_MGMT_ADDR, k);

      //The management address is no longer used
      context->mgmtAddrMap &= ~(1U << index);
   }

   //Check status code
   if(!error)
   {
      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
#else
   //TX mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Remove all TLVs with specified type
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] type TLV type
 * @return Error code
 **/

error_t lldpDeleteLocalTlv(LldpAgentContext *context, LldpTlvType type)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   uint_t i;
   bool_t somethingChangedLocal;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check TLV type
   if(type != LLDP_TLV_TYPE_PORT_DESC &&
      type != LLDP_TLV_TYPE_SYS_NAME &&
      type != LLDP_TLV_TYPE_SYS_DESC &&
      type != LLDP_TLV_TYPE_SYS_CAP &&
      type != LLDP_TLV_TYPE_MGMT_ADDR &&
      type != LLDP_TLV_TYPE_ORG_DEFINED)
   {
      return ERROR_INVALID_TYPE;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Initialize status code
   error = NO_ERROR;
   //Clear flag
   somethingChangedLocal = FALSE;

   //Remove all TLVs that match the specified type
   while(!error)
   {
      //Remove one TLV at a time
      error = lldpDeleteTlv(&context->txInfo, type, 0);

      //Check status code
      if(!error)
      {
         somethingChangedLocal = TRUE;
      }
   }

   //Loop through the ports
   for(i = 0; i < context->numPorts; i++)
   {
      //Initialize status code
      error = NO_ERROR;

      //Remove all port-specific TLVs that match the specified type
      while(!error)
      {
         //Remove one TLV at a time
         error = lldpDeleteTlv(&context->ports[i].txInfo, type, 0);

         //Check status code
         if(!error)
         {
            somethingChangedLocal = TRUE;
         }
      }
   }

   //Any change in the LLDP local system MIB?
   if(somethingChangedLocal)
   {
      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Report an error
      error = ERROR_NOT_FOUND;
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
#else
   //TX mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief LLDP agent task
 * @param[in] context Pointer to the LLDP agent context
 **/

void lldpTask(LldpAgentContext *context)
{
   systime_t time;
   systime_t timeout;
   SocketEventDesc eventDesc;

#if (NET_RTOS_SUPPORT == ENABLED)
   //Task prologue
   osEnterTask();

   //Main loop
   while(1)
   {
#endif
      //Get current time
      time = osGetSystemTime();

      //Maximum time to wait for an incoming datagram
      if((time - context->timestamp) < LLDP_TICK_INTERVAL)
      {
         timeout = time + LLDP_TICK_INTERVAL - context->timestamp;
      }
      else
      {
         timeout = 0;
      }

      //Specify the events the application is interested in
      eventDesc.socket = context->socket;
      eventDesc.eventMask = SOCKET_EVENT_RX_READY;
      eventDesc.eventFlags = 0;

      //Wait for an event
      socketPoll(&eventDesc, 1, &context->event, timeout);

      //Stop request?
      if(context->stop)
      {
         //Stop SNMP agent operation
         context->running = FALSE;
         //Task epilogue
         osExitTask();
         //Kill ourselves
         osDeleteTask(OS_SELF_TASK_ID);
      }

      //Any LLDP frame received?
      if(eventDesc.eventFlags != 0)
      {
         //Acquire exclusive access to the LLDP agent context
         osAcquireMutex(&context->mutex);
         //Frame reception process
         lldpProcessFrame(context);
         //Release exclusive access to the LLDP agent context
         osReleaseMutex(&context->mutex);
      }

      //Get current time
      time = osGetSystemTime();

      //All LLDP timers have a resolution of one second
      if((time - context->timestamp) >= LLDP_TICK_INTERVAL)
      {
         //Acquire exclusive access to the LLDP agent context
         osAcquireMutex(&context->mutex);
         //Handle periodic operations
         lldpTick(context);
         //Release exclusive access to the LLDP agent context
         osReleaseMutex(&context->mutex);

         //Save current time
         context->timestamp = time;
      }
#if (NET_RTOS_SUPPORT == ENABLED)
   }
#endif
}


/**
 * @brief Release LLDP agent context
 * @param[in] context Pointer to the LLDP agent context
 **/

void lldpDeinit(LldpAgentContext *context)
{
   //Make sure the LLDP agent context is valid
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteMutex(&context->mutex);
      osDeleteEvent(&context->event);

      //Clear LLDP agent context
      osMemset(context, 0, sizeof(LldpAgentContext));
   }
}

#endif

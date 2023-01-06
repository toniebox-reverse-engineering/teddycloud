/**
 * @file auto_ip.c
 * @brief Auto-IP (Dynamic Configuration of IPv4 Link-Local Addresses)
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
 * @section Description
 *
 * Auto-IP describes a method by which a host may automatically configure an
 * interface with an IPv4 address in the 169.254/16 prefix that is valid for
 * Link-Local communication on that interface. This is especially valuable in
 * environments where no other configuration mechanism is available. Refer to
 * the following RFCs for complete details:
 * - RFC 3927: Dynamic Configuration of IPv4 Link-Local Addresses
 * - RFC 5227: IPv4 Address Conflict Detection
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL AUTO_IP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "ipv4/auto_ip.h"
#include "ipv4/auto_ip_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED && AUTO_IP_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains Auto-IP settings
 **/

void autoIpGetDefaultSettings(AutoIpSettings *settings)
{
   //Use default interface
   settings->interface = netGetDefaultInterface();
   //Index of the IP address to be configured
   settings->ipAddrIndex = 0;

   //Initial link-local address to be used
   settings->linkLocalAddr = IPV4_UNSPECIFIED_ADDR;
   //Link state change event
   settings->linkChangeEvent = NULL;
   //FSM state change event
   settings->stateChangeEvent = NULL;
}


/**
 * @brief Auto-IP initialization
 * @param[in] context Pointer to the Auto-IP context
 * @param[in] settings Auto-IP specific settings
 * @return Error code
 **/

error_t autoIpInit(AutoIpContext *context, const AutoIpSettings *settings)
{
   NetInterface *interface;

   //Debug message
   TRACE_INFO("Initializing Auto-IP...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //The Auto-IP service must be bound to a valid interface
   if(settings->interface == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the underlying network interface
   interface = settings->interface;

   //Clear the Auto-IP context
   osMemset(context, 0, sizeof(AutoIpContext));
   //Save user settings
   context->settings = *settings;

   //Use default link-local address
   context->linkLocalAddr = settings->linkLocalAddr;
   //Reset conflict counter
   context->conflictCount = 0;

   //Auto-IP operation is currently suspended
   context->running = FALSE;
   //Initialize state machine
   context->state = AUTO_IP_STATE_INIT;

   //Attach the Auto-IP context to the network interface
   interface->autoIpContext = context;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start Auto-IP process
 * @param[in] context Pointer to the Auto-IP context
 * @return Error code
 **/

error_t autoIpStart(AutoIpContext *context)
{
   //Make sure the Auto-IP context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting Auto-IP...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Reset Auto-IP configuration
   autoIpResetConfig(context);

   //Initialize state machine
   context->state = AUTO_IP_STATE_INIT;
   //Reset conflict counter
   context->conflictCount = 0;
   //Start Auto-IP operation
   context->running = TRUE;

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Stop Auto-IP process
 * @param[in] context Pointer to the Auto-IP context
 * @return Error code
 **/

error_t autoIpStop(AutoIpContext *context)
{
   //Make sure the Auto-IP context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping Auto-IP...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Suspend Auto-IP operation
   context->running = FALSE;
   //Reinitialize state machine
   context->state = AUTO_IP_STATE_INIT;

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Retrieve current state
 * @param[in] context Pointer to the Auto-IP context
 * @return Current Auto-IP state
 **/

AutoIpState autoIpGetState(AutoIpContext *context)
{
   AutoIpState state;

   //Get exclusive access
   osAcquireMutex(&netMutex);
   //Get current state
   state = context->state;
   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Return current state
   return state;
}

#endif

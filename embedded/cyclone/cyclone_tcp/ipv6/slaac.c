/**
 * @file slaac.c
 * @brief IPv6 Stateless Address Autoconfiguration
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
 * Stateless Address Autoconfiguration is a facility to allow devices to
 * configure themselves independently. Refer to the following RFCs for
 * complete details:
 * - RFC 4862: IPv6 Stateless Address Autoconfiguration
 * - RFC 6106: IPv6 Router Advertisement Options for DNS Configuration
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL SLAAC_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "core/ethernet.h"
#include "ipv6/ipv6.h"
#include "ipv6/ipv6_misc.h"
#include "ipv6/slaac.h"
#include "ipv6/slaac_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV6_SUPPORT == ENABLED && SLAAC_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains SLAAC settings
 **/

void slaacGetDefaultSettings(SlaacSettings *settings)
{
   //Use default interface
   settings->interface = netGetDefaultInterface();

   //Use the DNS servers specified by the RDNSS option
   settings->manualDnsConfig = FALSE;
   //Link state change event
   settings->linkChangeEvent = NULL;
   //Router Advertisement parsing callback
   settings->parseRouterAdvCallback = NULL;
}


/**
 * @brief SLAAC initialization
 * @param[in] context Pointer to the SLAAC context
 * @param[in] settings SLAAC specific settings
 * @return Error code
 **/

error_t slaacInit(SlaacContext *context, const SlaacSettings *settings)
{
   NetInterface *interface;

   //Debug message
   TRACE_INFO("Initializing SLAAC...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //The SLAAC service must be bound to a valid interface
   if(settings->interface == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the underlying network interface
   interface = settings->interface;

   //Clear the SLAAC context
   osMemset(context, 0, sizeof(SlaacContext));
   //Save user settings
   context->settings = *settings;

   //SLAAC operation is currently suspended
   context->running = FALSE;

   //Attach the SLAAC context to the network interface
   interface->slaacContext = context;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start SLAAC process
 * @param[in] context Pointer to the SLAAC context
 * @return Error code
 **/

error_t slaacStart(SlaacContext *context)
{
   NetInterface *interface;

   //Make sure the SLAAC context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting SLAAC...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Clear the list of IPv6 addresses
   ipv6FlushAddrList(interface);

   //Automatic DNS server configuration?
   if(!context->settings.manualDnsConfig)
   {
      //Clear the list of DNS servers
      ipv6FlushDnsServerList(interface);
   }

   //Check if the link is up?
   if(interface->linkState)
   {
      //A link-local address is formed by combining the well-known
      //link-local prefix fe80::/10 with the interface identifier
      slaacGenerateLinkLocalAddr(context);
   }

   //Start SLAAC operation
   context->running = TRUE;

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Stop SLAAC process
 * @param[in] context Pointer to the SLAAC context
 * @return Error code
 **/

error_t slaacStop(SlaacContext *context)
{
   //Make sure the SLAAC context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping SLAAC...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Suspend SLAAC operation
   context->running = FALSE;

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}

#endif

/**
 * @file dhcp_server.c
 * @brief DHCP server (Dynamic Host Configuration Protocol)
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
 * The Dynamic Host Configuration Protocol is used to provide configuration
 * parameters to hosts. Refer to the following RFCs for complete details:
 * - RFC 2131: Dynamic Host Configuration Protocol
 * - RFC 2132: DHCP Options and BOOTP Vendor Extensions
 * - RFC 4039: Rapid Commit Option for the DHCP version 4
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL DHCP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "dhcp/dhcp_server.h"
#include "dhcp/dhcp_server_misc.h"
#include "date_time.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED && DHCP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains DHCP server settings
 **/

void dhcpServerGetDefaultSettings(DhcpServerSettings *settings)
{
   uint_t i;

   //Use default interface
   settings->interface = netGetDefaultInterface();
   //Index of the IP address assigned to the DHCP server
   settings->ipAddrIndex = 0;

   //Support for quick configuration using rapid commit
   settings->rapidCommit = FALSE;
   //Lease time, in seconds, assigned to the DHCP clients
   settings->leaseTime = DHCP_SERVER_DEFAULT_LEASE_TIME;

   //Lowest and highest IP addresses in the pool that are available
   //for dynamic address assignment
   settings->ipAddrRangeMin = IPV4_UNSPECIFIED_ADDR;
   settings->ipAddrRangeMax = IPV4_UNSPECIFIED_ADDR;

   //Subnet mask
   settings->subnetMask = IPV4_UNSPECIFIED_ADDR;
   //Default gateway
   settings->defaultGateway = IPV4_UNSPECIFIED_ADDR;

   //DNS servers
   for(i = 0; i < DHCP_SERVER_MAX_DNS_SERVERS; i++)
      settings->dnsServer[i] = IPV4_UNSPECIFIED_ADDR;
}


/**
 * @brief DHCP server initialization
 * @param[in] context Pointer to the DHCP server context
 * @param[in] settings DHCP server specific settings
 * @return Error code
 **/

error_t dhcpServerInit(DhcpServerContext *context,
   const DhcpServerSettings *settings)
{
   NetInterface *interface;

   //Debug message
   TRACE_INFO("Initializing DHCP server...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //Valid network interface?
   if(settings->interface == NULL)
      return ERROR_INVALID_PARAMETER;

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Point to the underlying network interface
   interface = settings->interface;

   //Clear the DHCP server context
   osMemset(context, 0, sizeof(DhcpServerContext));
   //Save user settings
   context->settings = *settings;

   //Next IP address that will be assigned by the DHCP server
   context->nextIpAddr = settings->ipAddrRangeMin;
   //DHCP server is currently suspended
   context->running = FALSE;

   //Attach the DHCP server context to the network interface
   interface->dhcpServerContext = context;

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start DHCP server
 * @param[in] context Pointer to the DHCP server context
 * @return Error code
 **/

error_t dhcpServerStart(DhcpServerContext *context)
{
   error_t error;
   NetInterface *interface;

   //Make sure the DHCP server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting DHCP server...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check the operational state of the DHCP client
   if(!context->running)
   {
      //Register the callback function to be called whenever a UDP datagram
      //is received on port 67
      error = udpAttachRxCallback(interface, DHCP_SERVER_PORT,
         dhcpServerProcessMessage, context);

      //Check status code
      if(!error)
      {
         //Start DHCP server
         context->running = TRUE;
      }
   }
   else
   {
      //The DHCP client is already running
      error = ERROR_ALREADY_RUNNING;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Return status code
   return error;
}


/**
 * @brief Stop DHCP server
 * @param[in] context Pointer to the DHCP server context
 * @return Error code
 **/

error_t dhcpServerStop(DhcpServerContext *context)
{
   NetInterface *interface;

   //Make sure the DHCP server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping DHCP server...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check whether the DHCP client is running
   if(context->running)
   {
      //Unregister callback function
      udpDetachRxCallback(interface, DHCP_SERVER_PORT);

      //Stop DHCP server
      context->running = FALSE;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release DHCP server context
 * @param[in] context Pointer to the DHCP server context
 **/

void dhcpServerDeinit(DhcpServerContext *context)
{
   NetInterface *interface;

   //Make sure the DHCP server context is valid
   if(context != NULL)
   {
      //Get exclusive access
      osAcquireMutex(&netMutex);

      //Point to the underlying network interface
      interface = context->settings.interface;

      //Valid network interface?
      if(interface != NULL)
      {
         //Detach the DHCP server context from the network interface
         interface->dhcpServerContext = NULL;
      }

      //Clear the DHCP server context
      osMemset(context, 0, sizeof(DhcpServerContext));

      //Release exclusive access
      osReleaseMutex(&netMutex);
   }
}

#endif

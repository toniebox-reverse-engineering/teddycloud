/**
 * @file dhcpv6_client.c
 * @brief DHCPv6 client (Dynamic Host Configuration Protocol for IPv6)
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
 * The Dynamic Host Configuration Protocol for IPv6 enables DHCP servers to
 * pass configuration parameters such as IPv6 network addresses to IPv6
 * nodes. This protocol is a stateful counterpart to IPv6 Stateless Address
 * Autoconfiguration (RFC 2462), and can be used separately or concurrently
 * with the latter to obtain configuration parameters. Refer to RFC 3315
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL DHCPV6_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "ipv6/ipv6.h"
#include "ipv6/ipv6_misc.h"
#include "dhcpv6/dhcpv6_client.h"
#include "dhcpv6/dhcpv6_client_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV6_SUPPORT == ENABLED && DHCPV6_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains DHCPv6 client settings
 **/

void dhcpv6ClientGetDefaultSettings(Dhcpv6ClientSettings *settings)
{
   //Use default interface
   settings->interface = netGetDefaultInterface();

   //Support for quick configuration using rapid commit
   settings->rapidCommit = FALSE;
   //Use the DNS servers provided by the DHCPv6 server
   settings->manualDnsConfig = FALSE;
   //DHCPv6 configuration timeout
   settings->timeout = 0;

   //DHCPv6 configuration timeout event
   settings->timeoutEvent = NULL;
   //Link state change event
   settings->linkChangeEvent = NULL;
   //FSM state change event
   settings->stateChangeEvent = NULL;

   //Add DHCPv6 options callback
   settings->addOptionsCallback = NULL;
   //Parse DHCPv6 options callback
   settings->parseOptionsCallback = NULL;
}


/**
 * @brief DHCPv6 client initialization
 * @param[in] context Pointer to the DHCPv6 client context
 * @param[in] settings DHCPv6 client specific settings
 * @return Error code
 **/

error_t dhcpv6ClientInit(Dhcpv6ClientContext *context,
   const Dhcpv6ClientSettings *settings)
{
   error_t error;
   NetInterface *interface;

   //Debug message
   TRACE_INFO("Initializing DHCPv6 client...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //The DHCPv6 client must be bound to a valid interface
   if(settings->interface == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the underlying network interface
   interface = settings->interface;

   //Clear the DHCPv6 client context
   osMemset(context, 0, sizeof(Dhcpv6ClientContext));
   //Save user settings
   context->settings = *settings;

   //Generate client's DUID
   error = dhcpv6ClientGenerateDuid(context);
   //any error to report?
   if(error)
      return error;

   //DHCPv6 client is currently suspended
   context->running = FALSE;
   //Initialize state machine
   context->state = DHCPV6_STATE_INIT;

   //Attach the DHCPv6 client context to the network interface
   interface->dhcpv6ClientContext = context;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start DHCPv6 client
 * @param[in] context Pointer to the DHCPv6 client context
 * @return Error code
 **/

error_t dhcpv6ClientStart(Dhcpv6ClientContext *context)
{
   error_t error;
   NetInterface *interface;

   //Make sure the DHCPv6 client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting DHCPv6 client...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check the operational state of the DHCPv6 client
   if(!context->running)
   {
      //Flush the list of IPv6 addresses from the client's IA
      dhcpv6ClientFlushAddrList(context);

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
         dhcpv6ClientGenerateLinkLocalAddr(context);
      }

      //Initialize state machine
      context->state = DHCPV6_STATE_INIT;

      //Register the callback function to be called whenever a UDP datagram
      //is received on port 546
      error = udpAttachRxCallback(interface, DHCPV6_CLIENT_PORT,
         dhcpv6ClientProcessMessage, context);

      //Check status code
      if(!error)
      {
         //Start DHCPv6 client
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
 * @brief Stop DHCPv6 client
 * @param[in] context Pointer to the DHCPv6 client context
 * @return Error code
 **/

error_t dhcpv6ClientStop(Dhcpv6ClientContext *context)
{
   NetInterface *interface;

   //Make sure the DHCPv6 client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping DHCPv6 client...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check whether the DHCPv6 client is running
   if(context->running)
   {
      //Unregister callback function
      udpDetachRxCallback(interface, DHCPV6_CLIENT_PORT);

      //Stop DHCPv6 client
      context->running = FALSE;
      //Reinitialize state machine
      context->state = DHCPV6_STATE_INIT;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release DHCPv6 lease
 * @param[in] context Pointer to the DHCPv6 client context
 * @return Error code
 **/

error_t dhcpv6ClientRelease(Dhcpv6ClientContext *context)
{
   uint_t i;
   NetInterface *interface;
   Dhcpv6ClientAddrEntry *entry;

   //Check parameter
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Releasing DHCPv6 lease...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check whether the DHCPv6 client is running
   if(context->running)
   {
      //BOUND state?
      if(context->state == DHCPV6_STATE_BOUND)
      {
         //Loop through the IPv6 addresses recorded by the DHCPv6 client
         for(i = 0; i < DHCPV6_CLIENT_ADDR_LIST_SIZE; i++)
         {
            //Point to the current entry
            entry = &context->ia.addrList[i];

            //Valid IPv6 address?
            if(entry->validLifetime > 0)
            {
               //The client must stop using the addresses being released as soon
               //as the client begins the Release message exchange process
               ipv6RemoveAddr(interface, &entry->addr);
            }
         }

         //Switch to the RELEASE state
         dhcpv6ClientChangeState(context, DHCPV6_STATE_RELEASE, 0);
      }
      else
      {
         //Stop DHCPv6 client
         context->running = FALSE;
         //Reinitialize state machine
         context->state = DHCPV6_STATE_INIT;
      }
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Retrieve current state
 * @param[in] context Pointer to the DHCPv6 client context
 * @return Current DHCPv6 client state
 **/

Dhcpv6State dhcpv6ClientGetState(Dhcpv6ClientContext *context)
{
   Dhcpv6State state;

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

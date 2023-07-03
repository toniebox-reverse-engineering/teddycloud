/**
 * @file ndp_router_adv.c
 * @brief Router advertisement service
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
#define TRACE_LEVEL NDP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "ipv6/ndp_router_adv.h"
#include "ipv6/ndp_router_adv_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV6_SUPPORT == ENABLED && NDP_ROUTER_ADV_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains the RA service configuration variables
 **/

void ndpRouterAdvGetDefaultSettings(NdpRouterAdvSettings *settings)
{
   //Underlying network interface
   settings->interface = netGetDefaultInterface();

   //The maximum time allowed between sending unsolicited multicast
   //Router Advertisements from the interface
   settings->maxRtrAdvInterval = NDP_MAX_RTR_ADVERT_INTERVAL;

   //The minimum time allowed between sending unsolicited multicast
   //Router Advertisements from the interface
   settings->minRtrAdvInterval = NDP_MAX_RTR_ADVERT_INTERVAL / 3;

   //The default value to be placed in the Cur Hop Limit field in the
   //Router Advertisement messages sent by the router
   settings->curHopLimit = 0;

   //The value to be placed in the Managed Address Configuration
   //flag in the Router Advertisement
   settings->managedFlag = FALSE;

   //The value to be placed in the Other Configuration flag
   //in the Router Advertisement
   settings->otherConfigFlag = FALSE;

   //The value to be placed in the Mobile IPv6 Home Agent
   //flag in the Router Advertisement
   settings->homeAgentFlag = FALSE;

   //The value to be placed in the Router Selection Preferences
   //field in the Router Advertisement
   settings->preference = NDP_ROUTER_SEL_PREFERENCE_MEDIUM;

   //The value to be placed in the Neighbor Discovery Proxy
   //flag in the Router Advertisement
   settings->proxyFlag = FALSE;

   //The value to be placed in the Router Lifetime field of
   //Router Advertisements sent from the interface
   settings->defaultLifetime = 3 * (NDP_MAX_RTR_ADVERT_INTERVAL / 1000);

   //The value to be placed in the Reachable Time field in the
   //Router Advertisement messages sent by the router
   settings->reachableTime = 0;

   //The value to be placed in the Retrans Timer field in the
   //Router Advertisement messages sent by the router
   settings->retransTimer = 0;

   //The value to be placed in the MTU option sent by the router
   settings->linkMtu = 0;

   //A list of prefixes to be placed in Prefix Information options (PIO)
   //in Router Advertisement messages sent from the interface
   settings->prefixList = NULL;
   settings->prefixListLength = 0;

   //A list of routes to be placed in Route Information options (RIO)
   //in Router Advertisement messages sent from the interface
   settings->routeList = NULL;
   settings->routeListLength = 0;

   //A list of header compression contexts to be placed in the 6LoWPAN Context
   //options (6CO) in Router Advertisement messages sent from the interface
   settings->contextList = NULL;
   settings->contextListLength = 0;
}


/**
 * @brief RA service initialization
 * @param[in] context Pointer to the RA service context
 * @param[in] settings RA service configuration variables
 * @return Error code
 **/

error_t ndpRouterAdvInit(NdpRouterAdvContext *context,
   const NdpRouterAdvSettings *settings)
{
   NetInterface *interface;

   //Debug message
   TRACE_INFO("Initializing Router Advertisement service...\r\n");

   //Ensure the parameters are valid
   if(!context || !settings)
      return ERROR_INVALID_PARAMETER;

   //Valid network interface?
   if(!settings->interface)
      return ERROR_INVALID_PARAMETER;

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Point to the underlying network interface
   interface = settings->interface;

   //Clear the RA service context
   osMemset(context, 0, sizeof(NdpRouterAdvContext));
   //Save user settings
   context->settings = *settings;

   //The RA service is currently disabled on the interface
   context->running = FALSE;
   //Attach the RA service context to the network interface
   interface->ndpRouterAdvContext = context;

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start RA service
 * @param[in] context Pointer to the RA service context
 * @return Error code
 **/

error_t ndpRouterAdvStart(NdpRouterAdvContext *context)
{
   error_t error;
   NetInterface *interface;

   //Make sure the RA service context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting Router Advertisement service...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Check whether the service is running
   if(!context->running)
   {
      //Point to the underlying network interface
      interface = context->settings.interface;

      //Join the All-Routers multicast address
      error = ipv6JoinMulticastGroup(interface, &IPV6_LINK_LOCAL_ALL_ROUTERS_ADDR);

      //Successful membership registration?
      if(!error)
      {
         //Reset variables
         context->timestamp = osGetSystemTime();
         context->timeout = 0;
         context->routerAdvCount = 0;

         //Enable the router to forward packets to or from the interface
         interface->ipv6Context.isRouter = TRUE;

         //Default Hop Limit value
         if(context->settings.curHopLimit != 0)
         {
            interface->ipv6Context.curHopLimit = context->settings.curHopLimit;
         }

         //The time a node assumes a neighbor is reachable
         if(context->settings.reachableTime != 0)
         {
            interface->ndpContext.reachableTime = context->settings.reachableTime;
         }

         //The time between retransmissions of NS messages
         if(context->settings.retransTimer != 0)
         {
            interface->ndpContext.retransTimer = context->settings.retransTimer;
         }

         //Start transmitting Router Advertisements
         context->running = TRUE;
      }
   }
   else
   {
      //The service is already running...
      error = NO_ERROR;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Return status code
   return error;
}


/**
 * @brief Stop RA service
 * @param[in] context Pointer to the RA service context
 * @return Error code
 **/

error_t ndpRouterAdvStop(NdpRouterAdvContext *context)
{
   error_t error;
   NetInterface *interface;

   //Make sure the RA service context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping Router Advertisement service...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Check whether the service is running
   if(context->running)
   {
      //Point to the underlying network interface
      interface = context->settings.interface;

      //The router should transmit one or more final multicast Router
      //Advertisements with a Router Lifetime field of zero
      ndpSendRouterAdv(context, 0);

      //Leave the All-Routers multicast address
      error = ipv6LeaveMulticastGroup(interface, &IPV6_LINK_LOCAL_ALL_ROUTERS_ADDR);

      //Restore default parameters
      interface->ipv6Context.curHopLimit = IPV6_DEFAULT_HOP_LIMIT;
      interface->ndpContext.reachableTime = NDP_REACHABLE_TIME;
      interface->ndpContext.retransTimer = NDP_RETRANS_TIMER;

      //Stop transmitting Router Advertisements
      context->running = FALSE;
   }
   else
   {
      //The service is not running...
      error = NO_ERROR;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Return status code
   return error;
}

#endif

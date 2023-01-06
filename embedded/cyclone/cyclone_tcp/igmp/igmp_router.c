/**
 * @file igmp_router.c
 * @brief IGMP router
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
 * IGMP is used by IP hosts to report their multicast group memberships
 * to routers. Refer to the following RFCs for complete details:
 * - RFC 1112: Host Extensions for IP Multicasting
 * - RFC 2236: Internet Group Management Protocol, Version 2
 * - RFC 3376: Internet Group Management Protocol, Version 3
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL IGMP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "ipv4/ipv4.h"
#include "igmp/igmp_router.h"
#include "igmp/igmp_router_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED && IGMP_ROUTER_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains IGMP router settings
 **/

void igmpRouterGetDefaultSettings(IgmpRouterSettings *settings)
{
   //Primary interface on an attached network
   settings->interface = NULL;

   //Implementations may provide a way for system administrators to enable the
   //use of IGMPv1 on their routers; in the absence of explicit configuration,
   //the configuration must default to IGMPv2 (refer to RFC 2236, section 4)
   settings->version = IGMP_VERSION_2;

   //Maximum number of multicast groups
   settings->numGroups = 0;
   //Multicast groups
   settings->groups = NULL;

   //Add multicast route callback
   settings->addMcastRouteCallback = NULL;
   //Delete multicast route callback
   settings->deleteMcastRouteCallback = NULL;
}


/**
 * @brief IGMP router initialization
 * @param[in] context Pointer to the IGMP router context
 * @param[in] settings IGMP router specific settings
 * @return Error code
 **/

error_t igmpRouterInit(IgmpRouterContext *context,
   const IgmpRouterSettings *settings)
{
   uint_t i;
   NetInterface *interface;

   //Debug message
   TRACE_INFO("Initializing IGMP router...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //The IGMP router must be bound to a valid interface
   if(settings->interface == NULL)
      return ERROR_INVALID_PARAMETER;

   //Sanity check
   if(settings->numGroups < 1 || settings->groups == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the underlying network interface
   interface = settings->interface;

   //Clear the IGMP router context
   osMemset(context, 0, sizeof(IgmpRouterContext));

   //Initialize IGMP router context
   context->interface = settings->interface;
   context->version = settings->version;
   context->numGroups = settings->numGroups;
   context->groups = settings->groups;
   context->addMcastRouteCallback = settings->addMcastRouteCallback;
   context->deleteMcastRouteCallback = settings->deleteMcastRouteCallback;

   //A router should start in the Initial state on all attached networks, and
   //immediately move to Querier state
   context->state = IGMP_ROUTER_STATE_INIT;

   //Loop through multicast groups
   for(i = 0; i < context->numGroups; i++)
   {
      //The "No Members Present" state, when there are no hosts on the network
      //which have sent reports for this multicast group is the initial state
      //for all groups on the router
      context->groups[i].state = IGMP_ROUTER_GROUP_STATE_NO_MEMBERS_PRESENT;
   }

   //Attach the IGMP router context to the network interface
   interface->igmpRouterContext = context;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start IGMP router
 * @param[in] context Pointer to the IGMP router context
 * @return Error code
 **/

error_t igmpRouterStart(IgmpRouterContext *context)
{
   //Make sure the IGMP router context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting IGMP router...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Accept all frames with a multicast destination address
   context->interface->acceptAllMulticast = TRUE;
   //Update the MAC filter table
   nicUpdateMacAddrFilter(context->interface);

   //The IGMP router is now running
   context->running = TRUE;

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Stop IGMP router
 * @param[in] context Pointer to the IGMP router context
 * @return Error code
 **/

error_t igmpRouterStop(IgmpRouterContext *context)
{
   //Make sure the IGMP router context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping IGMP router...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Revert to default configuration
   context->interface->acceptAllMulticast = FALSE;
   //Update the MAC filter table
   nicUpdateMacAddrFilter(context->interface);

   //The IGMP router is not running anymore
   context->running = FALSE;

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief IGMP router timer handler
 *
 * This routine must be periodically called by the TCP/IP stack to update
 * IGMP router state machines
 *
 * @param[in] context Pointer to the IGMP router context
 **/

void igmpRouterTick(IgmpRouterContext *context)
{
   uint_t i;

   //Check whether the IGMP router is running
   if(context->running)
   {
      //IGMP router state machine
      igmpRouterFsm(context);

      //Loop through multicast groups
      for(i = 0; i < context->numGroups; i++)
      {
         //IGMP group state machine
         igmpRouterGroupFsm(context, &context->groups[i]);
      }
   }
}


/**
 * @brief IGMP router state machine
 * @param[in] context Pointer to the IGMP router context
 **/

void igmpRouterFsm(IgmpRouterContext *context)
{
   //Check router state
   if(context->state == IGMP_ROUTER_STATE_INIT)
   {
      //Send a General Query message
      igmpRouterSendGeneralQuery(context);

      //Number of General Queries left to sent out on startup
      context->startupQueryCount = IGMP_STARTUP_QUERY_COUNT - 1;

      //Start General Query timer
      netStartTimer(&context->generalQueryTimer, IGMP_STARTUP_QUERY_INTERVAL);

      //A router should start in the Initial state on all attached networks,
      //and immediately move to Querier state (refer to RFC 2236, section 7)
      context->state = IGMP_ROUTER_STATE_QUERIER;
   }
   else if(context->state == IGMP_ROUTER_STATE_QUERIER)
   {
      //This router is designated to transmit IGMP Membership Queries on this
      //network
      if(netTimerExpired(&context->generalQueryTimer))
      {
         //Send a General Query message
         igmpRouterSendGeneralQuery(context);

         //On startup, a router should send General Queries spaced closely
         //together in order to quickly and reliably determine membership
         //information (refer to RFC 2236, section 3)
         if(context->startupQueryCount > 1)
         {
            //Number of General Queries left to sent out on startup
            context->startupQueryCount--;

            //The Startup Query Interval is the interval between General Queries
            //sent by a Querier on startup (refer to RFC 2236, section 8.6)
            netStartTimer(&context->generalQueryTimer, IGMP_STARTUP_QUERY_INTERVAL);
         }
         else
         {
            //The Query Interval is the interval between General Queries sent by
            //the Querier (refer to RFC 2236, section 8.2)
            netStartTimer(&context->generalQueryTimer, IGMP_QUERY_INTERVAL);
         }
      }
   }
   else if(context->state == IGMP_ROUTER_STATE_NON_QUERIER)
   {
      //There is another router designated to transmit IGMP membership Queries
      //on this network
      if(netTimerExpired(&context->otherQuerierPresentTimer))
      {
         //Switch to the "Querier" state
         context->state = IGMP_ROUTER_STATE_QUERIER;
      }
   }
   else
   {
      //Invalid state
      context->state = IGMP_ROUTER_STATE_INIT;
   }
}


/**
 * @brief IGMP group state machine
 * @param[in] context Pointer to the IGMP router context
 * @param[in] group Multicast group
 **/

void igmpRouterGroupFsm(IgmpRouterContext *context, IgmpRouterGroup *group)
{
   //A router may be in one of four possible states with respect to any single
   //IP multicast group on any single attached network
   if(group->state == IGMP_ROUTER_GROUP_STATE_NO_MEMBERS_PRESENT)
   {
      //The "No Members Present" state is the initial state for all groups on
      //the router; it requires no storage in the router
   }
   else if(group->state == IGMP_ROUTER_GROUP_STATE_MEMBERS_PRESENT)
   {
      //Check whether the timer set for a group membership has expired
      if(netTimerExpired(&group->timer))
      {
         //There are no longer any members of this group on the network
         igmpRouterDeleteGroup(context, group);
      }
   }
   else if(group->state == IGMP_ROUTER_GROUP_STATE_V1_MEMBERS_PRESENT)
   {
      //Check whether the timer set for a group membership has expired
      if(netTimerExpired(&group->timer))
      {
         //There are no longer any members of this group on the network
         igmpRouterDeleteGroup(context, group);
      }
      else if(netTimerExpired(&group->v1HostTimer))
      {
         //Switch to the "Members Present" state
         group->state = IGMP_ROUTER_GROUP_STATE_MEMBERS_PRESENT;
      }
      else
      {
         //Just for sanity
      }
   }
   else if(group->state == IGMP_ROUTER_GROUP_STATE_CHECKING_MEMBERSHIP)
   {
      //Any Querier to non-Querier transition is ignored during this time; the
      //same router keeps sending the Group-Specific Queries
      if(group->lastMemberQueryCount > 0)
      {
         //Check whether the retransmit timer has expired
         if(netTimerExpired(&group->retransmitTimer))
         {
            //Send a Group-Specific Query message
            igmpRouterSendGroupSpecificQuery(context, group->addr);

            //Number of Group-Specific Queries left to sent before the router
            //assumes there are no local members
            group->lastMemberQueryCount--;

            //Start retransmit timer for the group membership
            netStartTimer(&group->retransmitTimer, IGMP_LAST_MEMBER_QUERY_INTERVAL);
         }
      }
      else
      {
         //Check whether the timer set for a group membership has expired
         if(netTimerExpired(&group->timer))
         {
            //If no reports are received after the response time of the last query
            //expires, the routers assume that the group has no local members
            igmpRouterDeleteGroup(context, group);
         }
      }
   }
   else
   {
      //Invalid state
      group->state = IGMP_ROUTER_GROUP_STATE_NO_MEMBERS_PRESENT;
   }
}

#endif

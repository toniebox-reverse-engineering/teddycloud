/**
 * @file igmp_host.c
 * @brief IGMP host
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
#include "igmp/igmp_host.h"
#include "igmp/igmp_host_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED && IGMP_HOST_SUPPORT == ENABLED)


/**
 * @brief IGMP host initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t igmpHostInit(NetInterface *interface)
{
   IgmpHostContext *context;

   //Point to the IGMP host context
   context = &interface->igmpHostContext;

   //Clear the IGMP host context
   osMemset(context, 0, sizeof(IgmpHostContext));

   //The default host compatibility mode is IGMPv2
   context->igmpv1RouterPresent = FALSE;

   //Start IGMPv1 router present timer
   netStartTimer(&context->timer, IGMP_V1_ROUTER_PRESENT_TIMEOUT);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Join the specified host group
 * @param[in] interface Underlying network interface
 * @param[in] entry IPv4 filter entry identifying the host group to join
 * @return Error code
 **/

error_t igmpHostJoinGroup(NetInterface *interface, Ipv4FilterEntry *entry)
{
   //The all-systems group (address 224.0.0.1) is handled as a special
   //case. The host starts in Idle Member state for that group on every
   //interface and never transitions to another state
   if(entry->addr == IGMP_ALL_SYSTEMS_ADDR)
   {
      //Clear flag
      entry->flag = FALSE;
      //Enter the Idle Member state
      entry->state = IGMP_HOST_GROUP_STATE_IDLE_MEMBER;
   }
   else
   {
      //Link is up?
      if(interface->linkState)
      {
         //When a host joins a multicast group, it should immediately transmit
         //an unsolicited Membership Report for that group
         igmpHostSendMembershipReport(interface, entry->addr);

         //Set flag
         entry->flag = TRUE;
         //Start timer
         entry->timer = osGetSystemTime() + IGMP_UNSOLICITED_REPORT_INTERVAL;
         //Enter the Delaying Member state
         entry->state = IGMP_HOST_GROUP_STATE_DELAYING_MEMBER;
      }
      //Link is down?
      else
      {
         //Clear flag
         entry->flag = FALSE;
         //Enter the Idle Member state
         entry->state = IGMP_HOST_GROUP_STATE_IDLE_MEMBER;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Leave the specified host group
 * @param[in] interface Underlying network interface
 * @param[in] entry IPv4 filter entry identifying the host group to leave
 * @return Error code
 **/

error_t igmpHostLeaveGroup(NetInterface *interface, Ipv4FilterEntry *entry)
{
   //Check link state
   if(interface->linkState)
   {
      //Send a Leave Group message if the flag is set
      if(entry->flag)
      {
         igmpHostSendLeaveGroup(interface, entry->addr);
      }
   }

   //Switch to the "Non-Member" state
   entry->state = IGMP_HOST_GROUP_STATE_NON_MEMBER;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief IGMP timer handler
 *
 * This routine must be periodically called by the TCP/IP stack to
 * handle IGMP related timers
 *
 * @param[in] interface Underlying network interface
 **/

void igmpHostTick(NetInterface *interface)
{
   uint_t i;
   systime_t time;
   Ipv4FilterEntry *entry;
   IgmpHostContext *context;

   //Point to the IGMP host context
   context = &interface->igmpHostContext;

   //Get current time
   time = osGetSystemTime();

   //Check IGMP host state
   if(context->igmpv1RouterPresent)
   {
      //Check IGMPv1 router present timer
      if(netTimerExpired(&context->timer))
      {
         context->igmpv1RouterPresent = FALSE;
      }
   }

   //Go through the multicast filter table
   for(i = 0; i < IPV4_MULTICAST_FILTER_SIZE; i++)
   {
      //Point to the current entry
      entry = &interface->ipv4Context.multicastFilter[i];

      //Valid entry?
      if(entry->refCount > 0)
      {
         //Delaying Member state?
         if(entry->state == IGMP_HOST_GROUP_STATE_DELAYING_MEMBER)
         {
            //Timer expired?
            if(timeCompare(time, entry->timer) >= 0)
            {
               //Send a Membership Report message for the group on the interface
               igmpHostSendMembershipReport(interface, entry->addr);

               //Set flag
               entry->flag = TRUE;
               //Switch to the "Idle Member" state
               entry->state = IGMP_HOST_GROUP_STATE_IDLE_MEMBER;
            }
         }
      }
   }
}


/**
 * @brief Callback function for link change event
 * @param[in] interface Underlying network interface
 **/

void igmpHostLinkChangeEvent(NetInterface *interface)
{
   uint_t i;
   systime_t time;
   Ipv4FilterEntry *entry;
   IgmpHostContext *context;

   //Point to the IGMP host context
   context = &interface->igmpHostContext;

   //Get current time
   time = osGetSystemTime();

   //Link up event?
   if(interface->linkState)
   {
      //The default host compatibility mode is IGMPv2
      context->igmpv1RouterPresent = FALSE;
      //Start IGMPv1 router present timer
      netStartTimer(&context->timer, IGMP_V1_ROUTER_PRESENT_TIMEOUT);

      //Go through the multicast filter table
      for(i = 0; i < IPV4_MULTICAST_FILTER_SIZE; i++)
      {
         //Point to the current entry
         entry = &interface->ipv4Context.multicastFilter[i];

         //Valid entry?
         if(entry->refCount > 0)
         {
            //The all-systems group (address 224.0.0.1) is handled as a special
            //case. The host starts in Idle Member state for that group on every
            //interface and never transitions to another state
            if(entry->addr != IGMP_ALL_SYSTEMS_ADDR)
            {
               //Send an unsolicited Membership Report for that group
               igmpHostSendMembershipReport(interface, entry->addr);

               //Set flag
               entry->flag = TRUE;
               //Start timer
               entry->timer = time + IGMP_UNSOLICITED_REPORT_INTERVAL;
               //Enter the Delaying Member state
               entry->state = IGMP_HOST_GROUP_STATE_DELAYING_MEMBER;
            }
         }
      }
   }
   //Link down event?
   else
   {
      //Go through the multicast filter table
      for(i = 0; i < IPV4_MULTICAST_FILTER_SIZE; i++)
      {
         //Point to the current entry
         entry = &interface->ipv4Context.multicastFilter[i];

         //Valid entry?
         if(entry->refCount > 0)
         {
            //Clear flag
            entry->flag = FALSE;
            //Enter the Idle Member state
            entry->state = IGMP_HOST_GROUP_STATE_IDLE_MEMBER;
         }
      }
   }
}

#endif

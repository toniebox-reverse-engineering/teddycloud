/**
 * @file igmp_host_misc.c
 * @brief Helper functions for IGMP host
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
 * @brief Send Membership Report message
 * @param[in] interface Underlying network interface
 * @param[in] ipAddr IPv4 address specifying the group address
 * @return Error code
 **/

error_t igmpHostSendMembershipReport(NetInterface *interface, Ipv4Addr ipAddr)
{
   IgmpMessage message;
   IgmpHostContext *context;

   //Point to the IGMP host context
   context = &interface->igmpHostContext;

   //Make sure the specified address is a valid multicast address
   if(!ipv4IsMulticastAddr(ipAddr))
      return ERROR_INVALID_ADDRESS;

   //The all-systems group (224.0.0.1) is handled as a special case. The host
   //never sends a report for that group
   if(ipAddr == IGMP_ALL_SYSTEMS_ADDR)
      return ERROR_INVALID_ADDRESS;

   //The type of report is determined by the state of the interface
   if(context->igmpv1RouterPresent)
   {
      message.type = IGMP_TYPE_MEMBERSHIP_REPORT_V1;
   }
   else
   {
      message.type = IGMP_TYPE_MEMBERSHIP_REPORT_V2;
   }

   //Format the Membership Report message
   message.maxRespTime = 0;
   message.checksum = 0;
   message.groupAddr = ipAddr;

   //Message checksum calculation
   message.checksum = ipCalcChecksum(&message, sizeof(IgmpMessage));

   //The Membership Report message is sent to the group being reported
   return igmpSendMessage(interface, ipAddr, &message, sizeof(IgmpMessage));
}


/**
 * @brief Send Leave Group message
 * @param[in] interface Underlying network interface
 * @param[in] ipAddr IPv4 address specifying the group address being left
 * @return Error code
 **/

error_t igmpHostSendLeaveGroup(NetInterface *interface, Ipv4Addr ipAddr)
{
   IgmpMessage message;
   IgmpHostContext *context;

   //Point to the IGMP host context
   context = &interface->igmpHostContext;

   //Make sure the specified address is a valid multicast address
   if(!ipv4IsMulticastAddr(ipAddr))
      return ERROR_INVALID_ADDRESS;

   //The all-systems group (224.0.0.1) is handled as a special case. The host
   //never sends a Leave Group message for that group
   if(ipAddr == IGMP_ALL_SYSTEMS_ADDR)
      return ERROR_INVALID_ADDRESS;

   //If the interface state says the querier is running IGMPv1, this action
   //should be skipped
   if(context->igmpv1RouterPresent)
      return NO_ERROR;

   //Format the Leave Group message
   message.type = IGMP_TYPE_LEAVE_GROUP;
   message.maxRespTime = 0;
   message.checksum = 0;
   message.groupAddr = ipAddr;

   //Message checksum calculation
   message.checksum = ipCalcChecksum(&message, sizeof(IgmpMessage));

   //Leave Group messages are addressed to the all-routers group because other
   //group members have no need to know that a host has left the group, but it
   //does no harm to address the message to the group
   return igmpSendMessage(interface, IGMP_ALL_ROUTERS_ADDR, &message,
      sizeof(IgmpMessage));
}


/**
 * @brief Process incoming IGMP message
 * @param[in] interface Underlying network interface
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 **/

void igmpHostProcessMessage(NetInterface *interface,
   const IgmpMessage *message, size_t length)
{
   //Check IGMP message type
   if(message->type == IGMP_TYPE_MEMBERSHIP_QUERY)
   {
      //Process Membership Query message
      igmpHostProcessMembershipQuery(interface, message, length);
   }
   else if(message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V1 ||
      message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V2)
   {
      //Process Membership Report message
      igmpHostProcessMembershipReport(interface, message, length);
   }
   else
   {
      //Discard Leave Group messages
   }
}


/**
 * @brief Process incoming Membership Query message
 * @param[in] interface Underlying network interface
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 **/

void igmpHostProcessMembershipQuery(NetInterface *interface,
   const IgmpMessage *message, size_t length)
{
   uint_t i;
   systime_t time;
   systime_t maxRespTime;
   Ipv4FilterEntry *entry;
   IgmpHostContext *context;

   //The group address in the IGMP header must either be zero or a valid
   //multicast group address (refer to RFC 2236, section 6)
   if(message->groupAddr != IPV4_UNSPECIFIED_ADDR &&
      !ipv4IsMulticastAddr(message->groupAddr))
   {
      return;
   }

   //Point to the IGMP host context
   context = &interface->igmpHostContext;

   //Get current time
   time = osGetSystemTime();

   //IGMPv1 or IGMPv2 Membership Query message?
   if(message->maxRespTime == 0)
   {
      //The host has received a query with the Max Response Time field set to 0
      context->igmpv1RouterPresent = TRUE;
      //Restart IGMPv1 router present timer
      netStartTimer(&context->timer, IGMP_V1_ROUTER_PRESENT_TIMEOUT);
      //The maximum response time is 10 seconds by default
      maxRespTime = IGMP_V1_MAX_RESPONSE_TIME;
   }
   else
   {
      //The Max Resp Time field specifies the maximum time allowed before
      //sending a responding report
      maxRespTime = message->maxRespTime * 100;
   }

   //Go through the multicast filter table
   for(i = 0; i < IPV4_MULTICAST_FILTER_SIZE; i++)
   {
      //Point to the current entry
      entry = &interface->ipv4Context.multicastFilter[i];

      //Valid entry?
      if(entry->refCount > 0)
      {
         //The all-systems group (224.0.0.1) is handled as a special case. The
         //host starts in Idle Member state for that group on every interface
         //and never transitions to another state
         if(entry->addr != IGMP_ALL_SYSTEMS_ADDR)
         {
            //A General Query applies to all memberships on the interface from which
            //the Query is received. A Group-Specific Query applies to membership
            //in a single group on the interface from which the Query is received
            if(message->groupAddr == IPV4_UNSPECIFIED_ADDR ||
               message->groupAddr == entry->addr)
            {
               //Check group state
               if(entry->state == IGMP_HOST_GROUP_STATE_DELAYING_MEMBER)
               {
                  //The timer has not yet expired?
                  if(timeCompare(time, entry->timer) < 0)
                  {
                     //If a timer for the group is already running, it is reset to
                     //the random value only if the requested Max Response Time is
                     //less than the remaining value of the running timer
                     if(maxRespTime < (entry->timer - time))
                     {
                        //Restart delay timer
                        entry->timer = time + netGenerateRandRange(0, maxRespTime);
                     }
                  }
               }
               else if(entry->state == IGMP_HOST_GROUP_STATE_IDLE_MEMBER)
               {
                  //Switch to the "Delaying Member" state
                  entry->state = IGMP_HOST_GROUP_STATE_DELAYING_MEMBER;
                  //Delay the response by a random amount of time
                  entry->timer = time + netGenerateRandRange(0, maxRespTime);
               }
               else
               {
                  //Just for sanity
               }
            }
         }
      }
   }
}


/**
 * @brief Process incoming Membership Report message
 * @param[in] interface Underlying network interface
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 **/

void igmpHostProcessMembershipReport(NetInterface *interface,
   const IgmpMessage *message, size_t length)
{
   uint_t i;
   Ipv4FilterEntry *entry;

   //The group address in the IGMP header must be a valid multicast group
   //address
   if(!ipv4IsMulticastAddr(message->groupAddr))
      return;

   //Go through the multicast filter table
   for(i = 0; i < IPV4_MULTICAST_FILTER_SIZE; i++)
   {
      //Point to the current entry
      entry = &interface->ipv4Context.multicastFilter[i];

      //Valid entry?
      if(entry->refCount > 0)
      {
         //Report messages are ignored for memberships in the Non-Member or
         //Idle Member state
         if(entry->state == IGMP_HOST_GROUP_STATE_DELAYING_MEMBER)
         {
            //The Membership Report message matches the current entry?
            if(message->groupAddr == entry->addr)
            {
               //Clear flag
               entry->flag = FALSE;
               //Switch to the "Idle Member" state
               entry->state = IGMP_HOST_GROUP_STATE_IDLE_MEMBER;
            }
         }
      }
   }
}

#endif

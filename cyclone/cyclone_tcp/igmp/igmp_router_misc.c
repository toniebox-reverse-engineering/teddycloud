/**
 * @file igmp_router_misc.c
 * @brief Helper functions fore IGMP router
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
#include "igmp/igmp_router.h"
#include "igmp/igmp_router_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED && IGMP_ROUTER_SUPPORT == ENABLED)


/**
 * @brief Send General Query message
 * @param[in] context Pointer to the IGMP router context
 * @return Error code
 **/

error_t igmpRouterSendGeneralQuery(IgmpRouterContext *context)
{
   //A General Query is addressed to the all-systems multicast group, has a
   //Group Address field of zero, and has a Max Response Time of Query Response
   //Interval
   return igmpRouterSendMembershipQuery(context, IGMP_ALL_SYSTEMS_ADDR,
      IPV4_UNSPECIFIED_ADDR, IGMP_QUERY_RESPONSE_INTERVAL);
}


/**
 * @brief Send Group-Specific Query message
 * @param[in] context Pointer to the IGMP router context
 * @param[in] groupAddr Multicast address of the group being queried
 * @return Error code
 **/

error_t igmpRouterSendGroupSpecificQuery(IgmpRouterContext *context,
   Ipv4Addr groupAddr)
{
   //The Group-Specific Query is sent to the group being queried, and has a
   //Max Response Time of Last Member Query Interval
   return igmpRouterSendMembershipQuery(context, groupAddr, groupAddr,
      IGMP_LAST_MEMBER_QUERY_INTERVAL);
}


/**
 * @brief Send Membership Query message
 * @param[in] context Pointer to the IGMP router context
 * @param[in] destAddr Destination IP address
 * @param[in] groupAddr Multicast group address
 * @param[in] maxRespTime Maximum response time
 * @return Error code
 **/

error_t igmpRouterSendMembershipQuery(IgmpRouterContext *context,
   Ipv4Addr destAddr, Ipv4Addr groupAddr, systime_t maxRespTime)
{
   IgmpMessage message;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->interface;

   //Format Membership Query message
   message.type = IGMP_TYPE_MEMBERSHIP_QUERY;
   message.checksum = 0;

   //IGMPv1 compatibility mode?
   if(context->version == IGMP_VERSION_1)
   {
      //When in IGMPv1 mode, routers must send Periodic Queries with a Max
      //Response Time of 0 (refer to RFC 2236, section 4)
      message.maxRespTime = 0;
   }
   else
   {
      //The Max Response Time field is meaningful only in Membership Query
      //messages, and specifies the maximum allowed time before sending a
      //responding report in units of 1/10 second
      message.maxRespTime = (uint8_t) (maxRespTime / 100);
   }

   //In a Membership Query message, the group address field is set to zero
   //when sending a General Query, and set to the group address being queried
   //when sending a Group-Specific Query
   message.groupAddr = groupAddr;

   //Message checksum calculation
   message.checksum = ipCalcChecksum(&message, sizeof(IgmpMessage));

   //The Membership Report message is sent to the group being reported
   return igmpSendMessage(interface, destAddr, &message, sizeof(IgmpMessage));
}


/**
 * @brief Process incoming IGMP message
 * @param[in] context Pointer to the IGMP router context
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 **/

void igmpRouterProcessMessage(IgmpRouterContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message, size_t length)
{
   //Check IGMP message type
   if(message->type == IGMP_TYPE_MEMBERSHIP_QUERY)
   {
      //Process Membership Query message
      igmpRouterProcessMembershipQuery(context, pseudoHeader, message, length);
   }
   else if(message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V1 ||
      message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V2)
   {
      //Process Membership Report message
      igmpRouterProcessMembershipReport(context, pseudoHeader, message, length);
   }
   else if(message->type == IGMP_TYPE_LEAVE_GROUP)
   {
      //Process Leave Group message
      igmpRouterProcessLeaveGroup(context, pseudoHeader, message, length);
   }
   else
   {
      //Discard unrecognized IGMP messages
   }
}


/**
 * @brief Process incoming Membership Query message
 * @param[in] context Pointer to the IGMP router context
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 **/

void igmpRouterProcessMembershipQuery(IgmpRouterContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message, size_t length)
{
   systime_t maxRespTime;
   IgmpRouterGroup *group;
   NetInterface *interface;

   //The group address in the IGMP header must either be zero or a valid
   //multicast group address (refer to RFC 2236, section 6)
   if(message->groupAddr != IPV4_UNSPECIFIED_ADDR &&
      !ipv4IsMulticastAddr(message->groupAddr))
   {
      return;
   }

   //Point to the underlying network interface
   interface = context->interface;

   //IGMPv1 or IGMPv2 Membership Query message?
   if(message->maxRespTime == 0)
   {
      //The maximum response time is 10 seconds by default
      maxRespTime = IGMP_V1_MAX_RESPONSE_TIME;
   }
   else
   {
      //The Max Resp Time field specifies the maximum time allowed before
      //sending a responding report
      maxRespTime = message->maxRespTime * 100;
   }

   //Valid source address?
   if(pseudoHeader->srcAddr != IPV4_UNSPECIFIED_ADDR)
   {
      //Check whether the IGMP Membership Query is received from a router on
      //the same network with a lower IP address
      if(htonl(pseudoHeader->srcAddr) < htonl(interface->ipv4Context.addrList[0].addr))
      {
         //Start Other Querier Present timer
         netStartTimer(&context->otherQuerierPresentTimer,
            IGMP_OTHER_QUERIER_PRESENT_INTERVAL);

         //Switch to the "Non Querier" state
         context->state = IGMP_ROUTER_STATE_NON_QUERIER;
      }
   }

   //There are two sub-types of Membership Query messages. These two messages
   //are differentiated by the Group Address (refer to RFC 2236, section 2.1)
   if(message->groupAddr == IPV4_UNSPECIFIED_ADDR)
   {
      //General Queries are used to learn which groups have members on an
      //attached network
   }
   else if(ipv4IsMulticastAddr(message->groupAddr))
   {
      //Group-Specific Queries are used to learn if a particular group has any
      //members on an attached network
      group = igmpRouterFindGroup(context, message->groupAddr);

      //Valid multicast group?
      if(group != NULL)
      {
         //Non-Querier router?
         if(context->state == IGMP_ROUTER_STATE_NON_QUERIER)
         {
            //"Members Present" state?
            if(group->state == IGMP_ROUTER_GROUP_STATE_MEMBERS_PRESENT)
            {
               //Non-Queriers do not send any messages and are only driven by
               //message reception (refer to RFC 2236, section 7)
               group->lastMemberQueryCount = 0;

               //Set the timer to [Max Response Time] * [Last Member Query Count]
               //if this router is a non-Querier
               netStartTimer(&group->timer, maxRespTime * 100 *
                  IGMP_LAST_MEMBER_QUERY_COUNT);

               //Switch to the "Checking Membership" state
               group->state = IGMP_ROUTER_GROUP_STATE_CHECKING_MEMBERSHIP;
            }
            else
            {
               //When a non-Querier receives a Group-Specific Query message,
               //if its existing group membership timer is greater than [Last
               //Member Query Count] times the Max Response Time specified in
               //the message, it sets its group membership timer to that value
            }
         }
      }
   }
   else
   {
      //The group address in the IGMP header must either be zero or a valid
      //multicast group address (refer to RFC 2236, section 6)
   }
}


/**
 * @brief Process incoming Membership Report message
 * @param[in] context Pointer to the IGMP router context
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 **/

void igmpRouterProcessMembershipReport(IgmpRouterContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message, size_t length)
{
   IgmpRouterGroup *group;

   //The group address in the IGMP header must be a valid multicast group
   //address
   if(!ipv4IsMulticastAddr(message->groupAddr))
      return;

   //In a Membership Report, the group address field holds the IP multicast
   //group address of the group being reported (refer to RFC 2236, section 2.4)
   group = igmpRouterFindGroup(context, message->groupAddr);

   //First report received for this multicast group?
   if(group == NULL)
   {
      //Create a new multicast group
      group = igmpRouterCreateGroup(context, message->groupAddr);
   }

   //Valid multicast group?
   if(group != NULL)
   {
      //Version 1 Membership Report received by a non-Querier router?
      if(context->state == IGMP_ROUTER_STATE_QUERIER &&
         message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V1)
      {
         //Start the timer for the group membership
         netStartTimer(&group->timer, IGMP_GROUP_MEMBERSHIP_INTERVAL);
         //Start IGMPv1 Host timer
         netStartTimer(&group->v1HostTimer, IGMP_GROUP_MEMBERSHIP_INTERVAL);

         //Switch to the "V1 Members Present" state
         group->state = IGMP_ROUTER_GROUP_STATE_V1_MEMBERS_PRESENT;
      }
      else
      {
         //Start the timer for the group membership
         netStartTimer(&group->timer, IGMP_GROUP_MEMBERSHIP_INTERVAL);

         //"No Members Present", "Members Present" or "Checking Membership" state?
         if(group->state != IGMP_ROUTER_GROUP_STATE_V1_MEMBERS_PRESENT)
         {
            //Switch to the "Members Present" state
            group->state = IGMP_ROUTER_GROUP_STATE_MEMBERS_PRESENT;
         }
      }
   }
}


/**
 * @brief Process incoming Leave Group message
 * @param[in] context Pointer to the IGMP router context
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 **/

void igmpRouterProcessLeaveGroup(IgmpRouterContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message, size_t length)
{
   IgmpRouterGroup *group;

   //Routers should accept a Leave Group message addressed to the group being
   //left, in order to accommodate implementations of an earlier version of
   //this standard (refer to RFC 2236, section 3)
   if(pseudoHeader->destAddr != IGMP_ALL_ROUTERS_ADDR &&
      pseudoHeader->destAddr != message->groupAddr)
   {
      return;
   }

   //When in IGMPv1 mode, routers must ignore Leave Group messages (refer to
   //RFC 2236, section 4)
   if(context->version == IGMP_VERSION_1)
      return;

   //Non-Queriers must ignore Leave Group messages (refer to RFC 2236,
   //section 3)
   if(context->state != IGMP_ROUTER_STATE_QUERIER)
      return;

   //The group address in the IGMP header must be a valid multicast group
   //address
   if(!ipv4IsMulticastAddr(message->groupAddr))
      return;

   //In a Leave Group message, the group address field holds the IP multicast
   //group address of the group being left (refer to RFC 2236, section 2.4)
   group = igmpRouterFindGroup(context, message->groupAddr);

   //Queriers should ignore Leave Group messages for which there are no
   //group members on the reception interface (refer to RFC 2236, section 3)
   if(group != NULL)
   {
      //"Members Present" state?
      if(group->state == IGMP_ROUTER_GROUP_STATE_MEMBERS_PRESENT)
      {
         //When a Querier receives a Leave Group message for a group that has
         //group members on the reception interface, it sends Group-Specific
         //Queries to the group being left
         igmpRouterSendGroupSpecificQuery(context, group->addr);

         //Start retransmit timer for the group membership
         netStartTimer(&group->retransmitTimer, IGMP_LAST_MEMBER_QUERY_INTERVAL);

         //Number of Group-Specific Queries left to sent before the router
         //assumes there are no local members
         group->lastMemberQueryCount = IGMP_LAST_MEMBER_QUERY_COUNT - 1;

         //Set the timer to [Last Member Query Interval] * [Last Member
         //Query Count] if this router is a Querier
         netStartTimer(&group->timer, IGMP_LAST_MEMBER_QUERY_INTERVAL *
            IGMP_LAST_MEMBER_QUERY_COUNT);

         //Switch to the "Checking Membership" state
         group->state = IGMP_ROUTER_GROUP_STATE_CHECKING_MEMBERSHIP;
      }
   }
}


/**
 * @brief Create a new multicast group
 * @param[in] context Pointer to the IGMP router context
 * @param[in] groupAddr Multicast group address
 * @return Pointer to the newly created multicast group
 **/

IgmpRouterGroup *igmpRouterCreateGroup(IgmpRouterContext *context,
   Ipv4Addr groupAddr)
{
   uint_t i;
   IgmpRouterGroup *group;

   //Initialize pointer
   group = NULL;

   //Loop through multicast groups
   for(i = 0; i < context->numGroups; i++)
   {
      //Check whether the entry is available
      if(context->groups[i].state == IGMP_ROUTER_GROUP_STATE_NO_MEMBERS_PRESENT)
      {
         //Point to the current group
         group = &context->groups[i];
         //Save the multicast group address
         group->addr = groupAddr;

         //Any registered callback?
         if(context->addMcastRouteCallback != NULL)
         {
            //Notify the routing protocol that there are members of this group
            //on this connected network
            context->addMcastRouteCallback(context, group->addr,
               context->interface);
         }

         //We are done
         break;
      }
   }

   //Return a pointer to the newly created multicast group
   return group;
}


/**
 * @brief Search the list of multicast groups for a given group address
 * @param[in] context Pointer to the IGMP router context
 * @param[in] groupAddr Multicast group address
 * @return Pointer to the matching multicast group, if any
 **/

IgmpRouterGroup *igmpRouterFindGroup(IgmpRouterContext *context,
   Ipv4Addr groupAddr)
{
   uint_t i;
   IgmpRouterGroup *group;

   //Initialize pointer
   group = NULL;

   //Loop through multicast groups
   for(i = 0; i < context->numGroups; i++)
   {
      //Check whether there are hosts on the network which have sent reports
      //for this multicast group
      if(context->groups[i].state != IGMP_ROUTER_GROUP_STATE_NO_MEMBERS_PRESENT &&
         context->groups[i].addr == groupAddr)
      {
         //Point to the current group
         group = &context->groups[i];
         break;
      }
   }

   //Return a pointer to the matching multicast group
   return group;
}


/**
 * @brief Delete a multicast group
 * @param[in] context Pointer to the IGMP router context
 * @param[in] group Multicast group
 **/

void igmpRouterDeleteGroup(IgmpRouterContext *context, IgmpRouterGroup *group)
{
   //Any registered callback?
   if(context->deleteMcastRouteCallback != NULL)
   {
      //Notify the routing protocol that there are no longer any members of
      //this group on this connected network
      context->deleteMcastRouteCallback(context, group->addr,
         context->interface);
   }

   //Groups in "No Members Present" state require no storage in the router
   group->state = IGMP_ROUTER_GROUP_STATE_NO_MEMBERS_PRESENT;
}

#endif

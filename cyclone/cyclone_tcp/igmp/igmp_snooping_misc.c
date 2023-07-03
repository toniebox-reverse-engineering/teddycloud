/**
 * @file igmp_snooping_misc.c
 * @brief Helper functions for IGMP snooping switch
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
#include "ipv4/ipv4_misc.h"
#include "igmp/igmp_snooping.h"
#include "igmp/igmp_snooping_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED && IGMP_SNOOPING_SUPPORT == ENABLED)


/**
 * @brief Process incoming IGMP message
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 **/

void igmpSnoopingProcessMessage(IgmpSnoopingContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length, NetRxAncillary *ancillary)
{
   //Check the ingress port the IGMP message was received on
   if(ancillary->port == 0)
   {
      return;
   }
   else if(ancillary->port == SWITCH_CPU_PORT)
   {
   }
   else if(ancillary->port > context->numPorts)
   {
      return;
   }

   //Check IGMP message type
   if(message->type == IGMP_TYPE_MEMBERSHIP_QUERY)
   {
      //Process Membership Query message
      igmpSnoopingProcessMembershipQuery(context, pseudoHeader, message,
         length, ancillary);
   }
   else if(message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V1 ||
      message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V2)
   {
      //Process Membership Report message
      igmpSnoopingProcessMembershipReport(context, pseudoHeader, message,
         length, ancillary);
   }
   else if(message->type == IGMP_TYPE_LEAVE_GROUP)
   {
      //Process Leave Group message
      igmpSnoopingProcessLeaveGroup(context, pseudoHeader, message,
         length, ancillary);
   }
   else
   {
      //Process unrecognized IGMP messages
      igmpSnoopingProcessUnknownMessage(context, pseudoHeader, message,
         length, ancillary);
   }
}


/**
 * @brief Process incoming Membership Query message
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 **/

void igmpSnoopingProcessMembershipQuery(IgmpSnoopingContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length, NetRxAncillary *ancillary)
{
   uint_t i;
   uint32_t portMap;
   systime_t maxRespTime;
   IgmpSnoopingPort *port;
   IgmpSnoopingGroup *group;

   //The group address in the IGMP header must either be zero or a valid
   //multicast group address (refer to RFC 2236, section 6)
   if(message->groupAddr != IPV4_UNSPECIFIED_ADDR &&
      !ipv4IsMulticastAddr(message->groupAddr))
   {
      return;
   }

   //Point to snooping switch port
   port = &context->ports[ancillary->port - 1];

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

   //A switch supporting IGMP snooping must maintain a list of multicast
   //routers and the ports on which they are attached. This list can be
   //constructed by checking the arrival port for IGMP Queries (sent by
   //multicast routers) where the source address is not 0.0.0.0
   if(pseudoHeader->srcAddr != IPV4_UNSPECIFIED_ADDR)
   {
      //Check whether a new router has been detected
      if(!port->routerPresent)
      {
         //Update the list of router ports
         port->routerPresent = TRUE;

         //The snooping switch must update its forwarding table when the list of
         //router ports has changed
         for(i = 0; i < context->numGroups; i++)
         {
            //Point to the current group
            group = &context->groups[i];

            //Check whether there are hosts on the network which have sent reports
            //for this multicast group
            if(group->state != IGMP_SNOOPING_GROUP_STATE_NO_MEMBERS_PRESENT)
            {
               //Update the corresponding entry in forwarding table
               igmpSnoopingUpdateStaticFdbEntry(context, group->addr);
            }
         }

         //Check whether unregistered packets should be forwarded to router
         //ports only
         if(!context->floodUnknownMulticastPackets)
         {
            //Retrieve the port map identifying router ports
            portMap = igmpSnoopingGetRouterPorts(context);

            //Forward unknown multicast packets on all ports to which
            //an IGMP router is attached
            igmpSnoopingSetUnknownMcastFwdPorts(context, TRUE, portMap);
         }
      }

      //Start timer
      netStartTimer(&port->timer, IGMP_OTHER_QUERIER_PRESENT_INTERVAL);
   }

   //Group-Specific Query received?
   if(ipv4IsMulticastAddr(message->groupAddr))
   {
      //Group-Specific Queries are used to learn if a particular group has any
      //members on an attached network
      for(i = 0; i < context->numGroups; i++)
      {
         //Point to the current group
         group = &context->groups[i];

         //"Members Present" state?
         if(group->state == IGMP_SNOOPING_GROUP_STATE_MEMBERS_PRESENT &&
            group->addr == message->groupAddr)
         {
            //Set the timer to [Max Response Time] * [Last Member Query Count]
            netStartTimer(&group->timer, maxRespTime * 100 *
               IGMP_LAST_MEMBER_QUERY_COUNT);

            //Switch to the "Checking Membership" state
            group->state = IGMP_SNOOPING_GROUP_STATE_CHECKING_MEMBERSHIP;
         }
      }
   }

   //Flood all ports except the port the message was received on
   portMap = ((1 << context->numPorts) - 1) & ~(1 << (ancillary->port - 1));

   //Forward the IGMP message
   if(portMap != 0)
   {
      igmpSnoopingForwardMessage(context, portMap, &ancillary->destMacAddr,
         pseudoHeader, message, length);
   }
}


/**
 * @brief Process incoming Membership Report message
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 **/

void igmpSnoopingProcessMembershipReport(IgmpSnoopingContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length, NetRxAncillary *ancillary)
{
   uint32_t portMap;
   IgmpSnoopingGroup *group;

   //The group address in the IGMP header must be a valid multicast group
   //address
   if(!ipv4IsMulticastAddr(message->groupAddr))
      return;

   //In a Membership Report, the group address field holds the IP multicast
   //group address of the group being reported (refer to RFC 2236, section 2.4)
   group = igmpSnoopingFindGroup(context, message->groupAddr, ancillary->port);

   //First report received for this multicast group?
   if(group == NULL)
   {
      //Create a new multicast group
      group = igmpSnoopingCreateGroup(context, message->groupAddr, ancillary->port);
   }

   //Valid multicast group?
   if(group != NULL)
   {
      //Start timer
      netStartTimer(&group->timer, IGMP_GROUP_MEMBERSHIP_INTERVAL);
      //Switch to the "Members Present" state
      group->state = IGMP_SNOOPING_GROUP_STATE_MEMBERS_PRESENT;
   }

   //A snooping switch should forward IGMP Membership Reports only to ports
   //where multicast routers are attached (refer to RFC 4541, section 2.1.1)
   portMap = igmpSnoopingGetRouterPorts(context);

   //An administrative control may be provided to override this restriction,
   //allowing the report messages to be flooded to other ports
   if(context->floodReports)
   {
      portMap = ((1 << context->numPorts) - 1);
   }

   //Prevent the message from being forwarded to the port on which it arrived
   portMap &= ~(1 << (ancillary->port - 1));

   //Forward the IGMP message
   if(portMap != 0)
   {
      igmpSnoopingForwardMessage(context, portMap, &ancillary->destMacAddr,
         pseudoHeader, message, length);
   }
}


/**
 * @brief Process incoming Leave Group message
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 **/

void igmpSnoopingProcessLeaveGroup(IgmpSnoopingContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length, NetRxAncillary *ancillary)
{
   uint32_t portMap;
   IgmpSnoopingGroup *group;

   //The group address in the IGMP header must be a valid multicast group
   //address
   if(!ipv4IsMulticastAddr(message->groupAddr))
      return;

   //In a Leave Group message, the group address field holds the IP multicast
   //group address of the group being left (refer to RFC 2236, section 2.4)
   group = igmpSnoopingFindGroup(context, message->groupAddr, ancillary->port);

   //Valid multicast group?
   if(group != NULL)
   {
      //Ignore Leave Group messages for which there are no group members
      if(group->state == IGMP_SNOOPING_GROUP_STATE_MEMBERS_PRESENT)
      {
         //The Last Member Query Time represents the  "leave latency", or the
         //difference between the transmission of a membership change and the
         //change in the information given to the routing protocol
         netStartTimer(&group->timer, context->lastMemberQueryTime);

         //Switch to the "Checking Membership" state
         group->state = IGMP_SNOOPING_GROUP_STATE_CHECKING_MEMBERSHIP;
      }
   }

   //Flood all ports except the port the message was received on
   portMap = ((1 << context->numPorts) - 1) & ~(1 << (ancillary->port - 1));

   //Forward the IGMP message
   if(portMap != 0)
   {
      igmpSnoopingForwardMessage(context, portMap, &ancillary->destMacAddr,
         pseudoHeader, message, length);
   }
}


/**
 * @brief Process unrecognized IGMP messages
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] message Pointer to the incoming IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 **/

void igmpSnoopingProcessUnknownMessage(IgmpSnoopingContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length, NetRxAncillary *ancillary)
{
   uint32_t portMap;

   //A switch that supports IGMP snooping must flood all unrecognized IGMP
   //messages to all other ports and must not attempt to make use of any
   //information beyond the end of the network layer header
   portMap = ((1 << context->numPorts) - 1) & ~(1 << (ancillary->port - 1));

   //Forward the IGMP message
   if(portMap != 0)
   {
      igmpSnoopingForwardMessage(context, portMap, &ancillary->destMacAddr,
         pseudoHeader, message, length);
   }
}


/**
 * @brief Forward an IGMP message to the desired ports
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] forwardPorts Port map
 * @param[in] destMacAddr Destination MAC address
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] message Pointer to the IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 **/

error_t igmpSnoopingForwardMessage(IgmpSnoopingContext *context,
   uint32_t forwardPorts, const MacAddr *destMacAddr,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length)
{
   error_t error;
   size_t offset;
   NetBuffer *buffer;
   NetTxAncillary ancillary;

   //Debug message
   TRACE_INFO("Forwarding IGMP message (%" PRIuSIZE " bytes)...\r\n", length);
   //Dump port map
   TRACE_INFO("  Switch Port Map = 0x%02" PRIX8 "\r\n", forwardPorts);

   //Allocate a memory buffer to hold an IGMP message
   buffer = ipAllocBuffer(0, &offset);

   //Successful memory allocation?
   if(buffer != NULL)
   {
      //Copy the IGMP message
      error = netBufferAppend(buffer, message, length);

      //Check status code
      if(!error)
      {
         //Additional options can be passed to the stack along with the packet
         ancillary = NET_DEFAULT_TX_ANCILLARY;

         //All IGMP messages are sent with an IP TTL of 1 and contain an IP
         //Router Alert option in their IP header (refer to RFC 2236, section 2)
         ancillary.ttl = IGMP_TTL;
         ancillary.routerAlert = TRUE;

         //Specify egress ports
         ancillary.ports = forwardPorts;

         //Override port state if necessary
         if(!context->floodUnknownMulticastPackets)
         {
            ancillary.override = TRUE;
         }

         //Forward the IGMP message
         error = ipv4SendDatagram(context->interface, pseudoHeader, buffer,
            offset, &ancillary);
      }

      //Free previously allocated memory
      netBufferFree(buffer);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Create a new multicast group
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] groupAddr Multicast group address
 * @param[in] port Port number associated with the multicast group
 * @return Pointer to the newly created multicast group
 **/

IgmpSnoopingGroup *igmpSnoopingCreateGroup(IgmpSnoopingContext *context,
   Ipv4Addr groupAddr, uint8_t port)
{
   uint_t i;
   IgmpSnoopingGroup *group;

   //Initialize pointer
   group = NULL;

   //Loop through multicast groups
   for(i = 0; i < context->numGroups; i++)
   {
      //Check whether the entry is available
      if(context->groups[i].state == IGMP_SNOOPING_GROUP_STATE_NO_MEMBERS_PRESENT)
      {
         //Point to the current group
         group = &context->groups[i];

         //Switch to the "Members Present" state
         group->state = IGMP_SNOOPING_GROUP_STATE_MEMBERS_PRESENT;
         //Save the multicast group address
         group->addr = groupAddr;
         //Save port number
         group->port = port;

         //Update the corresponding entry in forwarding table
         igmpSnoopingUpdateStaticFdbEntry(context, groupAddr);

         //We are done
         break;
      }
   }

   //Return a pointer to the newly created multicast group
   return group;
}


/**
 * @brief Search the list of multicast groups for a given group address
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] groupAddr Multicast group address
 * @param[in] port Port number
 * @return Pointer to the matching multicast group, if any
 **/

IgmpSnoopingGroup *igmpSnoopingFindGroup(IgmpSnoopingContext *context,
   Ipv4Addr groupAddr, uint8_t port)
{
   uint_t i;
   IgmpSnoopingGroup *group;

   //Initialize pointer
   group = NULL;

   //Loop through multicast groups
   for(i = 0; i < context->numGroups; i++)
   {
      //Check whether there are hosts on this port which have sent reports for
      //this multicast group
      if(context->groups[i].state != IGMP_SNOOPING_GROUP_STATE_NO_MEMBERS_PRESENT &&
         context->groups[i].addr == groupAddr &&
         context->groups[i].port == port)
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
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] group Multicast group
 **/

void igmpSnoopingDeleteGroup(IgmpSnoopingContext *context,
   IgmpSnoopingGroup *group)
{
   //Switch to the "No Members Present" state
   group->state = IGMP_SNOOPING_GROUP_STATE_NO_MEMBERS_PRESENT;

   //Update the corresponding entry in forwarding table
   igmpSnoopingUpdateStaticFdbEntry(context, group->addr);
}


/**
 * @brief Enable IGMP monitoring
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] enable Enable or disable MLD monitoring
 **/

void igmpSnoopingEnableMonitoring(IgmpSnoopingContext *context, bool_t enable)
{
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->interface;

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->enableIgmpSnooping != NULL)
   {
      //Enable IGMP snooping
      interface->switchDriver->enableIgmpSnooping(interface, enable);
   }
}


/**
 * @brief Update a entry of the static MAC table
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] groupAddr Multicast group address to be updated
 **/

void igmpSnoopingUpdateStaticFdbEntry(IgmpSnoopingContext *context,
   Ipv4Addr groupAddr)
{
   uint_t i;
   uint32_t forwardPorts;
   SwitchFdbEntry entry;
   NetInterface *interface;
   IgmpSnoopingGroup *group;

   //Clear port map
   forwardPorts = 0;

   //Point to the underlying network interface
   interface = context->interface;

   //Packets should be forwarded according to group-based port membership
   //tables (refer to RFC 4541, section 2.1.2)
   for(i = 0; i < context->numGroups; i++)
   {
      //Point to the current group
      group = &context->groups[i];

      //Check whether there are hosts on this port which have sent reports for
      //this multicast group
      if(group->state != IGMP_SNOOPING_GROUP_STATE_NO_MEMBERS_PRESENT &&
         group->addr == groupAddr)
      {
         //Valid port number?
         if(group->port > 0 && group->port <= context->numPorts)
         {
            forwardPorts |= (1 << (group->port - 1));
         }
         else
         {
            forwardPorts |= SWITCH_CPU_PORT_MASK;
         }
      }
   }

   //Check whether this multicast group has any members
   if(forwardPorts != 0)
   {
      //Packets must also be forwarded on router ports
      forwardPorts |= igmpSnoopingGetRouterPorts(context);

      //Valid switch driver?
      if(interface->switchDriver != NULL &&
         interface->switchDriver->addStaticFdbEntry != NULL)
      {
         //Format forwarding database entry
         ipv4MapMulticastAddrToMac(groupAddr, &entry.macAddr);
         entry.srcPort = 0;
         entry.destPorts = forwardPorts;
         entry.override = FALSE;

         //Debug message
         TRACE_DEBUG("IGMP Snooping: Adding FDB entry...\r\n");
         TRACE_DEBUG("  MAC Address: %s\r\n", macAddrToString(&entry.macAddr, NULL));
         TRACE_DEBUG("  Forward Ports: 0x%08X\r\n", entry.destPorts);

         //Update the static MAC table of the switch
         interface->switchDriver->addStaticFdbEntry(context->interface, &entry);
      }
   }
   else
   {
      //Valid switch driver?
      if(interface->switchDriver != NULL &&
         interface->switchDriver->deleteStaticFdbEntry != NULL)
      {
         //Format forwarding database entry
         ipv4MapMulticastAddrToMac(groupAddr, &entry.macAddr);
         entry.srcPort = 0;
         entry.destPorts = 0;
         entry.override = FALSE;

         //Debug message
         TRACE_DEBUG("IGMP Snooping: Deleting FDB entry...\r\n");
         TRACE_DEBUG("  MAC Address: %s\r\n", macAddrToString(&entry.macAddr, NULL));

         //Update the static MAC table of the switch
         interface->switchDriver->deleteStaticFdbEntry(context->interface,
            &entry);
      }
   }
}


/**
 * @brief Set forward ports for unknown multicast packets
 * @param[in] context Pointer to the IGMP snooping switch context
 * @param[in] enable Enable or disable forwarding of unknown multicast packets
 * @param[in] forwardPorts Port map
 **/

void igmpSnoopingSetUnknownMcastFwdPorts(IgmpSnoopingContext *context,
   bool_t enable, uint32_t forwardPorts)
{
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->interface;

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->setUnknownMcastFwdPorts != NULL)
   {
      interface->switchDriver->setUnknownMcastFwdPorts(context->interface,
         enable, forwardPorts);
   }
}


/*
 * @brief Retrieve the port map identifying router ports
 * @param[in] context Pointer to the IGMP snooping switch context
 * @return Port map identifying router ports
 **/

uint32_t igmpSnoopingGetRouterPorts(IgmpSnoopingContext *context)
{
   uint_t i;
   uint32_t routerPorts;

   //Clear port map
   routerPorts = 0;

   //Loop through the list of multicast routers
   for(i = 0; i < context->numPorts; i++)
   {
      //Check whether any IGMP router is attached to this port
      if(context->ports[i].routerPresent)
      {
         routerPorts |= (1 << i);
      }
   }

   //Return the port map that identifies router ports
   return routerPorts;
}

#endif

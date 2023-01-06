/**
 * @file igmp_common.c
 * @brief Definitions common to IGMP host, router and snooping switch
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
#include "igmp/igmp_host.h"
#include "igmp/igmp_host_misc.h"
#include "igmp/igmp_router.h"
#include "igmp/igmp_router_misc.h"
#include "igmp/igmp_snooping.h"
#include "igmp/igmp_snooping_misc.h"
#include "igmp/igmp_common.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED && (IGMP_HOST_SUPPORT == ENABLED || \
   IGMP_ROUTER_SUPPORT == ENABLED || IGMP_SNOOPING_SUPPORT == ENABLED))

//Tick counter to handle periodic operations
systime_t igmpTickCounter;


/**
 * @brief IGMP initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t igmpInit(NetInterface *interface)
{
   error_t error;

   //Join the all-systems group
   error = ipv4JoinMulticastGroup(interface, IGMP_ALL_SYSTEMS_ADDR);
   //Any error to report?
   if(error)
      return error;

#if (IGMP_HOST_SUPPORT == ENABLED)
   //IGMP host initialization
   error = igmpHostInit(interface);
   //Any error to report?
   if(error)
      return error;
#endif

   //Successful initialization
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

void igmpTick(NetInterface *interface)
{
#if (IGMP_HOST_SUPPORT == ENABLED)
   //Manage IGMP host timers
   igmpHostTick(interface);
#endif

#if (IGMP_ROUTER_SUPPORT == ENABLED)
   //Valid IGMP router context?
   if(interface->igmpRouterContext != NULL)
   {
      //Manage IGMP router timers
      igmpRouterTick(interface->igmpRouterContext);
   }
#endif

#if (IGMP_SNOOPING_SUPPORT == ENABLED)
   //Valid IGMP snooping switch context?
   if(interface->igmpSnoopingContext != NULL)
   {
      //Manage IGMP snooping switch timers
      igmpSnoopingTick(interface->igmpSnoopingContext);
   }
#endif
}


/**
 * @brief Callback function for link change event
 * @param[in] interface Underlying network interface
 **/

void igmpLinkChangeEvent(NetInterface *interface)
{
#if (IGMP_HOST_SUPPORT == ENABLED)
   //Notify the IGMP host of link state changes
   igmpHostLinkChangeEvent(interface);
#endif
}


/**
 * @brief Send IGMP message
 * @param[in] interface Underlying network interface
 * @param[in] destAddr Destination IP address
 * @param[in] message Pointer to the IGMP message
 * @param[in] length Length of the IGMP message, in bytes
 * @return Error code
 **/

error_t igmpSendMessage(NetInterface *interface, Ipv4Addr destAddr,
   const IgmpMessage *message, size_t length)
{
   error_t error;
   Ipv4PseudoHeader pseudoHeader;

   //Initialize status code
   error = NO_ERROR;

   //Format IPv4 pseudo header
   pseudoHeader.srcAddr = interface->ipv4Context.addrList[0].addr;
   pseudoHeader.destAddr = destAddr;
   pseudoHeader.reserved = 0;
   pseudoHeader.protocol = IPV4_PROTOCOL_IGMP;
   pseudoHeader.length = htons(length);

   //Debug message
   TRACE_INFO("Sending IGMP message (%" PRIuSIZE " bytes)...\r\n", length);
   //Dump message contents for debugging purpose
   igmpDumpMessage(message);

#if (IGMP_SNOOPING_SUPPORT == ENABLED)
   //Valid IGMP snooping switch context?
   if(interface->igmpSnoopingContext != NULL)
   {
      NetRxAncillary ancillary;

      //Additional options can be passed to the stack along with the packet
      ancillary = NET_DEFAULT_RX_ANCILLARY;
      //Specify ingress port
      ancillary.port = SWITCH_CPU_PORT;

      //Forward the message to the IGMP snooping switch
      igmpSnoopingProcessMessage(interface->igmpSnoopingContext, &pseudoHeader,
         message, length, &ancillary);
   }
   else
#endif
   {
      size_t offset;
      NetBuffer *buffer;
      NetTxAncillary ancillary;

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

            //All IGMP messages are sent with an IP TTL of 1 and contain an IP Router
            //Alert option in their IP header (refer to RFC 2236, section 2)
            ancillary.ttl = IGMP_TTL;
            ancillary.routerAlert = TRUE;

            //Send the IGMP message
            error = ipv4SendDatagram(interface, &pseudoHeader, buffer, offset,
               &ancillary);
         }

         //Free previously allocated memory
         netBufferFree(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

#if (IGMP_HOST_SUPPORT == ENABLED && IGMP_ROUTER_SUPPORT == ENABLED)
   //Check IGMP message type
   if(message->type == IGMP_TYPE_MEMBERSHIP_QUERY)
   {
      //Forward Membership Query messages to the IGMP host
      igmpHostProcessMessage(interface, message, length);
   }
   else if(message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V1 ||
      message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V2 ||
      message->type == IGMP_TYPE_LEAVE_GROUP)
   {
      //Valid IGMP router context?
      if(interface->igmpRouterContext != NULL)
      {
         //Forward Membership Report and Leave Group messages to the IGMP router
         igmpRouterProcessMessage(interface->igmpRouterContext, &pseudoHeader,
            message, length);
      }
   }
   else
   {
      //Just for sanity
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Process incoming IGMP message
 * @param[in] interface Underlying network interface
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] buffer Multi-part buffer containing the incoming IGMP message
 * @param[in] offset Offset to the first byte of the IGMP message
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 **/

void igmpProcessMessage(NetInterface *interface,
   Ipv4PseudoHeader *pseudoHeader, const NetBuffer *buffer,
   size_t offset, NetRxAncillary *ancillary)
{
   size_t length;
   IgmpMessage *message;

   //Retrieve the length of the IGMP message
   length = netBufferGetLength(buffer) - offset;

   //To be valid, an IGMP message must be at least 8 octets long
   if(length < sizeof(IgmpMessage))
   {
      //Debug message
      TRACE_WARNING("IGMP message length is invalid!\r\n");
      //Silently discard incoming message
      return;
   }

   //Point to the beginning of the IGMP message
   message = netBufferAt(buffer, offset);
   //Sanity check
   if(message == NULL)
      return;

   //Debug message
   TRACE_INFO("IGMP message received (%" PRIuSIZE " bytes)...\r\n", length);

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
   //Dump switch port identifier
   if(ancillary->port != 0)
   {
      TRACE_INFO("  Switch Port = %" PRIu8 "\r\n", ancillary->port);
   }
#endif

   //Dump message contents for debugging purpose
   igmpDumpMessage(message);

   //Verify checksum value
   if(ipCalcChecksumEx(buffer, offset, length) != 0x0000)
   {
      //Debug message
      TRACE_WARNING("Wrong IGMP header checksum!\r\n");
      //Drop incoming message
      return;
   }

#if (IGMP_HOST_SUPPORT == ENABLED)
   //Pass the message to the IGMP host
   igmpHostProcessMessage(interface, message, length);
#endif

#if (IGMP_ROUTER_SUPPORT == ENABLED)
   //Valid IGMP router context?
   if(interface->igmpRouterContext != NULL)
   {
      //Pass the message to the IGMP router
      igmpRouterProcessMessage(interface->igmpRouterContext, pseudoHeader,
         message, length);
   }
#endif

#if (IGMP_SNOOPING_SUPPORT == ENABLED)
   //Valid IGMP snooping switch context?
   if(interface->igmpSnoopingContext != NULL)
   {
      //Pass the message to the IGMP snooping switch
      igmpSnoopingProcessMessage(interface->igmpSnoopingContext, pseudoHeader,
         message, length, ancillary);
   }
#endif
}


/**
 * @brief Dump IGMP message for debugging purpose
 * @param[in] message Pointer to the IGMP message
 **/

void igmpDumpMessage(const IgmpMessage *message)
{
#if (TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   const char_t *label;

   //Check IGMP message type
   if(message->type == IGMP_TYPE_MEMBERSHIP_QUERY)
   {
      label = "Membership Query";
   }
   else if(message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V1)
   {
      label = "Version 1 Membership Report";
   }
   else if(message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V2)
   {
      label = "Version 2 Membership Report";
   }
   else if(message->type == IGMP_TYPE_MEMBERSHIP_REPORT_V3)
   {
      label = "Version 3 Membership Report";
   }
   else if(message->type == IGMP_TYPE_LEAVE_GROUP)
   {
      label = "Leave Group";
   }
   else
   {
      label = "Unknown";
   }

   //Dump IGMP message
   TRACE_DEBUG("  Type = 0x%02" PRIX8 " (%s)\r\n", message->type, label);
   TRACE_DEBUG("  Max Resp Time = %" PRIu8 "\r\n", message->maxRespTime);
   TRACE_DEBUG("  Checksum = 0x%04" PRIX16 "\r\n", ntohs(message->checksum));
   TRACE_DEBUG("  Group Address = %s\r\n", ipv4AddrToString(message->groupAddr, NULL));
#endif
}

#endif

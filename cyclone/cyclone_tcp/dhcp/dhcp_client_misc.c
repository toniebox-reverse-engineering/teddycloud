/**
 * @file dhcp_client_misc.c
 * @brief Helper functions for DHCP client
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
#define TRACE_LEVEL DHCP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "dhcp/dhcp_client.h"
#include "dhcp/dhcp_client_fsm.h"
#include "dhcp/dhcp_client_misc.h"
#include "dhcp/dhcp_common.h"
#include "dhcp/dhcp_debug.h"
#include "mdns/mdns_responder.h"
#include "date_time.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED && DHCP_CLIENT_SUPPORT == ENABLED)

//Tick counter to handle periodic operations
systime_t dhcpClientTickCounter;

//Requested DHCP options
const uint8_t dhcpOptionList[] =
{
   DHCP_OPT_SUBNET_MASK,
   DHCP_OPT_ROUTER,
   DHCP_OPT_DNS_SERVER,
   DHCP_OPT_INTERFACE_MTU,
   DHCP_OPT_IP_ADDRESS_LEASE_TIME,
   DHCP_OPT_RENEWAL_TIME_VALUE,
   DHCP_OPT_REBINDING_TIME_VALUE
};


/**
 * @brief DHCP client timer handler
 *
 * This routine must be periodically called by the TCP/IP stack to
 * manage DHCP client operation
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientTick(DhcpClientContext *context)
{
   //Make sure the DHCP client has been properly instantiated
   if(context != NULL)
   {
      //DHCP client finite state machine
      switch(context->state)
      {
      //INIT state?
      case DHCP_STATE_INIT:
         //This is the initialization state, where a client begins the process
         //of acquiring a lease. It also returns here when a lease ends, or
         //when a lease negotiation fails
         dhcpClientStateInit(context);
         break;

      //SELECTING state?
      case DHCP_STATE_SELECTING:
         //The client is waiting to receive DHCPOFFER messages from one or more
         //DHCP servers, so it can choose one
         dhcpClientStateSelecting(context);
         break;

      //REQUESTING state?
      case DHCP_STATE_REQUESTING:
         //The client is waiting to hear back from the server to which it sent
         //its request
         dhcpClientStateRequesting(context);
         break;

      //INIT REBOOT state?
      case DHCP_STATE_INIT_REBOOT:
         //When a client that already has a valid lease starts up after a
         //power-down or reboot, it starts here instead of the INIT state
         dhcpClientStateInitReboot(context);
         break;

      //REBOOTING state?
      case DHCP_STATE_REBOOTING:
         //A client that has rebooted with an assigned address is waiting for
         //a confirming reply from a server
         dhcpClientStateRebooting(context);
         break;

      //PROBING state?
      case DHCP_STATE_PROBING:
         //The client probes the newly received address
         dhcpClientStateProbing(context);
         break;

      //ANNOUNCING state?
      case DHCP_STATE_ANNOUNCING:
         //The client announces its new IP address
         dhcpClientStateAnnouncing(context);
         break;

      //BOUND state?
      case DHCP_STATE_BOUND:
         //Client has a valid lease and is in its normal operating state
         dhcpClientStateBound(context);
         break;

      //RENEWING state?
      case DHCP_STATE_RENEWING:
         //Client is trying to renew its lease. It regularly sends DHCPREQUEST
         //messages with the server that gave it its current lease specified,
         //and waits for a reply
         dhcpClientStateRenewing(context);
         break;

      //REBINDING state?
      case DHCP_STATE_REBINDING:
         //The client has failed to renew its lease with the server that
         //originally granted it, and now seeks a lease extension with any
         //server that can hear it. It periodically sends DHCPREQUEST messages
         //with no server specified until it gets a reply or the lease ends
         dhcpClientStateRebinding(context);
         break;

      //Invalid state?
      default:
         //Switch to the default state
         context->state = DHCP_STATE_INIT;
         break;
      }
   }
}


/**
 * @brief Callback function for link change event
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientLinkChangeEvent(DhcpClientContext *context)
{
   NetInterface *interface;

   //Make sure the DHCP client has been properly instantiated
   if(context == NULL)
      return;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check whether the DHCP client is running
   if(context->running)
   {
      //The host address is no longer valid
      dhcpClientResetConfig(context);

#if (MDNS_RESPONDER_SUPPORT == ENABLED)
      //Restart mDNS probing process
      mdnsResponderStartProbing(interface->mdnsResponderContext);
#endif
   }

   //Check whether the client already has a valid lease
   if(context->state >= DHCP_STATE_INIT_REBOOT)
   {
      //Switch to the INIT-REBOOT state
      context->state = DHCP_STATE_INIT_REBOOT;
   }
   else
   {
      //Switch to the INIT state
      context->state = DHCP_STATE_INIT;
   }

   //Any registered callback?
   if(context->settings.linkChangeEvent != NULL)
   {
      //Release exclusive access
      osReleaseMutex(&netMutex);
      //Invoke user callback function
      context->settings.linkChangeEvent(context, interface, interface->linkState);
      //Get exclusive access
      osAcquireMutex(&netMutex);
   }
}


/**
 * @brief Send DHCPDISCOVER message
 * @param[in] context Pointer to the DHCP client context
 * @return Error code
 **/

error_t dhcpClientSendDiscover(DhcpClientContext *context)
{
   error_t error;
   size_t offset;
   size_t length;
   NetBuffer *buffer;
   NetInterface *interface;
   NetInterface *logicalInterface;
   DhcpMessage *message;
   IpAddr srcIpAddr;
   IpAddr destIpAddr;
   NetTxAncillary ancillary;

   //DHCP message type
   const uint8_t type = DHCP_MSG_TYPE_DISCOVER;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Point to the logical interface
   logicalInterface = nicGetLogicalInterface(interface);

   //Allocate a memory buffer to hold the DHCP message
   buffer = udpAllocBuffer(DHCP_MAX_MSG_SIZE, &offset);
   //Failed to allocate buffer?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Point to the beginning of the DHCP message
   message = netBufferAt(buffer, offset);
   //Clear memory buffer contents
   osMemset(message, 0, DHCP_MAX_MSG_SIZE);

   //Format DHCPDISCOVER message
   message->op = DHCP_OPCODE_BOOTREQUEST;
   message->htype = DHCP_HARDWARE_TYPE_ETH;
   message->hlen = sizeof(MacAddr);
   message->xid = htonl(context->transactionId);
   message->secs = dhcpClientComputeElapsedTime(context);
   message->flags = HTONS(DHCP_FLAG_BROADCAST);
   message->ciaddr = IPV4_UNSPECIFIED_ADDR;
   message->chaddr = logicalInterface->macAddr;

   //Write magic cookie before setting any option
   message->magicCookie = HTONL(DHCP_MAGIC_COOKIE);
   //Properly terminate the options field
   message->options[0] = DHCP_OPT_END;

   //Total length of the DHCP message
   length = sizeof(DhcpMessage) + sizeof(uint8_t);

   //DHCP Message Type option
   dhcpAddOption(message, &length, DHCP_OPT_DHCP_MESSAGE_TYPE,
      &type, sizeof(type));

   //Check whether rapid commit is enabled
   if(context->settings.rapidCommit)
   {
      //Include the Rapid Commit option if the client is prepared
      //to perform the DHCPDISCOVER-DHCPACK message exchange
      dhcpAddOption(message, &length, DHCP_OPT_RAPID_COMMIT, NULL, 0);
   }

   //Any registered callback?
   if(context->settings.addOptionsCallback != NULL)
   {
      //Invoke user callback function
      context->settings.addOptionsCallback(context, message, &length,
         DHCP_MSG_TYPE_DISCOVER);
   }

   //The minimum length of BOOTP frames is 300 octets (refer to RFC 951,
   //section 3)
   length = MAX(length, DHCP_MIN_MSG_SIZE);

   //Adjust the length of the multi-part buffer
   netBufferSetLength(buffer, offset + length);

   //DHCP messages broadcast by a client prior to that client obtaining its
   //IP address must have the source address field in the IP header set to 0
   //(refer to RFC 2131, section 4.1)
   srcIpAddr.length = sizeof(Ipv4Addr);
   srcIpAddr.ipv4Addr = IPV4_UNSPECIFIED_ADDR;

   //Set destination IP address
   destIpAddr.length = sizeof(Ipv4Addr);
   destIpAddr.ipv4Addr = IPV4_BROADCAST_ADDR;

   //Debug message
   TRACE_DEBUG("\r\n%s: Sending DHCP message (%" PRIuSIZE " bytes)...\r\n",
      formatSystemTime(osGetSystemTime(), NULL), length);

   //Dump the contents of the message for debugging purpose
   dhcpDumpMessage(message, length);

   //Additional options can be passed to the stack along with the packet
   ancillary = NET_DEFAULT_TX_ANCILLARY;

   //Broadcast DHCPDISCOVER message
   error = udpSendBuffer(interface, &srcIpAddr, DHCP_CLIENT_PORT, &destIpAddr,
      DHCP_SERVER_PORT, buffer, offset, &ancillary);

   //Free previously allocated memory
   netBufferFree(buffer);
   //Return status code
   return error;
}


/**
 * @brief Send DHCPREQUEST message
 * @param[in] context Pointer to the DHCP client context
 * @return Error code
 **/

error_t dhcpClientSendRequest(DhcpClientContext *context)
{
   uint_t i;
   error_t error;
   size_t offset;
   size_t length;
   NetBuffer *buffer;
   NetInterface *interface;
   NetInterface *logicalInterface;
   DhcpMessage *message;
   IpAddr srcIpAddr;
   IpAddr destIpAddr;
   NetTxAncillary ancillary;

   //DHCP message type
   const uint8_t type = DHCP_MSG_TYPE_REQUEST;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Point to the logical interface
   logicalInterface = nicGetLogicalInterface(interface);

   //Index of the IP address in the list of addresses assigned to the interface
   i = context->settings.ipAddrIndex;

   //Allocate a memory buffer to hold the DHCP message
   buffer = udpAllocBuffer(DHCP_MAX_MSG_SIZE, &offset);
   //Failed to allocate buffer?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Point to the beginning of the DHCP message
   message = netBufferAt(buffer, offset);
   //Clear memory buffer contents
   osMemset(message, 0, DHCP_MAX_MSG_SIZE);

   //Format DHCPREQUEST message
   message->op = DHCP_OPCODE_BOOTREQUEST;
   message->htype = DHCP_HARDWARE_TYPE_ETH;
   message->hlen = sizeof(MacAddr);
   message->xid = htonl(context->transactionId);
   message->secs = dhcpClientComputeElapsedTime(context);

   //The client IP address must be included if the client is fully configured
   //and can respond to ARP requests
   if(context->state == DHCP_STATE_RENEWING ||
      context->state == DHCP_STATE_REBINDING)
   {
      message->flags = 0;
      message->ciaddr = interface->ipv4Context.addrList[i].addr;
   }
   else
   {
      message->flags = HTONS(DHCP_FLAG_BROADCAST);
      message->ciaddr = IPV4_UNSPECIFIED_ADDR;
   }

   //Client hardware address
   message->chaddr = logicalInterface->macAddr;
   //Write magic cookie before setting any option
   message->magicCookie = HTONL(DHCP_MAGIC_COOKIE);
   //Properly terminate the options field
   message->options[0] = DHCP_OPT_END;

   //Total length of the DHCP message
   length = sizeof(DhcpMessage) + sizeof(uint8_t);

   //DHCP Message Type option
   dhcpAddOption(message, &length, DHCP_OPT_DHCP_MESSAGE_TYPE,
      &type, sizeof(type));

   //Server Identifier option
   if(context->state == DHCP_STATE_REQUESTING)
   {
      dhcpAddOption(message, &length, DHCP_OPT_SERVER_ID,
         &context->serverIpAddr, sizeof(Ipv4Addr));
   }

   //Requested IP Address option
   if(context->state == DHCP_STATE_REQUESTING ||
      context->state == DHCP_STATE_REBOOTING)
   {
      dhcpAddOption(message, &length, DHCP_OPT_REQUESTED_IP_ADDR,
         &context->requestedIpAddr, sizeof(Ipv4Addr));
   }

   //Any registered callback?
   if(context->settings.addOptionsCallback != NULL)
   {
      //Invoke user callback function
      context->settings.addOptionsCallback(context, message, &length,
         DHCP_MSG_TYPE_REQUEST);
   }

   //Parameter Request List option
   if(dhcpGetOption(message, length, DHCP_OPT_PARAM_REQUEST_LIST) == NULL)
   {
      //Use the default list of requested options
      dhcpAddOption(message, &length, DHCP_OPT_PARAM_REQUEST_LIST,
         dhcpOptionList, sizeof(dhcpOptionList));
   }

   //The minimum length of BOOTP frames is 300 octets (refer to RFC 951,
   //section 3)
   length = MAX(length, DHCP_MIN_MSG_SIZE);

   //Adjust the length of the multi-part buffer
   netBufferSetLength(buffer, offset + length);

   //IP address is being renewed?
   if(context->state == DHCP_STATE_RENEWING)
   {
      //Set source IP address
      srcIpAddr.length = sizeof(Ipv4Addr);
      srcIpAddr.ipv4Addr = interface->ipv4Context.addrList[i].addr;

      //The client transmits the message directly to the server that initially
      //granted the lease
      destIpAddr.length = sizeof(Ipv4Addr);
      destIpAddr.ipv4Addr = context->serverIpAddr;
   }
   else
   {
      //DHCP messages broadcast by a client prior to that client obtaining its
      //IP address must have the source address field in the IP header set to 0
      //(refer to RFC 2131, section 4.1)
      srcIpAddr.length = sizeof(Ipv4Addr);
      srcIpAddr.ipv4Addr = IPV4_UNSPECIFIED_ADDR;

      //Broadcast the message
      destIpAddr.length = sizeof(Ipv4Addr);
      destIpAddr.ipv4Addr = IPV4_BROADCAST_ADDR;
   }

   //Debug message
   TRACE_DEBUG("\r\n%s: Sending DHCP message (%" PRIuSIZE " bytes)...\r\n",
      formatSystemTime(osGetSystemTime(), NULL), length);

   //Dump the contents of the message for debugging purpose
   dhcpDumpMessage(message, length);

   //Additional options can be passed to the stack along with the packet
   ancillary = NET_DEFAULT_TX_ANCILLARY;

   //Send DHCPREQUEST message
   error = udpSendBuffer(interface, &srcIpAddr, DHCP_CLIENT_PORT, &destIpAddr,
      DHCP_SERVER_PORT, buffer, offset, &ancillary);

   //Free previously allocated memory
   netBufferFree(buffer);
   //Return status code
   return error;
}


/**
 * @brief Send DHCPDECLINE message
 * @param[in] context Pointer to the DHCP client context
 * @return Error code
 **/

error_t dhcpClientSendDecline(DhcpClientContext *context)
{
   error_t error;
   size_t offset;
   size_t length;
   NetBuffer *buffer;
   NetInterface *interface;
   NetInterface *logicalInterface;
   DhcpMessage *message;
   IpAddr srcIpAddr;
   IpAddr destIpAddr;
   NetTxAncillary ancillary;

   //DHCP message type
   const uint8_t type = DHCP_MSG_TYPE_DECLINE;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Point to the logical interface
   logicalInterface = nicGetLogicalInterface(interface);

   //Allocate a memory buffer to hold the DHCP message
   buffer = udpAllocBuffer(DHCP_MAX_MSG_SIZE, &offset);
   //Failed to allocate buffer?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Point to the beginning of the DHCP message
   message = netBufferAt(buffer, offset);
   //Clear memory buffer contents
   osMemset(message, 0, DHCP_MAX_MSG_SIZE);

   //Format DHCPDECLINE message
   message->op = DHCP_OPCODE_BOOTREQUEST;
   message->htype = DHCP_HARDWARE_TYPE_ETH;
   message->hlen = sizeof(MacAddr);
   message->xid = htonl(context->transactionId);
   message->secs = 0;
   message->flags = 0;
   message->ciaddr = IPV4_UNSPECIFIED_ADDR;
   message->chaddr = logicalInterface->macAddr;

   //Write magic cookie before setting any option
   message->magicCookie = HTONL(DHCP_MAGIC_COOKIE);
   //Properly terminate the options field
   message->options[0] = DHCP_OPT_END;

   //Total length of the DHCP message
   length = sizeof(DhcpMessage) + sizeof(uint8_t);

   //DHCP Message Type option
   dhcpAddOption(message, &length, DHCP_OPT_DHCP_MESSAGE_TYPE,
      &type, sizeof(type));

   //Server Identifier option
   dhcpAddOption(message, &length, DHCP_OPT_SERVER_ID,
      &context->serverIpAddr, sizeof(Ipv4Addr));

   //Requested IP Address option
   dhcpAddOption(message, &length, DHCP_OPT_REQUESTED_IP_ADDR,
      &context->requestedIpAddr, sizeof(Ipv4Addr));

   //Any registered callback?
   if(context->settings.addOptionsCallback != NULL)
   {
      //Invoke user callback function
      context->settings.addOptionsCallback(context, message, &length,
         DHCP_MSG_TYPE_DECLINE);
   }

   //The minimum length of BOOTP frames is 300 octets (refer to RFC 951,
   //section 3)
   length = MAX(length, DHCP_MIN_MSG_SIZE);

   //Adjust the length of the multi-part buffer
   netBufferSetLength(buffer, offset + length);

   //Use the unspecified address as source address
   srcIpAddr.length = sizeof(Ipv4Addr);
   srcIpAddr.ipv4Addr = IPV4_UNSPECIFIED_ADDR;

   //Set destination IP address
   destIpAddr.length = sizeof(Ipv4Addr);
   destIpAddr.ipv4Addr = IPV4_BROADCAST_ADDR;

   //Debug message
   TRACE_DEBUG("\r\n%s: Sending DHCP message (%" PRIuSIZE " bytes)...\r\n",
      formatSystemTime(osGetSystemTime(), NULL), length);

   //Dump the contents of the message for debugging purpose
   dhcpDumpMessage(message, length);

   //Additional options can be passed to the stack along with the packet
   ancillary = NET_DEFAULT_TX_ANCILLARY;

   //Broadcast DHCPDECLINE message
   error = udpSendBuffer(interface, &srcIpAddr, DHCP_CLIENT_PORT, &destIpAddr,
      DHCP_SERVER_PORT, buffer, offset, &ancillary);

   //Free previously allocated memory
   netBufferFree(buffer);
   //Return status code
   return error;
}


/**
 * @brief Send DHCPRELEASE message
 * @param[in] context Pointer to the DHCP client context
 * @return Error code
 **/

error_t dhcpClientSendRelease(DhcpClientContext *context)
{
   uint_t i;
   error_t error;
   size_t offset;
   size_t length;
   NetBuffer *buffer;
   NetInterface *interface;
   NetInterface *logicalInterface;
   DhcpMessage *message;
   IpAddr srcIpAddr;
   IpAddr destIpAddr;
   NetTxAncillary ancillary;

   //DHCP message type
   const uint8_t type = DHCP_MSG_TYPE_RELEASE;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Point to the logical interface
   logicalInterface = nicGetLogicalInterface(interface);

   //Index of the IP address in the list of addresses assigned to the interface
   i = context->settings.ipAddrIndex;

   //Allocate a memory buffer to hold the DHCP message
   buffer = udpAllocBuffer(DHCP_MAX_MSG_SIZE, &offset);
   //Failed to allocate buffer?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Point to the beginning of the DHCP message
   message = netBufferAt(buffer, offset);
   //Clear memory buffer contents
   osMemset(message, 0, DHCP_MAX_MSG_SIZE);

   //Format DHCP message
   message->op = DHCP_OPCODE_BOOTREQUEST;
   message->htype = DHCP_HARDWARE_TYPE_ETH;
   message->hlen = sizeof(MacAddr);
   message->xid = htonl(context->transactionId);
   message->secs = 0;
   message->flags = 0;
   message->ciaddr = interface->ipv4Context.addrList[i].addr;
   message->chaddr = logicalInterface->macAddr;

   //Write magic cookie before setting any option
   message->magicCookie = HTONL(DHCP_MAGIC_COOKIE);
   //Properly terminate the options field
   message->options[0] = DHCP_OPT_END;

   //Total length of the DHCP message
   length = sizeof(DhcpMessage) + sizeof(uint8_t);

   //DHCP Message Type option
   dhcpAddOption(message, &length, DHCP_OPT_DHCP_MESSAGE_TYPE,
      &type, sizeof(type));

   //Server Identifier option
   dhcpAddOption(message, &length, DHCP_OPT_SERVER_ID,
      &context->serverIpAddr, sizeof(Ipv4Addr));

   //Any registered callback?
   if(context->settings.addOptionsCallback != NULL)
   {
      //Invoke user callback function
      context->settings.addOptionsCallback(context, message, &length,
         DHCP_MSG_TYPE_RELEASE);
   }

   //The minimum length of BOOTP frames is 300 octets (refer to RFC 951,
   //section 3)
   length = MAX(length, DHCP_MIN_MSG_SIZE);

   //Adjust the length of the multi-part buffer
   netBufferSetLength(buffer, offset + length);

   //Set source IP address
   srcIpAddr.length = sizeof(Ipv4Addr);
   srcIpAddr.ipv4Addr = interface->ipv4Context.addrList[i].addr;

   //The client unicasts DHCPRELEASE messages to the server (refer to RFC 2131,
   //section 4.4.4)
   destIpAddr.length = sizeof(Ipv4Addr);
   destIpAddr.ipv4Addr = context->serverIpAddr;

   //Debug message
   TRACE_DEBUG("\r\n%s: Sending DHCP message (%" PRIuSIZE " bytes)...\r\n",
      formatSystemTime(osGetSystemTime(), NULL), length);

   //Dump the contents of the message for debugging purpose
   dhcpDumpMessage(message, length);

   //Additional options can be passed to the stack along with the packet
   ancillary = NET_DEFAULT_TX_ANCILLARY;

   //Broadcast DHCP message
   error = udpSendBuffer(interface, &srcIpAddr, DHCP_CLIENT_PORT, &destIpAddr,
      DHCP_SERVER_PORT, buffer, offset, &ancillary);

   //Free previously allocated memory
   netBufferFree(buffer);
   //Return status code
   return error;
}


/**
 * @brief Process incoming DHCP message
 * @param[in] interface Underlying network interface
 * @param[in] pseudoHeader UDP pseudo header
 * @param[in] udpHeader UDP header
 * @param[in] buffer Multi-part buffer containing the incoming DHCP message
 * @param[in] offset Offset to the first byte of the DHCP message
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @param[in] param Pointer to the DHCP client context
 **/

void dhcpClientProcessMessage(NetInterface *interface,
   const IpPseudoHeader *pseudoHeader, const UdpHeader *udpHeader,
   const NetBuffer *buffer, size_t offset, const NetRxAncillary *ancillary,
   void *param)
{
   size_t length;
   DhcpClientContext *context;
   DhcpMessage *message;
   DhcpOption *option;

   //Point to the DHCP client context
   context = (DhcpClientContext *) param;

   //Retrieve the length of the DHCP message
   length = netBufferGetLength(buffer) - offset;

   //Make sure the DHCP message is valid
   if(length < sizeof(DhcpMessage) || length > DHCP_MAX_MSG_SIZE)
      return;

   //Point to the beginning of the DHCP message
   message = netBufferAt(buffer, offset);
   //Sanity check
   if(message == NULL)
      return;

   //Debug message
   TRACE_DEBUG("\r\n%s: DHCP message received (%" PRIuSIZE " bytes)...\r\n",
      formatSystemTime(osGetSystemTime(), NULL), length);

   //Dump the contents of the message for debugging purpose
   dhcpDumpMessage(message, length);

   //The DHCP server shall respond with a BOOTREPLY opcode
   if(message->op != DHCP_OPCODE_BOOTREPLY)
      return;

   //Enforce hardware type
   if(message->htype != DHCP_HARDWARE_TYPE_ETH)
      return;

   //Check the length of the hardware address
   if(message->hlen != sizeof(MacAddr))
      return;

   //Check magic cookie
   if(message->magicCookie != HTONL(DHCP_MAGIC_COOKIE))
      return;

   //The DHCP Message Type option must be included in every DHCP message
   option = dhcpGetOption(message, length, DHCP_OPT_DHCP_MESSAGE_TYPE);

   //Failed to retrieve the Message Type option?
   if(option == NULL || option->length != 1)
      return;

   //Check message type
   switch(option->value[0])
   {
   case DHCP_MSG_TYPE_OFFER:
      //Parse DHCPOFFER message
      dhcpClientParseOffer(context, message, length);
      break;

   case DHCP_MSG_TYPE_ACK:
      //Parse DHCPACK message
      dhcpClientParseAck(context, message, length);
      break;

   case DHCP_MSG_TYPE_NAK:
      //Parse DHCPNAK message
      dhcpClientParseNak(context, message, length);
      break;

   default:
      //Silently drop incoming message
      break;
   }
}


/**
 * @brief Parse DHCPOFFER message
 * @param[in] context Pointer to the DHCP client context
 * @param[in] message Pointer to the incoming DHCP message
 * @param[in] length Length of the incoming message to parse
 **/

void dhcpClientParseOffer(DhcpClientContext *context,
   const DhcpMessage *message, size_t length)
{
   error_t error;
   DhcpOption *serverIdOption;
   NetInterface *interface;
   NetInterface *logicalInterface;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Point to the logical interface
   logicalInterface = nicGetLogicalInterface(interface);

   //Discard any received packet that does not match the transaction ID
   if(ntohl(message->xid) != context->transactionId)
      return;

   //Make sure the IP address offered to the client is valid
   if(message->yiaddr == IPV4_UNSPECIFIED_ADDR)
      return;

   //Check MAC address
   if(!macCompAddr(&message->chaddr, &logicalInterface->macAddr))
      return;

   //Make sure that the DHCPOFFER message is received in response to
   //a DHCPDISCOVER message
   if(context->state != DHCP_STATE_SELECTING)
      return;

   //A DHCP server always returns its own address in the Server Identifier option
   serverIdOption = dhcpGetOption(message, length, DHCP_OPT_SERVER_ID);

   //Failed to retrieve the Server Identifier option?
   if(serverIdOption == NULL || serverIdOption->length != 4)
      return;

   //Any registered callback?
   if(context->settings.parseOptionsCallback != NULL)
   {
      //Invoke user callback function
      error = context->settings.parseOptionsCallback(context, message, length,
         DHCP_MSG_TYPE_OFFER);
      //Check status code
      if(error)
         return;
   }

   //Record the IP address of the DHCP server
   ipv4CopyAddr(&context->serverIpAddr, serverIdOption->value);
   //Record the IP address offered to the client
   context->requestedIpAddr = message->yiaddr;

   //Switch to the REQUESTING state
   dhcpClientChangeState(context, DHCP_STATE_REQUESTING, 0);
}


/**
 * @brief Parse DHCPACK message
 * @param[in] context Pointer to the DHCP client context
 * @param[in] message Pointer to the incoming DHCP message
 * @param[in] length Length of the incoming message to parse
 **/

void dhcpClientParseAck(DhcpClientContext *context,
   const DhcpMessage *message, size_t length)
{
   error_t error;
   uint_t i;
   uint_t j;
   uint_t n;
   DhcpOption *option;
   DhcpOption *serverIdOption;
   NetInterface *interface;
   NetInterface *logicalInterface;
   NetInterface *physicalInterface;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Point to the logical interface
   logicalInterface = nicGetLogicalInterface(interface);
   //Point to the physical interface
   physicalInterface = nicGetPhysicalInterface(interface);

   //Index of the IP address in the list of addresses assigned to the interface
   i = context->settings.ipAddrIndex;

   //Discard any received packet that does not match the transaction ID
   if(ntohl(message->xid) != context->transactionId)
      return;

   //Make sure the IP address assigned to the client is valid
   if(message->yiaddr == IPV4_UNSPECIFIED_ADDR)
      return;

   //Check MAC address
   if(!macCompAddr(&message->chaddr, &logicalInterface->macAddr))
      return;

   //A DHCP server always returns its own address in the Server Identifier option
   serverIdOption = dhcpGetOption(message, length, DHCP_OPT_SERVER_ID);

   //Failed to retrieve the Server Identifier option?
   if(serverIdOption == NULL || serverIdOption->length != 4)
      return;

   //Check current state
   if(context->state == DHCP_STATE_SELECTING)
   {
      //A DHCPACK message is not acceptable when rapid commit is disallowed
      if(!context->settings.rapidCommit)
         return;

      //Search for the Rapid Commit option
      option = dhcpGetOption(message, length, DHCP_OPT_RAPID_COMMIT);

      //A server must include this option in a DHCPACK message sent
      //in a response to a DHCPDISCOVER message when completing the
      //DHCPDISCOVER-DHCPACK message exchange
      if(option == NULL || option->length != 0)
         return;
   }
   else if(context->state == DHCP_STATE_REQUESTING ||
      context->state == DHCP_STATE_RENEWING)
   {
      //Check the server identifier
      if(!ipv4CompAddr(serverIdOption->value, &context->serverIpAddr))
         return;
   }
   else if(context->state == DHCP_STATE_REBOOTING ||
      context->state == DHCP_STATE_REBINDING)
   {
      //Do not check the server identifier
   }
   else
   {
      //Silently discard the DHCPACK message
      return;
   }

   //Retrieve IP Address Lease Time option
   option = dhcpGetOption(message, length, DHCP_OPT_IP_ADDRESS_LEASE_TIME);

   //Failed to retrieve specified option?
   if(option == NULL || option->length != 4)
      return;

   //Any registered callback?
   if(context->settings.parseOptionsCallback != NULL)
   {
      //Invoke user callback function
      error = context->settings.parseOptionsCallback(context, message, length,
         DHCP_MSG_TYPE_ACK);
      //Check status code
      if(error)
         return;
   }

   //Record the lease time
   context->leaseTime = LOAD32BE(option->value);

   //Retrieve Renewal Time Value option
   option = dhcpGetOption(message, length, DHCP_OPT_RENEWAL_TIME_VALUE);

   //Specified option found?
   if(option != NULL && option->length == 4)
   {
      //This option specifies the time interval from address assignment
      //until the client transitions to the RENEWING state
      context->t1 = LOAD32BE(option->value);
   }
   else if(context->leaseTime != DHCP_INFINITE_TIME)
   {
      //By default, T1 is set to 50% of the lease time
      context->t1 = context->leaseTime / 2;
   }
   else
   {
      //Infinite lease
      context->t1 = DHCP_INFINITE_TIME;
   }

   //Retrieve Rebinding Time value option
   option = dhcpGetOption(message, length, DHCP_OPT_REBINDING_TIME_VALUE);

   //Specified option found?
   if(option != NULL && option->length == 4)
   {
      //This option specifies the time interval from address assignment
      //until the client transitions to the REBINDING state
      context->t2 = LOAD32BE(option->value);
   }
   else if(context->leaseTime != DHCP_INFINITE_TIME)
   {
      //By default, T2 is set to 87.5% of the lease time
      context->t2 = context->leaseTime * 7 / 8;
   }
   else
   {
      //Infinite lease
      context->t2 = DHCP_INFINITE_TIME;
   }

   //Retrieve Subnet Mask option
   option = dhcpGetOption(message, length, DHCP_OPT_SUBNET_MASK);

   //Option found?
   if(option != NULL && option->length == sizeof(Ipv4Addr))
   {
      //Save subnet mask
      ipv4CopyAddr(&interface->ipv4Context.addrList[i].subnetMask,
         option->value);
   }

   //Retrieve Router option
   option = dhcpGetOption(message, length, DHCP_OPT_ROUTER);

   //Option found?
   if(option != NULL && !(option->length % sizeof(Ipv4Addr)))
   {
      //Save default gateway
      if(option->length >= sizeof(Ipv4Addr))
      {
         ipv4CopyAddr(&interface->ipv4Context.addrList[i].defaultGateway,
            option->value);
      }
   }

   //Automatic DNS server configuration?
   if(!context->settings.manualDnsConfig)
   {
      //Retrieve DNS Server option
      option = dhcpGetOption(message, length, DHCP_OPT_DNS_SERVER);

      //Option found?
      if(option != NULL && !(option->length % sizeof(Ipv4Addr)))
      {
         //Get the number of addresses provided in the response
         n = option->length / sizeof(Ipv4Addr);

         //Loop through the list of addresses
         for(j = 0; j < n && j < IPV4_DNS_SERVER_LIST_SIZE; j++)
         {
            //Save DNS server address
            ipv4CopyAddr(&interface->ipv4Context.dnsServerList[j],
               option->value + j * sizeof(Ipv4Addr));
         }
      }
   }

   //Retrieve MTU option
   option = dhcpGetOption(message, length, DHCP_OPT_INTERFACE_MTU);

   //Option found?
   if(option != NULL && option->length == 2)
   {
      //This option specifies the MTU to use on this interface
      n = LOAD16BE(option->value);

      //Make sure that the option's value is acceptable
      if(n >= IPV4_MINIMUM_MTU && n <= physicalInterface->nicDriver->mtu)
      {
         //Set the MTU to be used on the interface
         interface->ipv4Context.linkMtu = n;
      }
   }

   //Record the IP address of the DHCP server
   ipv4CopyAddr(&context->serverIpAddr, serverIdOption->value);
   //Record the IP address assigned to the client
   context->requestedIpAddr = message->yiaddr;

   //Save the time a which the lease was obtained
   context->leaseStartTime = osGetSystemTime();

   //Check current state
   if(context->state == DHCP_STATE_REQUESTING ||
      context->state == DHCP_STATE_REBOOTING)
   {
      //Use the IP address as a tentative address
      interface->ipv4Context.addrList[i].addr = message->yiaddr;
      interface->ipv4Context.addrList[i].state = IPV4_ADDR_STATE_TENTATIVE;

      //Clear conflict flag
      interface->ipv4Context.addrList[i].conflict = FALSE;

      //The client should probe the newly received address
      dhcpClientChangeState(context, DHCP_STATE_PROBING, 0);
   }
   else
   {
      //Assign the IP address to the client
      interface->ipv4Context.addrList[i].addr = message->yiaddr;
      interface->ipv4Context.addrList[i].state = IPV4_ADDR_STATE_VALID;

#if (MDNS_RESPONDER_SUPPORT == ENABLED)
      //Restart mDNS probing process
      mdnsResponderStartProbing(interface->mdnsResponderContext);
#endif
      //The client transitions to the BOUND state
      dhcpClientChangeState(context, DHCP_STATE_BOUND, 0);
   }
}


/**
 * @brief Parse DHCPNAK message
 * @param[in] context Pointer to the DHCP client context
 * @param[in] message Pointer to the incoming DHCP message
 * @param[in] length Length of the incoming message to parse
 **/

void dhcpClientParseNak(DhcpClientContext *context,
   const DhcpMessage *message, size_t length)
{
   error_t error;
   DhcpOption *serverIdOption;
   NetInterface *interface;
   NetInterface *logicalInterface;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Point to the logical interface
   logicalInterface = nicGetLogicalInterface(interface);

   //Discard any received packet that does not match the transaction ID
   if(ntohl(message->xid) != context->transactionId)
      return;

   //Check MAC address
   if(!macCompAddr(&message->chaddr, &logicalInterface->macAddr))
      return;

   //A DHCP server always returns its own address in the Server Identifier option
   serverIdOption = dhcpGetOption(message, length, DHCP_OPT_SERVER_ID);

   //Failed to retrieve the Server Identifier option?
   if(serverIdOption == NULL || serverIdOption->length != 4)
      return;

   //Check current state
   if(context->state == DHCP_STATE_REQUESTING ||
      context->state == DHCP_STATE_RENEWING)
   {
      //Check the server identifier
      if(!ipv4CompAddr(serverIdOption->value, &context->serverIpAddr))
         return;
   }
   else if(context->state == DHCP_STATE_REBOOTING ||
      context->state == DHCP_STATE_REBINDING)
   {
      //Do not check the server identifier
   }
   else
   {
      //Silently discard the DHCPNAK message
      return;
   }

   //Any registered callback?
   if(context->settings.parseOptionsCallback != NULL)
   {
      //Invoke user callback function
      error = context->settings.parseOptionsCallback(context, message, length,
         DHCP_MSG_TYPE_NAK);
      //Check status code
      if(error)
         return;
   }

   //The host address is no longer appropriate for the link
   dhcpClientResetConfig(context);

#if (MDNS_RESPONDER_SUPPORT == ENABLED)
   //Restart mDNS probing process
   mdnsResponderStartProbing(interface->mdnsResponderContext);
#endif

   //Restart DHCP configuration
   dhcpClientChangeState(context, DHCP_STATE_INIT, 0);
}


/**
 * @brief Manage DHCP configuration timeout
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientCheckTimeout(DhcpClientContext *context)
{
   systime_t time;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Get current time
   time = osGetSystemTime();

   //Any registered callback?
   if(context->settings.timeoutEvent != NULL)
   {
      //DHCP configuration timeout?
      if(timeCompare(time, context->configStartTime + context->settings.timeout) >= 0)
      {
         //Ensure the callback function is only called once
         if(!context->timeoutEventDone)
         {
            //Release exclusive access
            osReleaseMutex(&netMutex);
            //Invoke user callback function
            context->settings.timeoutEvent(context, interface);
            //Get exclusive access
            osAcquireMutex(&netMutex);

            //Set flag
            context->timeoutEventDone = TRUE;
         }
      }
   }
}


/**
 * @brief Compute the appropriate secs field
 *
 * Compute the number of seconds elapsed since the client began
 * address acquisition or renewal process
 *
 * @param[in] context Pointer to the DHCP client context
 * @return The elapsed time expressed in seconds
 **/

uint16_t dhcpClientComputeElapsedTime(DhcpClientContext *context)
{
   systime_t time;

   //Compute the time elapsed since the DHCP configuration process started
   time = (osGetSystemTime() - context->configStartTime) / 1000;

   //The value 0xFFFF is used to represent any elapsed time values
   //greater than the largest time value that can be represented
   time = MIN(time, 0xFFFF);

   //Convert the 16-bit value to network byte order
   return htons(time);
}


/**
 * @brief Update DHCP FSM state
 * @param[in] context Pointer to the DHCP client context
 * @param[in] newState New DHCP state to switch to
 * @param[in] delay Initial delay
 **/

void dhcpClientChangeState(DhcpClientContext *context,
   DhcpState newState, systime_t delay)
{
   systime_t time;

   //Get current time
   time = osGetSystemTime();

#if (DHCP_TRACE_LEVEL >= TRACE_LEVEL_INFO)
   //Sanity check
   if(newState <= DHCP_STATE_REBINDING)
   {
      //DHCP FSM states
      static const char_t *const stateLabel[] =
      {
         "INIT",
         "SELECTING",
         "REQUESTING",
         "INIT-REBOOT",
         "REBOOTING",
         "PROBING",
         "ANNOUNCING",
         "BOUND",
         "RENEWING",
         "REBINDING"
      };

      //Debug message
      TRACE_INFO("%s: DHCP client %s state\r\n",
         formatSystemTime(time, NULL), stateLabel[newState]);
   }
#endif

   //Set time stamp
   context->timestamp = time;
   //Set initial delay
   context->timeout = delay;
   //Reset retransmission counter
   context->retransmitCount = 0;
   //Switch to the new state
   context->state = newState;

   //Any registered callback?
   if(context->settings.stateChangeEvent != NULL)
   {
      NetInterface *interface;

      //Point to the underlying network interface
      interface = context->settings.interface;

      //Release exclusive access
      osReleaseMutex(&netMutex);
      //Invoke user callback function
      context->settings.stateChangeEvent(context, interface, newState);
      //Get exclusive access
      osAcquireMutex(&netMutex);
   }
}


/**
 * @brief Reset DHCP configuration
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientResetConfig(DhcpClientContext *context)
{
   uint_t i;
   uint_t j;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Index of the IP address in the list of addresses assigned to the interface
   i = context->settings.ipAddrIndex;

   //The host address is not longer valid
   interface->ipv4Context.addrList[i].addr = IPV4_UNSPECIFIED_ADDR;
   interface->ipv4Context.addrList[i].state = IPV4_ADDR_STATE_INVALID;

   //Clear subnet mask
   interface->ipv4Context.addrList[i].subnetMask = IPV4_UNSPECIFIED_ADDR;

   //The default gateway is no longer valid
   interface->ipv4Context.addrList[i].defaultGateway = IPV4_UNSPECIFIED_ADDR;

   //Automatic DNS server configuration?
   if(!context->settings.manualDnsConfig)
   {
      //Loop through the list of DNS servers
      for(j = 0; j < IPV4_DNS_SERVER_LIST_SIZE; j++)
      {
         //The DNS server is no longer valid
         interface->ipv4Context.dnsServerList[j] = IPV4_UNSPECIFIED_ADDR;
      }
   }
}


/**
 * @brief Dump DHCP configuration for debugging purpose
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientDumpConfig(DhcpClientContext *context)
{
#if (DHCP_TRACE_LEVEL >= TRACE_LEVEL_INFO)
   uint_t i;
   uint_t j;
   NetInterface *interface;
   Ipv4Context *ipv4Context;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Point to the IPv4 context
   ipv4Context = &interface->ipv4Context;

   //Index of the IP address in the list of addresses assigned to the interface
   i = context->settings.ipAddrIndex;

   //Debug message
   TRACE_INFO("\r\n");
   TRACE_INFO("DHCP configuration:\r\n");

   //Lease start time
   TRACE_INFO("  Lease Start Time = %s\r\n",
      formatSystemTime(context->leaseStartTime, NULL));

   //Lease time
   TRACE_INFO("  Lease Time = %" PRIu32 "s\r\n", context->leaseTime);
   //Renewal time
   TRACE_INFO("  T1 = %" PRIu32 "s\r\n", context->t1);
   //Rebinding time
   TRACE_INFO("  T2 = %" PRIu32 "s\r\n", context->t2);

   //Host address
   TRACE_INFO("  IPv4 Address = %s\r\n",
      ipv4AddrToString(ipv4Context->addrList[i].addr, NULL));

   //Subnet mask
   TRACE_INFO("  Subnet Mask = %s\r\n",
      ipv4AddrToString(ipv4Context->addrList[i].subnetMask, NULL));

   //Default gateway
   TRACE_INFO("  Default Gateway = %s\r\n",
      ipv4AddrToString(ipv4Context->addrList[i].defaultGateway, NULL));

   //DNS servers
   for(j = 0; j < IPV4_DNS_SERVER_LIST_SIZE; j++)
   {
      TRACE_INFO("  DNS Server %u = %s\r\n", j + 1,
         ipv4AddrToString(ipv4Context->dnsServerList[j], NULL));
   }

   //Maximum transmit unit
   TRACE_INFO("  MTU = %" PRIuSIZE "\r\n", interface->ipv4Context.linkMtu);
   TRACE_INFO("\r\n");
#endif
}

#endif

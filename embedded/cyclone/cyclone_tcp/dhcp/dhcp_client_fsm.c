/**
 * @file dhcp_client_fsm.c
 * @brief DHCP client finite state machine
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
#include "mdns/mdns_responder.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED && DHCP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief INIT state
 *
 * This is the initialization state, where a client begins the process of
 * acquiring a lease. It also returns here when a lease ends, or when a
 * lease negotiation fails
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientStateInit(DhcpClientContext *context)
{
   systime_t delay;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check whether the DHCP client is running
   if(context->running)
   {
      //Wait for the link to be up before starting DHCP configuration
      if(interface->linkState)
      {
         //The client should wait for a random time to desynchronize
         //the use of DHCP at startup
         delay = netGenerateRandRange(0, DHCP_CLIENT_INIT_DELAY);

         //Record the time at which the client started the address
         //acquisition process
         context->configStartTime = osGetSystemTime();
         //Clear flag
         context->timeoutEventDone = FALSE;

         //Switch to the SELECTING state
         dhcpClientChangeState(context, DHCP_STATE_SELECTING, delay);
      }
   }
}


/**
 * @brief SELECTING state
 *
 * The client is waiting to receive DHCPOFFER messages from
 * one or more DHCP servers, so it can choose one
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientStateSelecting(DhcpClientContext *context)
{
   systime_t time;

   //Get current time
   time = osGetSystemTime();

   //Check current time
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //Check retransmission counter
      if(context->retransmitCount == 0)
      {
         //A transaction identifier is used by the client to match incoming
         //DHCP messages with pending requests
         context->transactionId = netGenerateRand();

         //Send a DHCPDISCOVER message
         dhcpClientSendDiscover(context);

         //Initial timeout value
         context->retransmitTimeout = DHCP_CLIENT_DISCOVER_INIT_RT;
      }
      else
      {
         //Send a DHCPDISCOVER message
         dhcpClientSendDiscover(context);

         //The timeout value is doubled for each subsequent retransmission
         context->retransmitTimeout *= 2;

         //Limit the timeout value to a maximum of 64 seconds
         if(context->retransmitTimeout > DHCP_CLIENT_DISCOVER_MAX_RT)
         {
            context->retransmitTimeout = DHCP_CLIENT_DISCOVER_MAX_RT;
         }
      }

      //Save the time at which the message was sent
      context->timestamp = time;

      //The timeout value should be randomized by the value of a uniform
      //number chosen from the range -1 to +1
      context->timeout = netGenerateRandRange(
         context->retransmitTimeout - DHCP_CLIENT_RAND_FACTOR,
         context->retransmitTimeout + DHCP_CLIENT_RAND_FACTOR);

      //Increment retransmission counter
      context->retransmitCount++;
   }

   //Manage DHCP configuration timeout
   dhcpClientCheckTimeout(context);
}


/**
 * @brief REQUESTING state
 *
 * The client is waiting to hear back from the server
 * to which it sent its request
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientStateRequesting(DhcpClientContext *context)
{
   systime_t time;

   //Get current time
   time = osGetSystemTime();

   //Check current time
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //Check retransmission counter
      if(context->retransmitCount == 0)
      {
         //A transaction identifier is used by the client to match incoming
         //DHCP messages with pending requests
         context->transactionId = netGenerateRand();

         //Send a DHCPREQUEST message
         dhcpClientSendRequest(context);

         //Initial timeout value
         context->retransmitTimeout = DHCP_CLIENT_REQUEST_INIT_RT;

         //Save the time at which the message was sent
         context->timestamp = time;

         //The timeout value should be randomized by the value of a uniform
         //number chosen from the range -1 to +1
         context->timeout = netGenerateRandRange(
            context->retransmitTimeout - DHCP_CLIENT_RAND_FACTOR,
            context->retransmitTimeout + DHCP_CLIENT_RAND_FACTOR);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else if(context->retransmitCount < DHCP_CLIENT_REQUEST_MAX_RC)
      {
         //Send a DHCPREQUEST message
         dhcpClientSendRequest(context);

         //The timeout value is doubled for each subsequent retransmission
         context->retransmitTimeout *= 2;

         //Limit the timeout value to a maximum of 64 seconds
         if(context->retransmitTimeout > DHCP_CLIENT_REQUEST_MAX_RT)
         {
            context->retransmitTimeout = DHCP_CLIENT_REQUEST_MAX_RT;
         }

         //Save the time at which the message was sent
         context->timestamp = time;

         //The timeout value should be randomized by the value of a uniform
         //number chosen from the range -1 to +1
         context->timeout = netGenerateRandRange(
            context->retransmitTimeout - DHCP_CLIENT_RAND_FACTOR,
            context->retransmitTimeout + DHCP_CLIENT_RAND_FACTOR);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else
      {
         //If the client does not receive a response within a reasonable
         //period of time, then it restarts the initialization procedure
         dhcpClientChangeState(context, DHCP_STATE_INIT, 0);
      }
   }

   //Manage DHCP configuration timeout
   dhcpClientCheckTimeout(context);
}


/**
 * @brief INIT-REBOOT state
 *
 * When a client that already has a valid lease starts up after a
 * power-down or reboot, it starts here instead of the INIT state
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientStateInitReboot(DhcpClientContext *context)
{
   systime_t delay;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check whether the DHCP client is running
   if(context->running)
   {
      //Wait for the link to be up before starting DHCP configuration
      if(interface->linkState)
      {
         //The client should wait for a random time to desynchronize
         //the use of DHCP at startup
         delay = netGenerateRandRange(0, DHCP_CLIENT_INIT_DELAY);

         //Record the time at which the client started the address
         //acquisition process
         context->configStartTime = osGetSystemTime();
         //Clear flag
         context->timeoutEventDone = FALSE;

         //Switch to the REBOOTING state
         dhcpClientChangeState(context, DHCP_STATE_REBOOTING, delay);
      }
   }
}


/**
 * @brief REBOOTING state
 *
 * A client that has rebooted with an assigned address is
 * waiting for a confirming reply from a server
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientStateRebooting(DhcpClientContext *context)
{
   systime_t time;

   //Get current time
   time = osGetSystemTime();

   //Check current time
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //Check retransmission counter
      if(context->retransmitCount == 0)
      {
         //A transaction identifier is used by the client to match incoming
         //DHCP messages with pending requests
         context->transactionId = netGenerateRand();

         //Send a DHCPREQUEST message
         dhcpClientSendRequest(context);

         //Initial timeout value
         context->retransmitTimeout = DHCP_CLIENT_REQUEST_INIT_RT;

         //Save the time at which the message was sent
         context->timestamp = time;

         //The timeout value should be randomized by the value of a uniform
         //number chosen from the range -1 to +1
         context->timeout = netGenerateRandRange(
            context->retransmitTimeout - DHCP_CLIENT_RAND_FACTOR,
            context->retransmitTimeout + DHCP_CLIENT_RAND_FACTOR);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else if(context->retransmitCount < DHCP_CLIENT_REQUEST_MAX_RC)
      {
         //Send a DHCPREQUEST message
         dhcpClientSendRequest(context);

         //The timeout value is doubled for each subsequent retransmission
         context->retransmitTimeout *= 2;

         //Limit the timeout value to a maximum of 64 seconds
         if(context->retransmitTimeout > DHCP_CLIENT_REQUEST_MAX_RT)
         {
            context->retransmitTimeout = DHCP_CLIENT_REQUEST_MAX_RT;
         }

         //Save the time at which the message was sent
         context->timestamp = time;

         //The timeout value should be randomized by the value of a uniform
         //number chosen from the range -1 to +1
         context->timeout = netGenerateRandRange(
            context->retransmitTimeout - DHCP_CLIENT_RAND_FACTOR,
            context->retransmitTimeout + DHCP_CLIENT_RAND_FACTOR);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else
      {
         //If the client does not receive a response within a reasonable
         //period of time, then it restarts the initialization procedure
         dhcpClientChangeState(context, DHCP_STATE_INIT, 0);
      }
   }

   //Manage DHCP configuration timeout
   dhcpClientCheckTimeout(context);
}


/**
 * @brief PROBING state
 *
 * The client probes the newly received address
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientStateProbing(DhcpClientContext *context)
{
   uint_t i;
   systime_t time;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Index of the IP address in the list of addresses assigned to the interface
   i = context->settings.ipAddrIndex;

   //Get current time
   time = osGetSystemTime();

   //Check current time
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //The address is already in use?
      if(interface->ipv4Context.addrList[i].conflict)
      {
         //If the client detects that the address is already in use, the
         //client must send a DHCPDECLINE message to the server and
         //restarts the configuration process
         dhcpClientSendDecline(context);

         //The client should wait a minimum of ten seconds before
         //restarting the configuration process to avoid excessive
         //network traffic in case of looping
         dhcpClientChangeState(context, DHCP_STATE_INIT, 0);
      }
      //Probing is on-going?
      else if(context->retransmitCount < DHCP_CLIENT_PROBE_NUM)
      {
         //Conflict detection is done using ARP probes
         arpSendProbe(interface, interface->ipv4Context.addrList[i].addr);

         //Save the time at which the packet was sent
         context->timestamp = time;
         //Delay until repeated probe
         context->timeout = DHCP_CLIENT_PROBE_DELAY;
         //Increment retransmission counter
         context->retransmitCount++;
      }
      //Probing is complete?
      else
      {
         //The use of the IPv4 address is now unrestricted
         interface->ipv4Context.addrList[i].state = IPV4_ADDR_STATE_VALID;

         //The client transitions to the ANNOUNCING state
         dhcpClientChangeState(context, DHCP_STATE_ANNOUNCING, 0);
      }
   }
}


/**
 * @brief ANNOUNCING state
 *
 * The client announces its new IP address
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientStateAnnouncing(DhcpClientContext *context)
{
   uint_t i;
   systime_t time;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Index of the IP address in the list of addresses assigned to the interface
   i = context->settings.ipAddrIndex;

   //Get current time
   time = osGetSystemTime();

   //Check current time
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //Announcement is on-going?
      if(context->retransmitCount < DHCP_CLIENT_ANNOUNCE_NUM)
      {
         //An ARP announcement is identical to an ARP probe, except that now
         //the sender and target IP addresses are both set to the host's newly
         //selected IPv4 address
         arpSendRequest(interface, interface->ipv4Context.addrList[i].addr,
            &MAC_BROADCAST_ADDR);

         //Save the time at which the packet was sent
         context->timestamp = time;
         //Delay until repeated probe
         context->timeout = DHCP_CLIENT_ANNOUNCE_INTERVAL;
         //Increment retransmission counter
         context->retransmitCount++;
      }

      //Announcing is complete?
      if(context->retransmitCount >= DHCP_CLIENT_ANNOUNCE_NUM)
      {
#if (MDNS_RESPONDER_SUPPORT == ENABLED)
         //Restart mDNS probing process
         mdnsResponderStartProbing(interface->mdnsResponderContext);
#endif
         //Dump current DHCP configuration for debugging purpose
         dhcpClientDumpConfig(context);

         //The client transitions to the BOUND state
         dhcpClientChangeState(context, DHCP_STATE_BOUND, 0);
      }
   }
}


/**
 * @brief BOUND state
 *
 * Client has a valid lease and is in its normal operating state
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientStateBound(DhcpClientContext *context)
{
   systime_t t1;
   systime_t time;

   //Get current time
   time = osGetSystemTime();

   //A client will never attempt to extend the lifetime of the address when
   //T1 set to 0xFFFFFFFF
   if(context->t1 != DHCP_INFINITE_TIME)
   {
      //Convert T1 to milliseconds
      if(context->t1 < (MAX_DELAY / 1000))
      {
         t1 = context->t1 * 1000;
      }
      else
      {
         t1 = MAX_DELAY;
      }

      //Check the time elapsed since the lease was obtained
      if(timeCompare(time, context->leaseStartTime + t1) >= 0)
      {
         //Record the time at which the client started the address renewal
         //process
         context->configStartTime = time;

         //Enter the RENEWING state
         dhcpClientChangeState(context, DHCP_STATE_RENEWING, 0);
      }
   }
}


/**
 * @brief RENEWING state
 *
 * Client is trying to renew its lease. It regularly sends
 * DHCPREQUEST messages with the server that gave it its current
 * lease specified, and waits for a reply
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientStateRenewing(DhcpClientContext *context)
{
   systime_t t2;
   systime_t time;

   //Get current time
   time = osGetSystemTime();

   //Check current time
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //Convert T2 to milliseconds
      if(context->t2 < (MAX_DELAY / 1000))
      {
         t2 = context->t2 * 1000;
      }
      else
      {
         t2 = MAX_DELAY;
      }

      //Check whether T2 timer has expired
      if(timeCompare(time, context->leaseStartTime + t2) < 0)
      {
         //First DHCPREQUEST message?
         if(context->retransmitCount == 0)
         {
            //A transaction identifier is used by the client to match incoming
            //DHCP messages with pending requests
            context->transactionId = netGenerateRand();
         }

         //Send a DHCPREQUEST message
         dhcpClientSendRequest(context);

         //Save the time at which the message was sent
         context->timestamp = time;

         //Compute the remaining time until T2 expires
         context->timeout = context->leaseStartTime + t2 - time;

         //The client should wait one-half of the remaining time until T2, down to
         //a minimum of 60 seconds, before retransmitting the DHCPREQUEST message
         if(context->timeout > (2 * DHCP_CLIENT_REQUEST_MIN_DELAY))
         {
            context->timeout /= 2;
         }

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else
      {
         //If no DHCPACK arrives before time T2, the client moves to REBINDING
         dhcpClientChangeState(context, DHCP_STATE_REBINDING, 0);
      }
   }
}


/**
 * @brief REBINDING state
 *
 * The client has failed to renew its lease with the server that originally
 * granted it, and now seeks a lease extension with any server that can
 * hear it. It periodically sends DHCPREQUEST messages with no server specified
 * until it gets a reply or the lease ends
 *
 * @param[in] context Pointer to the DHCP client context
 **/

void dhcpClientStateRebinding(DhcpClientContext *context)
{
   systime_t time;
   systime_t leaseTime;
#if (MDNS_RESPONDER_SUPPORT == ENABLED)
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->settings.interface;
#endif

   //Get current time
   time = osGetSystemTime();

   //Check current time
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //Convert the lease time to milliseconds
      if(context->leaseTime < (MAX_DELAY / 1000))
      {
         leaseTime = context->leaseTime * 1000;
      }
      else
      {
         leaseTime = MAX_DELAY;
      }

      //Check whether the lease has expired
      if(timeCompare(time, context->leaseStartTime + leaseTime) < 0)
      {
         //First DHCPREQUEST message?
         if(context->retransmitCount == 0)
         {
            //A transaction identifier is used by the client to match incoming
            //DHCP messages with pending requests
            context->transactionId = netGenerateRand();
         }

         //Send a DHCPREQUEST message
         dhcpClientSendRequest(context);

         //Save the time at which the message was sent
         context->timestamp = time;

         //Compute the remaining time until the lease expires
         context->timeout = context->leaseStartTime + leaseTime - time;

         //The client should wait one-half of the remaining lease time, down to a
         //minimum of 60 seconds, before retransmitting the DHCPREQUEST message
         if(context->timeout > (2 * DHCP_CLIENT_REQUEST_MIN_DELAY))
         {
            context->timeout /= 2;
         }

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else
      {
         //The host address is no longer valid
         dhcpClientResetConfig(context);

#if (MDNS_RESPONDER_SUPPORT == ENABLED)
         //Restart mDNS probing process
         mdnsResponderStartProbing(interface->mdnsResponderContext);
#endif
         //If the lease expires before the client receives a DHCPACK, the client
         //moves to INIT state
         dhcpClientChangeState(context, DHCP_STATE_INIT, 0);
      }
   }
}

#endif

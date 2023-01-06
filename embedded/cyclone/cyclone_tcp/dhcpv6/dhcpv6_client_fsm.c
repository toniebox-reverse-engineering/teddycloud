/**
 * @file dhcpv6_client_fsm.c
 * @brief DHCPv6 client finite state machine
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
#define TRACE_LEVEL DHCPV6_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "ipv6/ipv6.h"
#include "ipv6/ipv6_misc.h"
#include "dhcpv6/dhcpv6_client.h"
#include "dhcpv6/dhcpv6_client_fsm.h"
#include "dhcpv6/dhcpv6_client_misc.h"
#include "dhcpv6/dhcpv6_common.h"
#include "dhcpv6/dhcpv6_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV6_SUPPORT == ENABLED && DHCPV6_CLIENT_SUPPORT == ENABLED)


/**
 * @brief INIT state
 *
 * This is the initialization state, where a client begins the process of
 * acquiring a lease. It also returns here when a lease ends, or when a
 * lease negotiation fails
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateInit(Dhcpv6ClientContext *context)
{
   systime_t delay;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check whether the DHCPv6 client is running
   if(context->running)
   {
      //Wait for the link to be up before starting DHCPv6 configuration
      if(interface->linkState)
      {
         //Make sure that a valid link-local address has been assigned to the
         //interface
         if(ipv6GetLinkLocalAddrState(interface) == IPV6_ADDR_STATE_PREFERRED)
         {
            //Flush the list of IPv6 addresses from the client's IA
            dhcpv6ClientFlushAddrList(context);

            //The first Solicit message from the client on the interface must be
            //delayed by a random amount of time between 0 and SOL_MAX_DELAY
            delay = netGenerateRandRange(0, DHCPV6_CLIENT_SOL_MAX_DELAY);

            //Record the time at which the client started
            //the address acquisition process
            context->configStartTime = osGetSystemTime();
            //Clear flag
            context->timeoutEventDone = FALSE;

            //Switch to the SOLICIT state
            dhcpv6ClientChangeState(context, DHCPV6_STATE_SOLICIT, delay);
         }
      }
   }
}


/**
 * @brief SOLICIT state
 *
 * A client uses the Solicit message to discover DHCPv6 servers
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateSolicit(Dhcpv6ClientContext *context)
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
         //Reset server preference value
         context->serverPreference = -1;
         //Generate a 24-bit transaction ID
         context->transactionId = netGenerateRand() & 0x00FFFFFF;

         //Send a Solicit message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_SOLICIT);

         //Save the time at which the message was sent
         context->exchangeStartTime = time;
         context->timestamp = time;

         //If the client is waiting for an Advertise message, the first RT must
         //be selected to be strictly greater than IRT
         context->timeout = netGenerateRandRange(DHCPV6_CLIENT_SOL_TIMEOUT,
            DHCPV6_CLIENT_SOL_TIMEOUT + DHCPV6_CLIENT_SOL_TIMEOUT / 10);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else
      {
         //Check whether a valid Advertise message has been received
         if(context->serverPreference >= 0)
         {
            //Continue configuration procedure
            dhcpv6ClientChangeState(context, DHCPV6_STATE_REQUEST, 0);
         }
         else
         {
            //Send a Solicit message
            dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_SOLICIT);

            //Save the time at which the message was sent
            context->timestamp = time;

            //The RT is doubled for each subsequent retransmission
            context->timeout = netGenerateRandRange(
               context->timeout * 2 - context->timeout / 10,
               context->timeout * 2 + context->timeout / 10);

            //MRT specifies an upper bound on the value of RT
            if(context->timeout > DHCPV6_CLIENT_SOL_MAX_RT)
            {
               //Each computation of a new RT includes a randomization factor
               context->timeout = netGenerateRandRange(
                  DHCPV6_CLIENT_SOL_MAX_RT - DHCPV6_CLIENT_SOL_MAX_RT / 10,
                  DHCPV6_CLIENT_SOL_MAX_RT + DHCPV6_CLIENT_SOL_MAX_RT / 10);
            }

            //Increment retransmission counter
            context->retransmitCount++;
         }
      }
   }

   //Manage DHCPv6 configuration timeout
   dhcpv6ClientCheckTimeout(context);
}


/**
 * @brief REQUEST state
 *
 * The client uses a Request message to populate IAs with addresses and obtain
 * other configuration information. The client includes one or more more IA
 * options in the Request message. The server then returns addresses and other
 * information about the IAs to the client in IA options in a Reply message
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateRequest(Dhcpv6ClientContext *context)
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
         //Generate a 24-bit transaction ID
         context->transactionId = netGenerateRand() & 0x00FFFFFF;

         //Send a Request message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_REQUEST);

         //Save the time at which the message was sent
         context->exchangeStartTime = time;
         context->timestamp = time;

         //Initial retransmission timeout
         context->timeout = netGenerateRandRange(
            DHCPV6_CLIENT_REQ_TIMEOUT - DHCPV6_CLIENT_REQ_TIMEOUT / 10,
            DHCPV6_CLIENT_REQ_TIMEOUT + DHCPV6_CLIENT_REQ_TIMEOUT / 10);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else if(context->retransmitCount < DHCPV6_CLIENT_REQ_MAX_RC)
      {
         //Send a Request message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_REQUEST);

         //Save the time at which the message was sent
         context->timestamp = time;

         //The RT is doubled for each subsequent retransmission
         context->timeout = netGenerateRandRange(
            context->timeout * 2 - context->timeout / 10,
            context->timeout * 2 + context->timeout / 10);

         //MRT specifies an upper bound on the value of RT
         if(context->timeout > DHCPV6_CLIENT_REQ_MAX_RT)
         {
            //Each computation of a new RT includes a randomization factor
            context->timeout = netGenerateRandRange(
               DHCPV6_CLIENT_REQ_MAX_RT - DHCPV6_CLIENT_REQ_MAX_RT / 10,
               DHCPV6_CLIENT_REQ_MAX_RT + DHCPV6_CLIENT_REQ_MAX_RT / 10);
         }

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else
      {
         //If the client does not receive a response within a reasonable period
         //of time, then it restarts the initialization procedure
         dhcpv6ClientChangeState(context, DHCPV6_STATE_INIT, 0);
      }
   }

   //Manage DHCPv6 configuration timeout
   dhcpv6ClientCheckTimeout(context);
}


/**
 * @brief INIT-CONFIRM state
 *
 * When a client that already has a valid lease starts up after a power-down
 * or reboot, it starts here instead of the INIT state
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateInitConfirm(Dhcpv6ClientContext *context)
{
   systime_t delay;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check whether the DHCPv6 client is running
   if(context->running)
   {
      //Wait for the link to be up before starting DHCPv6 configuration
      if(interface->linkState)
      {
         //Make sure that a valid link-local address has been assigned to the
         //interface
         if(ipv6GetLinkLocalAddrState(interface) == IPV6_ADDR_STATE_PREFERRED)
         {
            //The first Confirm message from the client on the interface must be
            //delayed by a random amount of time between 0 and CNF_MAX_DELAY
            delay = netGenerateRandRange(0, DHCPV6_CLIENT_CNF_MAX_DELAY);

            //Record the time at which the client started the address
            //acquisition process
            context->configStartTime = osGetSystemTime();
            //Clear flag
            context->timeoutEventDone = FALSE;

            //Switch to the CONFIRM state
            dhcpv6ClientChangeState(context, DHCPV6_STATE_CONFIRM, delay);
         }
      }
   }
}


/**
 * @brief CONFIRM state
 *
 * Whenever a client may have moved to a new link, the prefixes from the
 * addresses assigned to the interfaces on that link may no longer be
 * appropriate for the link to which the client is attached. In such the
 * client must initiate a Confirm/Reply message exchange
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateConfirm(Dhcpv6ClientContext *context)
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
         //Generate a 24-bit transaction ID
         context->transactionId = netGenerateRand() & 0x00FFFFFF;

         //Send a Confirm message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_CONFIRM);

         //Save the time at which the client sent the first message
         context->exchangeStartTime = time;
         context->timestamp = time;

         //Initial retransmission timeout
         context->timeout = netGenerateRandRange(
            DHCPV6_CLIENT_CNF_TIMEOUT - DHCPV6_CLIENT_CNF_TIMEOUT / 10,
            DHCPV6_CLIENT_CNF_TIMEOUT + DHCPV6_CLIENT_CNF_TIMEOUT / 10);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else
      {
         //Send a Confirm message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_CONFIRM);

         //Save the time at which the message was sent
         context->timestamp = time;

         //The RT is doubled for each subsequent retransmission
         context->timeout = netGenerateRandRange(
            context->timeout * 2 - context->timeout / 10,
            context->timeout * 2 + context->timeout / 10);

         //MRT specifies an upper bound on the value of RT
         if(context->timeout > DHCPV6_CLIENT_CNF_MAX_RT)
         {
            //Each computation of a new RT includes a randomization factor
            context->timeout = netGenerateRandRange(
               DHCPV6_CLIENT_CNF_MAX_RT - DHCPV6_CLIENT_CNF_MAX_RT / 10,
               DHCPV6_CLIENT_CNF_MAX_RT + DHCPV6_CLIENT_CNF_MAX_RT / 10);
         }

         //Increment retransmission counter
         context->retransmitCount++;
      }
   }
   else
   {
      //Check retransmission counter
      if(context->retransmitCount > 0)
      {
         //The message exchange fails once MRD seconds have elapsed since the
         //client first transmitted the message
         if(timeCompare(time, context->exchangeStartTime + DHCPV6_CLIENT_CNF_MAX_RD) >= 0)
         {
            //If the client receives no responses before the message transmission
            //process terminates, the client should continue to use any IP
            //addresses using the last known lifetimes for those addresses
            dhcpv6ClientChangeState(context, DHCPV6_STATE_INIT, 0);
         }
      }
   }

   //Manage DHCPv6 configuration timeout
   dhcpv6ClientCheckTimeout(context);
}


/**
 * @brief DAD state
 *
 * The client perform duplicate address detection on each of the addresses
 * in any IAs it receives in the Reply message before using that address for
 * traffic
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateDad(Dhcpv6ClientContext *context)
{
   uint_t i;
   NetInterface *interface;
   Ipv6AddrState state;
   Dhcpv6ClientAddrEntry *entry;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Loop through the IPv6 addresses recorded by the DHCPv6 client
   for(i = 0; i < DHCPV6_CLIENT_ADDR_LIST_SIZE; i++)
   {
      //Point to the current entry
      entry = &context->ia.addrList[i];

      //Check the IPv6 address is a tentative address?
      if(entry->validLifetime > 0)
      {
         //Get the state of the current IPv6 address
         state = ipv6GetAddrState(interface, &entry->addr);

         //Duplicate Address Detection in progress?
         if(state == IPV6_ADDR_STATE_TENTATIVE)
         {
            //Exit immediately
            return;
         }
         //Duplicate Address Detection failed?
         else if(state == IPV6_ADDR_STATE_INVALID)
         {
            //Switch to the DECLINE state
            dhcpv6ClientChangeState(context, DHCPV6_STATE_DECLINE, 0);
            //Exit immediately
            return;
         }
      }
   }

   //Dump current DHCPv6 configuration for debugging purpose
   dhcpv6ClientDumpConfig(context);
   //Switch to the BOUND state
   dhcpv6ClientChangeState(context, DHCPV6_STATE_BOUND, 0);
}


/**
 * @brief BOUND state
 *
 * Client has a valid lease and is in its normal operating state
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateBound(Dhcpv6ClientContext *context)
{
   systime_t t1;
   systime_t time;

   //Get current time
   time = osGetSystemTime();

   //A client will never attempt to extend the lifetime of any address in an
   //IA with T1 set to 0xffffffff
   if(context->ia.t1 != DHCPV6_INFINITE_TIME)
   {
      //Convert T1 to milliseconds
      if(context->ia.t1 < (MAX_DELAY / 1000))
      {
         t1 = context->ia.t1 * 1000;
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

         //Enter the RENEW state
         dhcpv6ClientChangeState(context, DHCPV6_STATE_RENEW, 0);
      }
   }
}


/**
 * @brief RENEW state
 *
 * The client sends a Renew message to the server that originally provided
 * the client's addresses and configuration parameters to extend the lifetimes
 * on the addresses assigned to the client and to update other configuration
 * parameters
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateRenew(Dhcpv6ClientContext *context)
{
   systime_t t2;
   systime_t time;

   //Get current time
   time = osGetSystemTime();

   //Check current time
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //Check retransmission counter
      if(context->retransmitCount == 0)
      {
         //Generate a 24-bit transaction ID
         context->transactionId = netGenerateRand() & 0x00FFFFFF;

         //Send a Renew message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_RENEW);

         //Save the time at which the message was sent
         context->exchangeStartTime = time;
         context->timestamp = time;

         //Initial retransmission timeout
         context->timeout = netGenerateRandRange(
            DHCPV6_CLIENT_REN_TIMEOUT - DHCPV6_CLIENT_REN_TIMEOUT / 10,
            DHCPV6_CLIENT_REN_TIMEOUT + DHCPV6_CLIENT_REN_TIMEOUT / 10);
      }
      else
      {
         //Send a Renew message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_RENEW);

         //Save the time at which the message was sent
         context->timestamp = time;

         //The RT is doubled for each subsequent retransmission
         context->timeout = netGenerateRandRange(
            context->timeout * 2 - context->timeout / 10,
            context->timeout * 2 + context->timeout / 10);

         //MRT specifies an upper bound on the value of RT
         if(context->timeout > DHCPV6_CLIENT_REN_MAX_RT)
         {
            //Each computation of a new RT includes a randomization factor
            context->timeout = netGenerateRandRange(
               DHCPV6_CLIENT_REN_MAX_RT - DHCPV6_CLIENT_REN_MAX_RT / 10,
               DHCPV6_CLIENT_REN_MAX_RT + DHCPV6_CLIENT_REN_MAX_RT / 10);
         }
      }

      //Increment retransmission counter
      context->retransmitCount++;
   }
   else
   {
      //A client will never attempt to use a Rebind message to locate a
      //different server to extend the lifetime of any address in an IA
      //with T2 set to 0xffffffff
      if(context->ia.t2 != DHCPV6_INFINITE_TIME)
      {
         //Convert T2 to milliseconds
         if(context->ia.t2 < (MAX_DELAY / 1000))
         {
            t2 = context->ia.t2 * 1000;
         }
         else
         {
            t2 = MAX_DELAY;
         }

         //Check whether T2 timer has expired
         if(timeCompare(time, context->leaseStartTime + t2) >= 0)
         {
            //Switch to the REBIND state
            dhcpv6ClientChangeState(context, DHCPV6_STATE_REBIND, 0);
         }
      }
   }
}


/**
 * @brief REBIND state
 *
 * The client sends a Rebind message to any available server to extend the
 * lifetimes on the addresses assigned to the client and to update other
 * configuration parameters. This message is sent after a client receives no
 * response to a Renew message
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateRebind(Dhcpv6ClientContext *context)
{
   uint_t i;
   systime_t time;
   NetInterface *interface;
   Dhcpv6ClientAddrEntry *entry;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Get current time
   time = osGetSystemTime();

   //Check current time
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //Check retransmission counter
      if(context->retransmitCount == 0)
      {
         //Generate a 24-bit transaction ID
         context->transactionId = netGenerateRand() & 0x00FFFFFF;

         //Send a Rebind message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_REBIND);

         //Save the time at which the message was sent
         context->exchangeStartTime = time;
         context->timestamp = time;

         //Initial retransmission timeout
         context->timeout = netGenerateRandRange(
            DHCPV6_CLIENT_REB_TIMEOUT - DHCPV6_CLIENT_REB_TIMEOUT / 10,
            DHCPV6_CLIENT_REB_TIMEOUT + DHCPV6_CLIENT_REB_TIMEOUT / 10);
      }
      else
      {
         //Send a Rebind message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_REBIND);

         //Save the time at which the message was sent
         context->timestamp = time;

         //The RT is doubled for each subsequent retransmission
         context->timeout = netGenerateRandRange(
            context->timeout * 2 - context->timeout / 10,
            context->timeout * 2 + context->timeout / 10);

         //MRT specifies an upper bound on the value of RT
         if(context->timeout > DHCPV6_CLIENT_REB_MAX_RT)
         {
            //Each computation of a new RT includes a randomization factor
            context->timeout = netGenerateRandRange(
               DHCPV6_CLIENT_REB_MAX_RT - DHCPV6_CLIENT_REB_MAX_RT / 10,
               DHCPV6_CLIENT_REB_MAX_RT + DHCPV6_CLIENT_REB_MAX_RT / 10);
         }
      }

      //Increment retransmission counter
      context->retransmitCount++;
   }
   else
   {
      //Loop through the IPv6 addresses recorded by the DHCPv6 client
      for(i = 0; i < DHCPV6_CLIENT_ADDR_LIST_SIZE; i++)
      {
         //Point to the current entry
         entry = &context->ia.addrList[i];

         //Valid IPv6 address?
         if(entry->validLifetime > 0)
         {
            //Check whether the valid lifetime has expired
            if(ipv6GetAddrState(interface, &entry->addr) == IPV6_ADDR_STATE_INVALID)
            {
               //Restart DHCPv6 configuration
               dhcpv6ClientChangeState(context, DHCPV6_STATE_INIT, 0);
            }
         }
      }
   }
}


/**
 * @brief RELEASE state
 *
 * To release one or more addresses, a client sends a Release message to the
 * server
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateRelease(Dhcpv6ClientContext *context)
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
         //Generate a 24-bit transaction ID
         context->transactionId = netGenerateRand() & 0x00FFFFFF;

         //Send a Release message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_RELEASE);

         //Save the time at which the message was sent
         context->exchangeStartTime = time;
         context->timestamp = time;

         //Initial retransmission timeout
         context->timeout = netGenerateRandRange(
            DHCPV6_CLIENT_REL_TIMEOUT - DHCPV6_CLIENT_REL_TIMEOUT / 10,
            DHCPV6_CLIENT_REL_TIMEOUT + DHCPV6_CLIENT_REL_TIMEOUT / 10);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else if(context->retransmitCount < DHCPV6_CLIENT_REL_MAX_RC)
      {
         //Send a Release message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_RELEASE);

         //Save the time at which the message was sent
         context->timestamp = time;

         //The RT is doubled for each subsequent retransmission
         context->timeout = netGenerateRandRange(
            context->timeout * 2 - context->timeout / 10,
            context->timeout * 2 + context->timeout / 10);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else
      {
         //Implementations should retransmit one or more times, but may choose
         //to terminate the retransmission procedure early
         context->running = FALSE;

         //Reinitialize state machine
         dhcpv6ClientChangeState(context, DHCPV6_STATE_INIT, 0);
      }
   }
}


/**
 * @brief DECLINE state
 *
 * If a client detects that one or more addresses assigned to it by a server
 * are already in use by another node, the client sends a Decline message to
 * the server to inform it that the address is suspect
 *
 * @param[in] context Pointer to the DHCPv6 client context
 **/

void dhcpv6ClientStateDecline(Dhcpv6ClientContext *context)
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
         //Generate a 24-bit transaction ID
         context->transactionId = netGenerateRand() & 0x00FFFFFF;

         //Send a Decline message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_DECLINE);

         //Save the time at which the message was sent
         context->exchangeStartTime = time;
         context->timestamp = time;

         //Initial retransmission timeout
         context->timeout = netGenerateRandRange(
            DHCPV6_CLIENT_DEC_TIMEOUT - DHCPV6_CLIENT_DEC_TIMEOUT / 10,
            DHCPV6_CLIENT_DEC_TIMEOUT + DHCPV6_CLIENT_DEC_TIMEOUT / 10);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else if(context->retransmitCount < DHCPV6_CLIENT_DEC_MAX_RC)
      {
         //Send a Decline message
         dhcpv6ClientSendMessage(context, DHCPV6_MSG_TYPE_DECLINE);

         //Save the time at which the message was sent
         context->timestamp = time;

         //The RT is doubled for each subsequent retransmission
         context->timeout = netGenerateRandRange(
            context->timeout * 2 - context->timeout / 10,
            context->timeout * 2 + context->timeout / 10);

         //Increment retransmission counter
         context->retransmitCount++;
      }
      else
      {
         //If the client does not receive a response within a reasonable period
         //of time, then it restarts the initialization procedure
         dhcpv6ClientChangeState(context, DHCPV6_STATE_INIT, 0);
      }
   }
}

#endif

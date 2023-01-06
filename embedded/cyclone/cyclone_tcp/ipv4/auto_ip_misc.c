/**
 * @file auto_ip_misc.c
 * @brief Helper functions for Auto-IP
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
#define TRACE_LEVEL AUTO_IP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "core/ethernet.h"
#include "ipv4/arp.h"
#include "ipv4/auto_ip.h"
#include "ipv4/auto_ip_misc.h"
#include "mdns/mdns_responder.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED && AUTO_IP_SUPPORT == ENABLED)

//Tick counter to handle periodic operations
systime_t autoIpTickCounter;


/**
 * @brief Auto-IP timer handler
 *
 * This routine must be periodically called by the TCP/IP stack to
 * manage Auto-IP operation
 *
 * @param[in] context Pointer to the Auto-IP context
 **/

void autoIpTick(AutoIpContext *context)
{
   uint_t i;
   systime_t time;
   systime_t delay;
   NetInterface *interface;

   //Make sure Auto-IP has been properly instantiated
   if(context == NULL)
      return;

   //Point to the underlying network interface
   interface = context->settings.interface;
   //Index of the IP address in the list of addresses assigned to the interface
   i = context->settings.ipAddrIndex;

   //Get current time
   time = osGetSystemTime();

   //Check current state
   if(context->state == AUTO_IP_STATE_INIT)
   {
      //Wait for the link to be up before starting Auto-IP
      if(context->running && interface->linkState)
      {
         //Configure subnet mask
         interface->ipv4Context.addrList[i].subnetMask = AUTO_IP_MASK;

         //The address must be in the range from 169.254.1.0 to 169.254.254.255
         if(ntohl(context->linkLocalAddr) < NTOHL(AUTO_IP_ADDR_MIN) ||
            ntohl(context->linkLocalAddr) > NTOHL(AUTO_IP_ADDR_MAX))
         {
            //Generate a random link-local address
            autoIpGenerateAddr(&context->linkLocalAddr);
         }

         //Use the link-local address as a tentative address
         interface->ipv4Context.addrList[i].addr = context->linkLocalAddr;
         interface->ipv4Context.addrList[i].state = IPV4_ADDR_STATE_TENTATIVE;

         //Clear conflict flag
         interface->ipv4Context.addrList[i].conflict = FALSE;

         //Initial random delay
         delay = netGenerateRandRange(0, AUTO_IP_PROBE_WAIT);

         //Check whether the number of conflicts exceeds the maximum acceptable
         //value
         if(context->conflictCount >= AUTO_IP_MAX_CONFLICTS)
         {
            //The host must limit the rate at which it probes for new addresses
            delay += AUTO_IP_RATE_LIMIT_INTERVAL;
         }

         //Verify the uniqueness of the link-local address
         autoIpChangeState(context, AUTO_IP_STATE_PROBING, delay);
      }
   }
   else if(context->state == AUTO_IP_STATE_PROBING)
   {
      //Any conflict detected?
      if(interface->ipv4Context.addrList[i].conflict)
      {
         //The address is already in use by some other host and must not be
         //assigned to the interface
         autoIpResetConfig(context);

         //The host should maintain a counter of the number of address conflicts
         //it has experienced
         context->conflictCount++;

         //The host must pick a new random address and repeat the process
         autoIpGenerateAddr(&context->linkLocalAddr);
         //Update state machine
         autoIpChangeState(context, AUTO_IP_STATE_INIT, 0);
      }
      else
      {
         //Check current time
         if(timeCompare(time, context->timestamp + context->timeout) >= 0)
         {
            //Address Conflict Detection is on-going?
            if(context->retransmitCount < AUTO_IP_PROBE_NUM)
            {
               //Conflict detection is done using ARP probes
               arpSendProbe(interface, context->linkLocalAddr);

               //Save the time at which the packet was sent
               context->timestamp = time;
               //Increment retransmission counter
               context->retransmitCount++;

               //Last probe packet sent?
               if(context->retransmitCount == AUTO_IP_PROBE_NUM)
               {
                  //Delay before announcing
                  context->timeout = AUTO_IP_ANNOUNCE_WAIT;
               }
               else
               {
                  //Maximum delay till repeated probe
                  context->timeout = netGenerateRandRange(AUTO_IP_PROBE_MIN,
                     AUTO_IP_PROBE_MAX);
               }
            }
            else
            {
               //The use of the IPv4 address is now unrestricted
               interface->ipv4Context.addrList[i].state = IPV4_ADDR_STATE_VALID;

#if (MDNS_RESPONDER_SUPPORT == ENABLED)
               //Restart mDNS probing process
               mdnsResponderStartProbing(interface->mdnsResponderContext);
#endif
               //The host must then announce its claimed address
               autoIpChangeState(context, AUTO_IP_STATE_ANNOUNCING, 0);
            }
         }
      }
   }
   else if(context->state == AUTO_IP_STATE_ANNOUNCING)
   {
      //Check current time
      if(timeCompare(time, context->timestamp + context->timeout) >= 0)
      {
         //An ARP announcement is identical to an ARP probe, except that now
         //the sender and target IP addresses are both set to the host's newly
         //selected IPv4 address
         arpSendRequest(interface, context->linkLocalAddr, &MAC_BROADCAST_ADDR);

         //Save the time at which the packet was sent
         context->timestamp = time;
         //Time interval between announcement packets
         context->timeout = AUTO_IP_ANNOUNCE_INTERVAL;
         //Increment retransmission counter
         context->retransmitCount++;

         //Announcing is complete?
         if(context->retransmitCount >= AUTO_IP_ANNOUNCE_NUM)
         {
            //Successful address autoconfiguration
            autoIpChangeState(context, AUTO_IP_STATE_CONFIGURED, 0);
            //Reset conflict counter
            context->conflictCount = 0;

            //Dump current IPv4 configuration for debugging purpose
            autoIpDumpConfig(context);
         }
      }
   }
   else if(context->state == AUTO_IP_STATE_CONFIGURED)
   {
      //Address Conflict Detection is an on-going process that is in effect for
      //as long as a host is using an IPv4 link-local address
      if(interface->ipv4Context.addrList[i].conflict)
      {
         //The host may elect to attempt to defend its address by recording
         //the time that the conflicting ARP packet was received, and then
         //broadcasting one single ARP announcement, giving its own IP and
         //hardware addresses as the sender addresses of the ARP
#if (AUTO_IP_BCT_SUPPORT == ENABLED)
         arpSendProbe(interface, context->linkLocalAddr);
#else
         arpSendRequest(interface, context->linkLocalAddr, &MAC_BROADCAST_ADDR);
#endif
         //Clear conflict flag
         interface->ipv4Context.addrList[i].conflict = FALSE;

         //The host can then continue to use the address normally without
         //any further special action
         autoIpChangeState(context, AUTO_IP_STATE_DEFENDING, 0);
      }
   }
   else if(context->state == AUTO_IP_STATE_DEFENDING)
   {
      //if this is not the first conflicting ARP packet the host has seen, and
      //the time recorded for the previous conflicting ARP packet is recent,
      //within DEFEND_INTERVAL seconds, then the host must immediately cease
      //using this address
      if(interface->ipv4Context.addrList[i].conflict)
      {
         //The link-local address cannot be used anymore
         autoIpResetConfig(context);

#if (MDNS_RESPONDER_SUPPORT == ENABLED)
         //Restart mDNS probing process
         mdnsResponderStartProbing(interface->mdnsResponderContext);
#endif
         //The host must pick a new random address and probes/announces again
         autoIpGenerateAddr(&context->linkLocalAddr);
         //Update state machine
         autoIpChangeState(context, AUTO_IP_STATE_INIT, 0);
      }
      else
      {
         //Check whether the DEFEND_INTERVAL has elapsed
         if(timeCompare(time, context->timestamp + AUTO_IP_DEFEND_INTERVAL) >= 0)
         {
            //The host can continue to use its link-local address
            autoIpChangeState(context, AUTO_IP_STATE_CONFIGURED, 0);
         }
      }
   }
}


/**
 * @brief Callback function for link change event
 * @param[in] context Pointer to the Auto-IP context
 **/

void autoIpLinkChangeEvent(AutoIpContext *context)
{
   NetInterface *interface;

   //Make sure Auto-IP has been properly instantiated
   if(context == NULL)
      return;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check whether Auto-IP is enabled
   if(context->running)
   {
      //The host address is not longer valid
      autoIpResetConfig(context);

#if (MDNS_RESPONDER_SUPPORT == ENABLED)
      //Restart mDNS probing process
      mdnsResponderStartProbing(interface->mdnsResponderContext);
#endif
   }

   //Reinitialize state machine
   context->state = AUTO_IP_STATE_INIT;
   //Reset conflict counter
   context->conflictCount = 0;

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
 * @brief Update Auto-IP FSM state
 * @param[in] context Pointer to the Auto-IP context
 * @param[in] newState New Auto-IP state to switch to
 * @param[in] delay Initial delay
 **/

void autoIpChangeState(AutoIpContext *context, AutoIpState newState,
   systime_t delay)
{
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Set time stamp
   context->timestamp = osGetSystemTime();
   //Set initial delay
   context->timeout = delay;
   //Reset retransmission counter
   context->retransmitCount = 0;
   //Switch to the new state
   context->state = newState;

   //Any registered callback?
   if(context->settings.stateChangeEvent != NULL)
   {
      //Release exclusive access
      osReleaseMutex(&netMutex);
      //Invoke user callback function
      context->settings.stateChangeEvent(context, interface, newState);
      //Get exclusive access
      osAcquireMutex(&netMutex);
   }
}


/**
 * @brief Generate a random link-local address
 * @param[out] ipAddr Random link-local address
 **/

void autoIpGenerateAddr(Ipv4Addr *ipAddr)
{
   uint32_t n;

   //Generate a random address in the range from 169.254.1.0 to 169.254.254.255
   n = netGenerateRand() % (NTOHL(AUTO_IP_ADDR_MAX - AUTO_IP_ADDR_MIN) + 1);
   n += NTOHL(AUTO_IP_ADDR_MIN);

   //Convert the resulting address to network byte order
   *ipAddr = htonl(n);
}


/**
 * @brief Reset Auto-IP configuration
 * @param[in] context Pointer to the Auto-IP context
 **/

void autoIpResetConfig(AutoIpContext *context)
{
   uint_t i;
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

   //The host must not send packets to any router for forwarding (refer to
   //RFC 3927, section 2.6.2)
   interface->ipv4Context.addrList[i].defaultGateway = IPV4_UNSPECIFIED_ADDR;
}


/**
 * @brief Dump Auto-IP configuration for debugging purpose
 * @param[in] context Pointer to the Auto-IP context
 **/

void autoIpDumpConfig(AutoIpContext *context)
{
#if (AUTO_IP_TRACE_LEVEL >= TRACE_LEVEL_INFO)
   uint_t i;
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
   TRACE_INFO("Auto-IP configuration:\r\n");

   //Link-local address
   TRACE_INFO("  Link-local Address = %s\r\n",
      ipv4AddrToString(ipv4Context->addrList[i].addr, NULL));

   //Subnet mask
   TRACE_INFO("  Subnet Mask = %s\r\n",
      ipv4AddrToString(ipv4Context->addrList[i].subnetMask, NULL));

   //Debug message
   TRACE_INFO("\r\n");
#endif
}

#endif

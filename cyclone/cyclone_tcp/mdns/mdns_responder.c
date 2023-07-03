/**
 * @file mdns_responder.c
 * @brief mDNS responder (Multicast DNS)
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
#define TRACE_LEVEL MDNS_TRACE_LEVEL

//Dependencies
#include <stdlib.h>
#include "core/net.h"
#include "dns/dns_debug.h"
#include "mdns/mdns_responder.h"
#include "mdns/mdns_responder_misc.h"
#include "dns_sd/dns_sd_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (MDNS_RESPONDER_SUPPORT == ENABLED)

//Tick counter to handle periodic operations
systime_t mdnsResponderTickCounter;


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains mDNS responder settings
 **/

void mdnsResponderGetDefaultSettings(MdnsResponderSettings *settings)
{
   //Use default interface
   settings->interface = netGetDefaultInterface();

   //Number of announcement packets
   settings->numAnnouncements = MDNS_ANNOUNCE_NUM;
   //TTL resource record
   settings->ttl = MDNS_DEFAULT_RR_TTL;
   //FSM state change event
   settings->stateChangeEvent = NULL;
}


/**
 * @brief mDNS responder initialization
 * @param[in] context Pointer to the mDNS responder context
 * @param[in] settings mDNS responder specific settings
 * @return Error code
 **/

error_t mdnsResponderInit(MdnsResponderContext *context,
   const MdnsResponderSettings *settings)
{
   NetInterface *interface;

   //Debug message
   TRACE_INFO("Initializing mDNS responder...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid network interface?
   if(settings->interface == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the underlying network interface
   interface = settings->interface;

   //Clear the mDNS responder context
   osMemset(context, 0, sizeof(MdnsResponderContext));
   //Save user settings
   context->settings = *settings;

   //mDNS responder is currently suspended
   context->running = FALSE;
   //Initialize state machine
   context->state = MDNS_STATE_INIT;

   //Attach the mDNS responder context to the network interface
   interface->mdnsResponderContext = context;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start mDNS responder
 * @param[in] context Pointer to the mDNS responder context
 * @return Error code
 **/

error_t mdnsResponderStart(MdnsResponderContext *context)
{
   //Make sure the mDNS responder context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting mDNS responder...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Start mDNS responder
   context->running = TRUE;
   //Initialize state machine
   context->state = MDNS_STATE_INIT;

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Stop mDNS responder
 * @param[in] context Pointer to the mDNS responder context
 * @return Error code
 **/

error_t mdnsResponderStop(MdnsResponderContext *context)
{
   //Make sure the mDNS responder context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping mDNS responder...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Suspend mDNS responder
   context->running = FALSE;
   //Reinitialize state machine
   context->state = MDNS_STATE_INIT;

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Retrieve current state
 * @param[in] context Pointer to the mDNS responder context
 * @return Current mDNS responder state
 **/

MdnsState mdnsResponderGetState(MdnsResponderContext *context)
{
   MdnsState state;

   //Get exclusive access
   osAcquireMutex(&netMutex);
   //Get current state
   state = context->state;
   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Return current state
   return state;
}


/**
 * @brief Set host name
 * @param[in] context Pointer to the mDNS responder context
 * @param[in] hostname NULL-terminated string that contains the host name
 * @return Error code
 **/

error_t mdnsResponderSetHostname(MdnsResponderContext *context,
   const char_t *hostname)
{
   NetInterface *interface;

   //Check parameters
   if(context == NULL || hostname == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the host name is acceptable
   if(osStrlen(hostname) > MDNS_RESPONDER_MAX_HOSTNAME_LEN)
      return ERROR_INVALID_LENGTH;

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Check whether a host name is already assigned
   if(context->hostname[0] != '\0')
   {
      //Check whether the link is up
      if(interface->linkState)
      {
         //Send a goodbye packet
         mdnsResponderSendGoodbye(context);
      }
   }

   //Set host name
   osStrcpy(context->hostname, hostname);

   //Restart probing process (host name)
   mdnsResponderStartProbing(interface->mdnsResponderContext);

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Restart probing process
 * @param[in] context Pointer to the mDNS responder context
 * @return Error code
 **/

error_t mdnsResponderStartProbing(MdnsResponderContext *context)
{
   uint_t i;
   NetInterface *interface;

   //Check whether the mDNS responder has been properly instantiated
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Reset variables
   context->ipv4AddrCount = 0;
   context->ipv6AddrCount = 0;

#if (IPV4_SUPPORT == ENABLED)
   //Loop through the list of IPv4 addresses assigned to the interface
   for(i = 0; i < IPV4_ADDR_LIST_SIZE; i++)
   {
      //Valid IPv4 address?
      if(interface->ipv4Context.addrList[i].state == IPV4_ADDR_STATE_VALID)
      {
         MdnsIpv4AddrEntry *entry;

         //Point to the current entry
         entry = &context->ipv4AddrList[i];

         //Format A resource record
         entry->record.rtype = HTONS(DNS_RR_TYPE_A);
         entry->record.rclass = HTONS(DNS_RR_CLASS_IN);
         entry->record.ttl = htonl(MDNS_DEFAULT_RR_TTL);
         entry->record.rdlength = HTONS(sizeof(Ipv4Addr));

         //Copy IPv4 address
         ipv4CopyAddr(entry->record.rdata, &interface->ipv4Context.addrList[i].addr);

         //Generate domain name for reverse DNS lookup
         dnsGenerateIpv4ReverseName(interface->ipv4Context.addrList[i].addr,
            entry->reverseName);

         //The entry is valid
         context->ipv4AddrList[i].valid = TRUE;

         //Increment the number of valid IPv4 addresses
         context->ipv4AddrCount++;
      }
      else
      {
         //Invalidate the entry
         context->ipv4AddrList[i].valid = FALSE;
      }
   }
#endif

#if (IPV6_SUPPORT == ENABLED)
   //Loop through the list of IPv6 addresses assigned to the interface
   for(i = 0; i < IPV6_ADDR_LIST_SIZE; i++)
   {
      //Valid IPv6 address?
      if(interface->ipv6Context.addrList[i].state == IPV6_ADDR_STATE_PREFERRED ||
         interface->ipv6Context.addrList[i].state == IPV6_ADDR_STATE_DEPRECATED)
      {
         MdnsIpv6AddrEntry *entry;

         //Point to the current entry
         entry = &context->ipv6AddrList[i];

         //Format AAAA resource record
         entry->record.rtype = HTONS(DNS_RR_TYPE_AAAA);
         entry->record.rclass = HTONS(DNS_RR_CLASS_IN);
         entry->record.ttl = htonl(MDNS_DEFAULT_RR_TTL);
         entry->record.rdlength = HTONS(sizeof(Ipv6Addr));

         //Copy IPv6 address
         ipv6CopyAddr(entry->record.rdata, &interface->ipv6Context.addrList[i].addr);

         //Generate domain name for reverse DNS lookup
         dnsGenerateIpv6ReverseName(&interface->ipv6Context.addrList[i].addr,
            entry->reverseName);

         //The entry is valid
         context->ipv6AddrList[i].valid = TRUE;

         //Increment the number of valid IPv6 addresses
         context->ipv6AddrCount++;
      }
      else
      {
         //Invalidate the entry
         context->ipv6AddrList[i].valid = FALSE;
      }
   }
#endif

   //Force mDNS responder to start probing again
   context->state = MDNS_STATE_INIT;

#if (DNS_SD_SUPPORT == ENABLED)
   //Restart probing process (service instance name)
   dnsSdStartProbing(interface->dnsSdContext);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief mDNS responder timer handler
 *
 * This routine must be periodically called by the TCP/IP stack to
 * manage mDNS operation
 *
 * @param[in] context Pointer to the mDNS responder context
 **/

void mdnsResponderTick(MdnsResponderContext *context)
{
   systime_t time;
   systime_t delay;
   NetInterface *interface;
   IpAddr destIpAddr;

   //Make sure the mDNS responder has been properly instantiated
   if(context == NULL)
      return;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Get current time
   time = osGetSystemTime();

   //Check current state
   if(context->state == MDNS_STATE_INIT)
   {
      //Wait for the link to be up before starting mDNS responder
      if(context->running && interface->linkState)
      {
         //Valid host name?
         if(context->hostname[0] != '\0')
         {
            //Check whether a valid IPv4 or IPv6 address has been assigned
            if(context->ipv4AddrCount > 0 || context->ipv6AddrCount > 0)
            {
               mdnsResponderChangeState(context, MDNS_STATE_WAITING, 0);
            }
         }
      }
   }
   else if(context->state == MDNS_STATE_WAITING)
   {
      //Check current time
      if(timeCompare(time, context->timestamp + MDNS_INIT_DELAY) >= 0)
      {
         //Initial random delay
         delay = netGenerateRandRange(MDNS_RAND_DELAY_MIN, MDNS_RAND_DELAY_MAX);
         //Start probing
         mdnsResponderChangeState(context, MDNS_STATE_PROBING, delay);
      }
   }
   else if(context->state == MDNS_STATE_PROBING)
   {
      //Probing failed?
      if(context->conflict && context->retransmitCount > 0)
      {
         //Programmatically change the host name
         mdnsResponderChangeHostname(context);

         //Probe again, and repeat as necessary until a unique name is found
         mdnsResponderChangeState(context, MDNS_STATE_PROBING,
            MDNS_PROBE_CONFLICT_DELAY);
      }
      //Tie-break lost?
      else if(context->tieBreakLost && context->retransmitCount > 0)
      {
         //The host defers to the winning host by waiting one second, and
         //then begins probing for this record again
         mdnsResponderChangeState(context, MDNS_STATE_PROBING,
            MDNS_PROBE_DEFER_DELAY);
      }
      else
      {
         //Check current time
         if(timeCompare(time, context->timestamp + context->timeout) >= 0)
         {
            //Probing is on-going?
            if(context->retransmitCount < MDNS_PROBE_NUM)
            {
               //First probe?
               if(context->retransmitCount == 0)
               {
                  //Apparently conflicting mDNS responses received before the
                  //first probe packet is sent must be silently ignored
                  context->conflict = FALSE;
                  context->tieBreakLost = FALSE;
               }

               //Send probe packet
               mdnsResponderSendProbe(context);

               //Save the time at which the packet was sent
               context->timestamp = time;
               //Time interval between subsequent probe packets
               context->timeout = MDNS_PROBE_DELAY;
               //Increment retransmission counter
               context->retransmitCount++;
            }
            //Probing is complete?
            else
            {
               //The mDNS responder must send unsolicited mDNS responses
               //containing all of its newly registered resource records
               if(context->settings.numAnnouncements > 0)
               {
                  mdnsResponderChangeState(context, MDNS_STATE_ANNOUNCING, 0);
               }
               else
               {
                  mdnsResponderChangeState(context, MDNS_STATE_IDLE, 0);
               }
            }
         }
      }
   }
   else if(context->state == MDNS_STATE_ANNOUNCING)
   {
      //Whenever a mDNS responder receives any mDNS response (solicited or
      //otherwise) containing a conflicting resource record, the conflict
      //must be resolved
      if(context->conflict)
      {
         //Probe again, and repeat as necessary until a unique name is found
         mdnsResponderChangeState(context, MDNS_STATE_PROBING, 0);
      }
      else
      {
         //Check current time
         if(timeCompare(time, context->timestamp + context->timeout) >= 0)
         {
            //Send announcement packet
            mdnsResponderSendAnnouncement(context);

            //Save the time at which the packet was sent
            context->timestamp = time;
            //Increment retransmission counter
            context->retransmitCount++;

            //First announcement packet?
            if(context->retransmitCount == 1)
            {
               //The mDNS responder must send at least two unsolicited
               //responses, one second apart
               context->timeout = MDNS_ANNOUNCE_DELAY;
            }
            else
            {
               //To provide increased robustness against packet loss, a mDNS
               //responder may send up to eight unsolicited responses, provided
               //that the interval between unsolicited responses increases by
               //at least a factor of two with every response sent
               context->timeout *= 2;
            }

            //Last announcement packet?
            if(context->retransmitCount >= context->settings.numAnnouncements)
            {
               //A mDNS responder must not send regular periodic announcements
               mdnsResponderChangeState(context, MDNS_STATE_IDLE, 0);
            }
         }
      }
   }
   else if(context->state == MDNS_STATE_IDLE)
   {
      //Whenever a mDNS responder receives any mDNS response (solicited or
      //otherwise) containing a conflicting resource record, the conflict
      //must be resolved
      if(context->conflict)
      {
         //Probe again, and repeat as necessary until a unique name is found
         mdnsResponderChangeState(context, MDNS_STATE_PROBING, 0);
      }
   }

#if (IPV4_SUPPORT == ENABLED)
   //Any response message pending to be sent?
   if(context->ipv4Response.buffer != NULL)
   {
      //Check whether the time delay has elapsed
      if(timeCompare(time, context->ipv4Response.timestamp +
         context->ipv4Response.timeout) >= 0)
      {
#if (DNS_SD_SUPPORT == ENABLED)
         //Generate additional records (DNS-SD)
         dnsSdGenerateAdditionalRecords(interface,
            &context->ipv4Response, FALSE);
#endif
         //Generate additional records (mDNS)
         mdnsResponderGenerateAdditionalRecords(context,
            &context->ipv4Response, FALSE);

         //Use mDNS IPv4 multicast address
         destIpAddr.length = sizeof(Ipv4Addr);
         destIpAddr.ipv4Addr = MDNS_IPV4_MULTICAST_ADDR;

         //Send mDNS response message
         mdnsSendMessage(interface, &context->ipv4Response, &destIpAddr,
            MDNS_PORT);

         //Free previously allocated memory
         mdnsDeleteMessage(&context->ipv4Response);
      }
   }
#endif

#if (IPV6_SUPPORT == ENABLED)
   //Any response message pending to be sent?
   if(context->ipv6Response.buffer != NULL)
   {
      //Check whether the time delay has elapsed
      if(timeCompare(time, context->ipv6Response.timestamp +
         context->ipv6Response.timeout) >= 0)
      {
#if (DNS_SD_SUPPORT == ENABLED)
         //Generate additional records (DNS-SD)
         dnsSdGenerateAdditionalRecords(interface,
            &context->ipv6Response, FALSE);
#endif
         //Generate additional records (mDNS)
         mdnsResponderGenerateAdditionalRecords(context,
            &context->ipv6Response, FALSE);

         //Use mDNS IPv6 multicast address
         destIpAddr.length = sizeof(Ipv6Addr);
         destIpAddr.ipv6Addr = MDNS_IPV6_MULTICAST_ADDR;

         //Send mDNS response message
         mdnsSendMessage(interface, &context->ipv6Response, &destIpAddr,
            MDNS_PORT);

         //Free previously allocated memory
         mdnsDeleteMessage(&context->ipv6Response);
      }
   }
#endif
}


/**
 * @brief Callback function for link change event
 * @param[in] context Pointer to the mDNS responder context
 **/

void mdnsResponderLinkChangeEvent(MdnsResponderContext *context)
{
   //Make sure the mDNS responder has been properly instantiated
   if(context == NULL)
      return;

#if (IPV4_SUPPORT == ENABLED)
   //Free any response message pending to be sent
   mdnsDeleteMessage(&context->ipv4Response);
#endif

#if (IPV6_SUPPORT == ENABLED)
   //Free any response message pending to be sent
   mdnsDeleteMessage(&context->ipv6Response);
#endif

   //Whenever a mDNS responder receives an indication of a link
   //change event, it must perform probing and announcing
   mdnsResponderChangeState(context, MDNS_STATE_INIT, 0);
}

#endif

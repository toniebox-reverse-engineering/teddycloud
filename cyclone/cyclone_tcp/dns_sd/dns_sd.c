/**
 * @file dns_sd.c
 * @brief DNS-SD (DNS-Based Service Discovery)
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
 * DNS-SD allows clients to discover a list of named instances of that
 * desired service, using standard DNS queries. Refer to the following
 * RFCs for complete details:
 * - RFC 6763: DNS-Based Service Discovery
 * - RFC 2782: A DNS RR for specifying the location of services (DNS SRV)
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL DNS_SD_TRACE_LEVEL

//Dependencies
#include <stdlib.h>
#include "core/net.h"
#include "mdns/mdns_responder.h"
#include "dns_sd/dns_sd.h"
#include "dns_sd/dns_sd_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (DNS_SD_SUPPORT == ENABLED)

//Tick counter to handle periodic operations
systime_t dnsSdTickCounter;


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains DNS-SD settings
 **/

void dnsSdGetDefaultSettings(DnsSdSettings *settings)
{
   //Use default interface
   settings->interface = netGetDefaultInterface();

   //Number of announcement packets
   settings->numAnnouncements = MDNS_ANNOUNCE_NUM;
   //TTL resource record
   settings->ttl = DNS_SD_DEFAULT_RR_TTL;
   //FSM state change event
   settings->stateChangeEvent = NULL;
}


/**
 * @brief DNS-DS initialization
 * @param[in] context Pointer to the DNS-SD context
 * @param[in] settings DNS-SD specific settings
 * @return Error code
 **/

error_t dnsSdInit(DnsSdContext *context, const DnsSdSettings *settings)
{
   NetInterface *interface;

   //Debug message
   TRACE_INFO("Initializing DNS-SD...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid network interface?
   if(settings->interface == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the underlying network interface
   interface = settings->interface;

   //Clear the DNS-SD context
   osMemset(context, 0, sizeof(DnsSdContext));
   //Save user settings
   context->settings = *settings;

   //DNS-SD is currently suspended
   context->running = FALSE;
   //Initialize state machine
   context->state = MDNS_STATE_INIT;

   //Attach the DNS-SD context to the network interface
   interface->dnsSdContext = context;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start mDNS responder
 * @param[in] context Pointer to the DNS-SD context
 * @return Error code
 **/

error_t dnsSdStart(DnsSdContext *context)
{
   //Make sure the DNS-SD context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting DNS-SD...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Start DNS-SD
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
 * @param[in] context Pointer to the DNS-SD context
 * @return Error code
 **/

error_t dnsSdStop(DnsSdContext *context)
{
   //Make sure the DNS-SD context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping DNS-SD...\r\n");

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Suspend DNS-SD
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
 * @param[in] context Pointer to the DNS-SD context
 * @return Current DNS-SD state
 **/

MdnsState dnsSdGetState(DnsSdContext *context)
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
 * @brief Set service instance name
 * @param[in] context Pointer to the DNS-SD context
 * @param[in] instanceName NULL-terminated string that contains the service
 *   instance name
 * @return Error code
 **/

error_t dnsSdSetInstanceName(DnsSdContext *context, const char_t *instanceName)
{
   NetInterface *interface;

   //Check parameters
   if(context == NULL || instanceName == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the instance name is acceptable
   if(osStrlen(instanceName) > DNS_SD_MAX_INSTANCE_NAME_LEN)
      return ERROR_INVALID_LENGTH;

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Any registered services?
   if(dnsSdGetNumServices(context) > 0)
   {
      //Check whether the link is up
      if(interface->linkState)
      {
         //Send a goodbye packet
         dnsSdSendGoodbye(context, NULL);
      }
   }

   //Set instance name
   osStrcpy(context->instanceName, instanceName);

   //Restart probing process
   dnsSdStartProbing(context);

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register a DNS-SD service
 * @param[in] context Pointer to the DNS-SD context
 * @param[in] serviceName NULL-terminated string that contains the name of the
 *   service to be registered
 * @param[in] priority Priority field
 * @param[in] weight Weight field
 * @param[in] port Port number
 * @param[in] metadata NULL-terminated string that contains the discovery-time
 *   metadata (TXT record)
 * @return Error code
 **/

error_t dnsSdRegisterService(DnsSdContext *context, const char_t *serviceName,
   uint16_t priority, uint16_t weight, uint16_t port, const char_t *metadata)
{
   error_t error;
   size_t i;
   size_t j;
   size_t k;
   size_t n;
   DnsSdService *entry;
   DnsSdService *firstFreeEntry;

   //Check parameters
   if(context == NULL || serviceName == NULL || metadata == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the service name is acceptable
   if(osStrlen(serviceName) > DNS_SD_MAX_SERVICE_NAME_LEN)
      return ERROR_INVALID_LENGTH;

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Keep track of the first free entry
   firstFreeEntry = NULL;

   //Loop through the list of registered services
   for(i = 0; i < DNS_SD_SERVICE_LIST_SIZE; i++)
   {
      //Point to the current entry
      entry = &context->serviceList[i];

      //Check if the entry is currently in use
      if(entry->name[0] != '\0')
      {
         //Check whether the specified service is already registered
         if(!osStrcasecmp(entry->name, serviceName))
            break;
      }
      else
      {
         //Keep track of the first free entry
         if(firstFreeEntry == NULL)
         {
            firstFreeEntry = entry;
         }
      }
   }

   //If the specified service is not yet registered, then a new
   //entry should be created
   if(i >= DNS_SD_SERVICE_LIST_SIZE)
      entry = firstFreeEntry;

   //Check whether the service list runs out of space
   if(entry != NULL)
   {
      //Service name
      osStrcpy(entry->name, serviceName);

      //Priority field
      entry->priority = priority;
      //Weight field
      entry->weight = weight;
      //Port number
      entry->port = port;

      //Clear TXT record
      entry->metadataLength = 0;

      //Point to the beginning of the information string
      i = 0;
      j = 0;

      //Point to the beginning of the resulting TXT record data
      k = 0;

      //Format TXT record
      while(1)
      {
         //End of text data?
         if(metadata[i] == '\0' || metadata[i] == ';')
         {
            //Calculate the length of the text data
            n = MIN(i - j, UINT8_MAX);

            //Check the length of the resulting TXT record
            if((entry->metadataLength + n + 1) > DNS_SD_MAX_METADATA_LEN)
               break;

            //Write length field
            entry->metadata[k] = n;
            //Write text data
            osMemcpy(entry->metadata + k + 1, metadata + j, n);

            //Jump to the next text data
            j = i + 1;
            //Advance write index
            k += n + 1;

            //Update the length of the TXT record
            entry->metadataLength += n + 1;

            //End of string detected?
            if(metadata[i] == '\0')
               break;
         }

         //Advance read index
         i++;
      }

      //Empty TXT record?
      if(!entry->metadataLength)
      {
         //An empty TXT record shall contain a single zero byte
         entry->metadata[0] = 0;
         entry->metadataLength = 1;
      }

      //Restart probing process
      dnsSdStartProbing(context);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //The service list is full
      error = ERROR_FAILURE;
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Return error code
   return error;
}


/**
 * @brief Unregister a DNS-SD service
 * @param[in] context Pointer to the DNS-SD context
 * @param[in] serviceName NULL-terminated string that contains the name of the
 *   service to be unregistered
 * @return Error code
 **/

error_t dnsSdUnregisterService(DnsSdContext *context, const char_t *serviceName)
{
   uint_t i;
   DnsSdService *entry;

   //Check parameters
   if(context == NULL || serviceName == NULL)
      return ERROR_INVALID_PARAMETER;

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Loop through the list of registered services
   for(i = 0; i < DNS_SD_SERVICE_LIST_SIZE; i++)
   {
      //Point to the current entry
      entry = &context->serviceList[i];

      //Service name found?
      if(!osStrcasecmp(entry->name, serviceName))
      {
         //Send a goodbye packet
         dnsSdSendGoodbye(context, entry);
         //Remove the service from the list
         entry->name[0] = '\0';
      }
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the number of registered services
 * @param[in] context Pointer to the DNS-SD context
 * @return Number of registered services
 **/

uint_t dnsSdGetNumServices(DnsSdContext *context)
{
   uint_t i;
   uint_t n;

   //Number of registered services
   n = 0;

   //Check parameter
   if(context != NULL)
   {
      //Valid instance name?
      if(context->instanceName[0] != '\0')
      {
         //Loop through the list of registered services
         for(i = 0; i < DNS_SD_SERVICE_LIST_SIZE; i++)
         {
            //Check if the entry is currently in use
            if(context->serviceList[i].name[0] != '\0')
               n++;
         }
      }
   }

   //Return the number of registered services
   return n;
}


/**
 * @brief Restart probing process
 * @param[in] context Pointer to the DNS-SD context
 * @return Error code
 **/

error_t dnsSdStartProbing(DnsSdContext *context)
{
   //Check parameter
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Force DNS-SD to start probing again
   context->state = MDNS_STATE_INIT;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief DNS-SD responder timer handler
 *
 * This routine must be periodically called by the TCP/IP stack to
 * manage DNS-SD operation
 *
 * @param[in] context Pointer to the DNS-SD context
 **/

void dnsSdTick(DnsSdContext *context)
{
   systime_t time;
   systime_t delay;
   NetInterface *interface;

   //Make sure DNS-SD has been properly instantiated
   if(context == NULL)
      return;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Get current time
   time = osGetSystemTime();

   //Check current state
   if(context->state == MDNS_STATE_INIT)
   {
      //Ensure the mDNS and DNS-SD services are running
      if(context->running && interface->mdnsResponderContext != NULL)
      {
         //Wait for mDNS probing to complete
         if(interface->mdnsResponderContext->state == MDNS_STATE_IDLE)
         {
            //Any registered services?
            if(dnsSdGetNumServices(context) > 0)
            {
               //Initial random delay
               delay = netGenerateRandRange(MDNS_RAND_DELAY_MIN,
                  MDNS_RAND_DELAY_MAX);

               //Perform probing
               dnsSdChangeState(context, MDNS_STATE_PROBING, delay);
            }
         }
      }
   }
   else if(context->state == MDNS_STATE_PROBING)
   {
      //Probing failed?
      if(context->conflict && context->retransmitCount > 0)
      {
         //Programmatically change the service instance name
         dnsSdChangeInstanceName(context);
         //Probe again, and repeat as necessary until a unique name is found
         dnsSdChangeState(context, MDNS_STATE_PROBING, MDNS_PROBE_CONFLICT_DELAY);
      }
      //Tie-break lost?
      else if(context->tieBreakLost && context->retransmitCount > 0)
      {
         //The host defers to the winning host by waiting one second, and
         //then begins probing for this record again
         dnsSdChangeState(context, MDNS_STATE_PROBING, MDNS_PROBE_DEFER_DELAY);
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
               dnsSdSendProbe(context);

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
                  dnsSdChangeState(context, MDNS_STATE_ANNOUNCING, 0);
               }
               else
               {
                  dnsSdChangeState(context, MDNS_STATE_IDLE, 0);
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
         dnsSdChangeState(context, MDNS_STATE_PROBING, 0);
      }
      else
      {
         //Check current time
         if(timeCompare(time, context->timestamp + context->timeout) >= 0)
         {
            //Send announcement packet
            dnsSdSendAnnouncement(context);

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
               dnsSdChangeState(context, MDNS_STATE_IDLE, 0);
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
         dnsSdChangeState(context, MDNS_STATE_PROBING, 0);
      }
   }
}


/**
 * @brief Callback function for link change event
 * @param[in] context Pointer to the DNS-SD context
 **/

void dnsSdLinkChangeEvent(DnsSdContext *context)
{
   //Make sure DNS-SD has been properly instantiated
   if(context == NULL)
      return;

   //Whenever a mDNS responder receives an indication of a link
   //change event, it must perform probing and announcing
   dnsSdChangeState(context, MDNS_STATE_INIT, 0);
}

#endif

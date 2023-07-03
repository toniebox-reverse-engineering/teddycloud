/**
 * @file dns_sd_misc.c
 * @brief Helper functions for DNS-SD
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


/**
 * @brief Update FSM state
 * @param[in] context Pointer to the DNS-SD context
 * @param[in] newState New state to switch to
 * @param[in] delay Initial delay
 **/

void dnsSdChangeState(DnsSdContext *context, MdnsState newState,
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
 * @brief Programmatically change the service instance name
 * @param[in] context Pointer to the DNS-SD context
 **/

void dnsSdChangeInstanceName(DnsSdContext *context)
{
   size_t i;
   size_t m;
   size_t n;
   uint32_t index;
   char_t s[16];

   //Retrieve the length of the string
   n = osStrlen(context->instanceName);

   //Parse the string backwards
   for(i = n; i > 0; i--)
   {
      //Last character?
      if(i == n)
      {
         //Check whether the last character is a bracket
         if(context->instanceName[i - 1] != ')')
            break;
      }
      else
      {
         //Check whether the current character is a digit
         if(!osIsdigit(context->instanceName[i - 1]))
            break;
      }
   }

   //Any number following the service instance name?
   if(context->instanceName[i] != '\0')
   {
      //Retrieve the number at the end of the name
      index = atoi(context->instanceName + i);
      //Increment the value
      index++;

      //Check the length of the name
      if(i >= 2)
      {
         //Discard any space and bracket that may precede the number
         if(context->instanceName[i - 2] == ' ' &&
            context->instanceName[i - 1] == '(')
         {
            i -= 2;
         }
      }

      //Strip the digits
      context->instanceName[i] = '\0';
   }
   else
   {
      //Append the digit "2" to the name
      index = 2;
   }

   //Convert the number to a string of characters
   m = osSprintf(s, " (%" PRIu32 ")", index);

   //Sanity check
   if((i + m) <= DNS_SD_MAX_INSTANCE_NAME_LEN)
   {
      //Programmatically change the service instance name
      osStrcat(context->instanceName, s);
   }
}


/**
 * @brief Send probe packet
 * @param[in] context Pointer to the DNS-SD context
 * @return Error code
 **/

error_t dnsSdSendProbe(DnsSdContext *context)
{
   error_t error;
   uint_t i;
   NetInterface *interface;
   DnsQuestion *dnsQuestion;
   DnsSdService *service;
   MdnsMessage message;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Create an empty mDNS query message
   error = mdnsCreateMessage(&message, FALSE);
   //Any error to report?
   if(error)
      return error;

   //Start of exception handling block
   do
   {
      //For all those resource records that a mDNS responder desires to be
      //unique on the local link, it must send a mDNS query asking for those
      //resource records, to see if any of them are already in use
      if(dnsSdGetNumServices(context) > 0)
      {
         //Loop through the list of registered services
         for(i = 0; i < DNS_SD_SERVICE_LIST_SIZE; i++)
         {
            //Point to the current entry
            service = &context->serviceList[i];

            //Valid service?
            if(service->name[0] != '\0')
            {
               //Encode the service name using DNS notation
               message.length += mdnsEncodeName(context->instanceName, service->name,
                  ".local", (uint8_t *) message.dnsHeader + message.length);

               //Point to the corresponding question structure
               dnsQuestion = DNS_GET_QUESTION(message.dnsHeader, message.length);

               //The probes should be sent as QU questions with the unicast-response
               //bit set, to allow a defending host to respond immediately via unicast
               dnsQuestion->qtype = HTONS(DNS_RR_TYPE_ANY);
               dnsQuestion->qclass = HTONS(MDNS_QCLASS_QU | DNS_RR_CLASS_IN);

               //Update the length of the mDNS query message
               message.length += sizeof(DnsQuestion);

               //Number of questions in the Question Section
               message.dnsHeader->qdcount++;
            }
         }
      }

      //A probe query can be distinguished from a normal query by the fact that
      //a probe query contains a proposed record in the Authority Section that
      //answers the question in the Question Section
      if(dnsSdGetNumServices(context) > 0)
      {
         //Loop through the list of registered services
         for(i = 0; i < DNS_SD_SERVICE_LIST_SIZE; i++)
         {
            //Point to the current entry
            service = &context->serviceList[i];

            //Valid service?
            if(service->name[0] != '\0')
            {
               //Format SRV resource record
               error = dnsSdFormatSrvRecord(interface, &message,
                  service, FALSE, DNS_SD_DEFAULT_RR_TTL);
               //Any error to report?
               if(error)
                  break;

               //Format TXT resource record
               error = dnsSdFormatTxtRecord(interface, &message,
                  service, FALSE, DNS_SD_DEFAULT_RR_TTL);
               //Any error to report?
               if(error)
                  break;
            }
         }
      }

      //Propagate exception if necessary
      if(error)
         break;

      //Number of resource records in the Authority Section
      message.dnsHeader->nscount = message.dnsHeader->ancount;
      //Number of resource records in the Answer Section
      message.dnsHeader->ancount = 0;

      //Send mDNS message
      error = mdnsSendMessage(interface, &message, NULL, MDNS_PORT);

      //End of exception handling block
   } while(0);

   //Free previously allocated memory
   mdnsDeleteMessage(&message);

   //Return status code
   return error;
}


/**
 * @brief Send announcement packet
 * @param[in] context Pointer to the DNS-SD context
 * @return Error code
 **/

error_t dnsSdSendAnnouncement(DnsSdContext *context)
{
   error_t error;
   uint_t i;
   NetInterface *interface;
   DnsSdService *service;
   MdnsMessage message;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Create an empty mDNS response message
   error = mdnsCreateMessage(&message, TRUE);
   //Any error to report?
   if(error)
      return error;

   //Start of exception handling block
   do
   {
      //Send an unsolicited mDNS response containing, in the Answer Section,
      //all of its newly registered resource records
      if(dnsSdGetNumServices(context) > 0)
      {
         //Loop through the list of registered services
         for(i = 0; i < DNS_SD_SERVICE_LIST_SIZE; i++)
         {
            //Point to the current entry
            service = &context->serviceList[i];

            //Valid service?
            if(service->name[0] != '\0')
            {
               //Format PTR resource record (service type enumeration)
               error = dnsSdFormatServiceEnumPtrRecord(interface,
                  &message, service, DNS_SD_DEFAULT_RR_TTL);
               //Any error to report?
               if(error)
                  break;

               //Format PTR resource record
               error = dnsSdFormatPtrRecord(interface, &message,
                  service, DNS_SD_DEFAULT_RR_TTL);
               //Any error to report?
               if(error)
                  break;

               //Format SRV resource record
               error = dnsSdFormatSrvRecord(interface, &message,
                  service, TRUE, DNS_SD_DEFAULT_RR_TTL);
               //Any error to report?
               if(error)
                  break;

               //Format TXT resource record
               error = dnsSdFormatTxtRecord(interface, &message,
                  service, TRUE, DNS_SD_DEFAULT_RR_TTL);
               //Any error to report?
               if(error)
                  break;
            }
         }
      }

      //Propagate exception if necessary
      if(error)
         break;

      //Send mDNS message
      error = mdnsSendMessage(interface, &message, NULL, MDNS_PORT);

      //End of exception handling block
   } while(0);

   //Free previously allocated memory
   mdnsDeleteMessage(&message);

   //Return status code
   return error;
}


/**
 * @brief Send goodbye packet
 * @param[in] context Pointer to the DNS-SD context
 * @param[in] service Pointer to a DNS-SD service
 * @return Error code
 **/

error_t dnsSdSendGoodbye(DnsSdContext *context, const DnsSdService *service)
{
   error_t error;
   uint_t i;
   NetInterface *interface;
   DnsSdService *entry;
   MdnsMessage message;

   //Point to the underlying network interface
   interface = context->settings.interface;

   //Create an empty mDNS response message
   error = mdnsCreateMessage(&message, TRUE);
   //Any error to report?
   if(error)
      return error;

   //Loop through the list of registered services
   for(i = 0; i < DNS_SD_SERVICE_LIST_SIZE; i++)
   {
      //Point to the current entry
      entry = &context->serviceList[i];

      //Valid service?
      if(entry->name[0] != '\0')
      {
         if(service == entry || service == NULL)
         {
            //Format PTR resource record (service type enumeration)
            error = dnsSdFormatServiceEnumPtrRecord(interface, &message, entry, 0);
            //Any error to report?
            if(error)
               break;

            //Format PTR resource record
            error = dnsSdFormatPtrRecord(interface, &message, entry, 0);
            //Any error to report?
            if(error)
               break;

            //Format SRV resource record
            error = dnsSdFormatSrvRecord(interface, &message, entry, TRUE, 0);
            //Any error to report?
            if(error)
               break;

            //Format TXT resource record
            error = dnsSdFormatTxtRecord(interface, &message, entry, TRUE, 0);
            //Any error to report?
            if(error)
               break;
         }
      }
   }

   //Check status code
   if(!error)
   {
      //Send mDNS message
      error = mdnsSendMessage(interface, &message, NULL, MDNS_PORT);
   }

   //Free previously allocated memory
   mdnsDeleteMessage(&message);

   //Return status code
   return error;
}


/**
 * @brief Parse a question
 * @param[in] interface Underlying network interface
 * @param[in] query Incoming mDNS query message
 * @param[in] offset Offset to first byte of the question
 * @param[in] question Pointer to the question
 * @param[in,out] response mDNS response message
 * @return Error code
 **/

error_t dnsSdParseQuestion(NetInterface *interface, const MdnsMessage *query,
   size_t offset, const DnsQuestion *question, MdnsMessage *response)
{
   error_t error;
   uint_t i;
   uint16_t qclass;
   uint16_t qtype;
   uint32_t ttl;
   bool_t cacheFlush;
   DnsSdContext *context;
   DnsSdService *service;

   //Point to the DNS-SD context
   context = interface->dnsSdContext;
   //Make sure DNS-SD has been properly instantiated
   if(context == NULL)
      return NO_ERROR;

   //Check the state of the mDNS responder
   if(context->state != MDNS_STATE_ANNOUNCING &&
      context->state != MDNS_STATE_IDLE)
   {
      //Do not respond to mDNS queries during probing
      return NO_ERROR;
   }

   //Convert the query class to host byte order
   qclass = ntohs(question->qclass);
   //Discard QU flag
   qclass &= ~MDNS_QCLASS_QU;

   //Convert the query type to host byte order
   qtype = ntohs(question->qtype);

   //Get the TTL resource record
   ttl = context->settings.ttl;

   //Check whether the querier originating the query is a simple resolver
   if(ntohs(query->udpHeader->srcPort) != MDNS_PORT)
   {
      //The resource record TTL given in a legacy unicast response should
      //not be greater than ten seconds, even if the true TTL of the mDNS
      //resource record is higher
      ttl = MIN(ttl, MDNS_LEGACY_UNICAST_RR_TTL);

      //The cache-flush bit must not be set in legacy unicast responses
      cacheFlush = FALSE;
   }
   else
   {
      //The cache-bit should be set for unique resource records
      cacheFlush = TRUE;
   }

   //Any registered services?
   if(dnsSdGetNumServices(context) > 0)
   {
      //Loop through the list of registered services
      for(i = 0; i < DNS_SD_SERVICE_LIST_SIZE; i++)
      {
         //Point to the current entry
         service = &context->serviceList[i];

         //Valid service?
         if(service->name[0] != '\0')
         {
            //Check the class of the query
            if(qclass == DNS_RR_CLASS_IN || qclass == DNS_RR_CLASS_ANY)
            {
               //Compare service name
               if(!mdnsCompareName(query->dnsHeader, query->length,
                  offset, "", "_services._dns-sd._udp", ".local", 0))
               {
                  //PTR query?
                  if(qtype == DNS_RR_TYPE_PTR || qtype == DNS_RR_TYPE_ANY)
                  {
                     //Format PTR resource record (service type enumeration)
                     error = dnsSdFormatServiceEnumPtrRecord(interface,
                        response, service, ttl);
                     //Any error to report?
                     if(error)
                        return error;

                     //Update the number of shared resource records
                     response->sharedRecordCount++;
                  }
               }
               else if(!mdnsCompareName(query->dnsHeader, query->length,
                  offset, "", service->name, ".local", 0))
               {
                  //PTR query?
                  if(qtype == DNS_RR_TYPE_PTR || qtype == DNS_RR_TYPE_ANY)
                  {
                     //Format PTR resource record
                     error = dnsSdFormatPtrRecord(interface, response,
                        service, ttl);
                     //Any error to report?
                     if(error)
                        return error;

                     //Update the number of shared resource records
                     response->sharedRecordCount++;
                  }
               }
               else if(!mdnsCompareName(query->dnsHeader, query->length, offset,
                  context->instanceName, service->name, ".local", 0))
               {
                  //SRV query?
                  if(qtype == DNS_RR_TYPE_SRV || qtype == DNS_RR_TYPE_ANY)
                  {
                     //Format SRV resource record
                     error = dnsSdFormatSrvRecord(interface, response,
                        service, cacheFlush, ttl);
                     //Any error to report?
                     if(error)
                        return error;
                  }

                  //TXT query?
                  if(qtype == DNS_RR_TYPE_TXT || qtype == DNS_RR_TYPE_ANY)
                  {
                     //Format TXT resource record
                     error = dnsSdFormatTxtRecord(interface, response,
                        service, cacheFlush, ttl);
                     //Any error to report?
                     if(error)
                        return error;
                  }

                  //NSEC query?
                  if(qtype != DNS_RR_TYPE_SRV && qtype != DNS_RR_TYPE_TXT)
                  {
                     //Format NSEC resource record
                     error = dnsSdFormatNsecRecord(interface, response,
                        service, cacheFlush, ttl);
                     //Any error to report?
                     if(error)
                        return error;
                  }
               }
            }
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}



/**
 * @brief Parse a resource record from the Authority Section
 * @param[in] interface Underlying network interface
 * @param[in] query Incoming mDNS query message
 * @param[in] offset Offset to first byte of the resource record
 * @param[in] record Pointer to the resource record
 **/

void dnsSdParseNsRecord(NetInterface *interface, const MdnsMessage *query,
   size_t offset, const DnsResourceRecord *record)
{
   uint_t i;
   uint16_t rclass;
   DnsSdContext *context;
   DnsSdService *service;
   DnsSrvResourceRecord *srvRecord;

   //Point to the DNS-SD context
   context = interface->dnsSdContext;
   //Make sure DNS-SD has been properly instantiated
   if(context == NULL)
      return;

   //Any services registered?
   if(dnsSdGetNumServices(context) > 0)
   {
      //Loop through the list of registered services
      for(i = 0; i < DNS_SD_SERVICE_LIST_SIZE; i++)
      {
         //Point to the current entry
         service = &context->serviceList[i];

         //Valid service?
         if(service->name[0] != '\0')
         {
            //Apply tie-breaking rules
            if(!mdnsCompareName(query->dnsHeader, query->length, offset,
               context->instanceName, service->name, ".local", 0))
            {
               //Convert the class to host byte order
               rclass = ntohs(record->rclass);
               //Discard Cache Flush flag
               rclass &= ~MDNS_RCLASS_CACHE_FLUSH;

               //Check the class of the resource record
               if(rclass == DNS_RR_CLASS_IN)
               {
                  //SRV resource record found?
                  if(ntohs(record->rtype) == DNS_RR_TYPE_SRV)
                  {
                     //Cast resource record
                     srvRecord = (DnsSrvResourceRecord *) record;

                     //Compare Priority fields
                     if(ntohs(srvRecord->priority) > service->priority)
                     {
                        context->tieBreakLost = TRUE;
                     }
                     else if(ntohs(srvRecord->priority) == service->priority)
                     {
                        //Compare Weight fields
                        if(ntohs(srvRecord->weight) > service->weight)
                        {
                           context->tieBreakLost = TRUE;
                        }
                        else if(ntohs(srvRecord->weight) == service->weight)
                        {
                           //Compare Port fields
                           if(ntohs(srvRecord->port) > service->port)
                           {
                              context->tieBreakLost = TRUE;
                           }
                           else if(ntohs(srvRecord->port) == service->port)
                           {
                              //Compute the offset of the first byte of the target
                              offset = srvRecord->target - (uint8_t *) query->dnsHeader;

                              if(mdnsCompareName(query->dnsHeader, query->length, offset,
                                 context->instanceName, "", ".local", 0) > 0)
                              {
                                 //The host has lost the tie-break
                                 context->tieBreakLost = TRUE;
                              }
                           }
                        }
                     }
                  }
               }
            }
         }
      }
   }
}


/**
 * @brief Parse a resource record from the Answer Section
 * @param[in] interface Underlying network interface
 * @param[in] response Incoming mDNS response message
 * @param[in] offset Offset to first byte of the resource record to be checked
 * @param[in] record Pointer to the resource record
 **/

void dnsSdParseAnRecord(NetInterface *interface, const MdnsMessage *response,
   size_t offset, const DnsResourceRecord *record)
{
   uint_t i;
   uint16_t rclass;
   DnsSdContext *context;
   DnsSdService *service;

   //Point to the DNS-SD context
   context = interface->dnsSdContext;
   //Make sure DNS-SD has been properly instantiated
   if(context == NULL)
      return;

   //Any services registered?
   if(dnsSdGetNumServices(context) > 0)
   {
      //Loop through the list of registered services
      for(i = 0; i < DNS_SD_SERVICE_LIST_SIZE; i++)
      {
         //Point to the current entry
         service = &context->serviceList[i];

         //Valid service?
         if(service->name[0] != '\0')
         {
            //Check for conflicts
            if(!mdnsCompareName(response->dnsHeader, response->length, offset,
               context->instanceName, service->name, ".local", 0))
            {
               //Convert the class to host byte order
               rclass = ntohs(record->rclass);
               //Discard Cache Flush flag
               rclass &= ~MDNS_RCLASS_CACHE_FLUSH;

               //Check the class of the resource record
               if(rclass == DNS_RR_CLASS_IN)
               {
                  //SRV resource record found?
                  if(ntohs(record->rtype) == DNS_RR_TYPE_SRV)
                  {
                     //Compute the offset of the first byte of the rdata
                     offset = record->rdata - (uint8_t *) response->dnsHeader;

                     //A conflict occurs when a mDNS responder has a unique record for
                     //which it is currently authoritative, and it receives a mDNS
                     //response message containing a record with the same name, rrtype
                     //and rrclass, but inconsistent rdata
                     if(mdnsCompareName(response->dnsHeader, response->length, offset,
                        context->instanceName, "", ".local", 0))
                     {
                        //The service instance name is already in use by some other host
                        context->conflict = TRUE;
                     }
                  }
               }
            }
         }
      }
   }
}


/**
 * @brief Additional record generation
 * @param[in] interface Underlying network interface
 * @param[in,out] response mDNS response message
 * @param[in] legacyUnicast This flag is set for legacy unicast responses
 **/

void dnsSdGenerateAdditionalRecords(NetInterface *interface,
   MdnsMessage *response, bool_t legacyUnicast)
{
   error_t error;
   uint_t i;
   uint_t j;
   size_t n;
   size_t offset;
   uint_t ancount;
   uint16_t rclass;
   uint32_t ttl;
   bool_t cacheFlush;
   DnsSdContext *context;
   DnsSdService *service;
   DnsResourceRecord *record;

   //Point to the DNS-SD context
   context = interface->dnsSdContext;
   //Make sure DNS-SD has been properly instantiated
   if(context == NULL)
      return;

   //No registered services?
   if(dnsSdGetNumServices(context) == 0)
      return;

   //mDNS responses must not contain any questions in the Question Section
   if(response->dnsHeader->qdcount != 0)
      return;

   //Get the TTL resource record
   ttl = context->settings.ttl;

   //Check whether the querier originating the query is a simple resolver
   if(legacyUnicast)
   {
      //The resource record TTL given in a legacy unicast response should
      //not be greater than ten seconds, even if the true TTL of the mDNS
      //resource record is higher
      ttl = MIN(ttl, MDNS_LEGACY_UNICAST_RR_TTL);

      //The cache-flush bit must not be set in legacy unicast responses
      cacheFlush = FALSE;
   }
   else
   {
      //The cache-bit should be set for unique resource records
      cacheFlush = TRUE;
   }

   //Point to the first resource record
   offset = sizeof(DnsHeader);

   //Save the number of resource records in the Answer Section
   ancount = response->dnsHeader->ancount;

   //Parse the Answer Section
   for(i = 0; i < ancount; i++)
   {
      //Parse resource record name
      n = dnsParseName(response->dnsHeader, response->length, offset, NULL, 0);
      //Invalid name?
      if(!n)
         break;

      //Point to the associated resource record
      record = DNS_GET_RESOURCE_RECORD(response->dnsHeader, n);
      //Point to the resource data
      n += sizeof(DnsResourceRecord);

      //Make sure the resource record is valid
      if(n > response->length)
         break;
      if((n + ntohs(record->rdlength)) > response->length)
         break;

      //Convert the record class to host byte order
      rclass = ntohs(record->rclass);
      //Discard the cache-flush bit
      rclass &= ~MDNS_RCLASS_CACHE_FLUSH;

      //Loop through the list of registered services
      for(j = 0; j < DNS_SD_SERVICE_LIST_SIZE; j++)
      {
         //Point to the current entry
         service = &context->serviceList[j];

         //Valid service?
         if(service->name[0] != '\0')
         {
            //Check the class of the resource record
            if(rclass == DNS_RR_CLASS_IN)
            {
               //PTR record?
               if(ntohs(record->rtype) == DNS_RR_TYPE_PTR)
               {
                  //Compare service name
                  if(!mdnsCompareName(response->dnsHeader, response->length,
                     offset, "", service->name, ".local", 0))
                  {
                     //Format SRV resource record
                     error = dnsSdFormatSrvRecord(interface,
                        response, service, cacheFlush, ttl);
                     //Any error to report?
                     if(error)
                        return;

                     //Format TXT resource record
                     error = dnsSdFormatTxtRecord(interface,
                        response, service, cacheFlush, ttl);
                     //Any error to report?
                     if(error)
                        return;
                  }
               }
               //SRV record?
               else if(ntohs(record->rtype) == DNS_RR_TYPE_SRV)
               {
                  //Compare service name
                  if(!mdnsCompareName(response->dnsHeader, response->length,
                     offset, context->instanceName, service->name, ".local", 0))
                  {
                     //Format TXT resource record
                     error = dnsSdFormatTxtRecord(interface,
                        response, service, cacheFlush, ttl);
                     //Any error to report?
                     if(error)
                        return;
                  }
               }
            }
         }
      }

      //Point to the next resource record
      offset = n + ntohs(record->rdlength);
   }

   //Number of resource records in the Additional Section
   response->dnsHeader->arcount += response->dnsHeader->ancount - ancount;
   //Number of resource records in the Answer Section
   response->dnsHeader->ancount = ancount;
}


/**
 * @brief Format PTR resource record (in response to a meta-query)
 * @param[in] interface Underlying network interface
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] service Pointer to a DNS-SD service
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t dnsSdFormatServiceEnumPtrRecord(NetInterface *interface,
   MdnsMessage *message, const DnsSdService *service, uint32_t ttl)
{
   size_t n;
   size_t offset;
   DnsResourceRecord *record;

   //Set the position to the end of the buffer
   offset = message->length;

   //The first pass calculates the length of the DNS encoded service name
   n = mdnsEncodeName("", "_services._dns-sd._udp", ".local", NULL);

   //Check the length of the resulting mDNS message
   if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
      return ERROR_MESSAGE_TOO_LONG;

   //The second pass encodes the service name using the DNS name notation
   offset += mdnsEncodeName("", "_services._dns-sd._udp",
      ".local", (uint8_t *) message->dnsHeader + offset);

   //Consider the length of the resource record itself
   if((offset + sizeof(DnsResourceRecord)) > MDNS_MESSAGE_MAX_SIZE)
      return ERROR_MESSAGE_TOO_LONG;

   //Point to the corresponding resource record
   record = DNS_GET_RESOURCE_RECORD(message->dnsHeader, offset);

   //Fill in resource record
   record->rtype = HTONS(DNS_RR_TYPE_PTR);
   record->rclass = HTONS(DNS_RR_CLASS_IN);
   record->ttl = htonl(ttl);

   //Advance write index
   offset += sizeof(DnsResourceRecord);

   //The first pass calculates the length of the DNS encoded service name
   n = mdnsEncodeName("", service->name, ".local", NULL);

   //Check the length of the resulting mDNS message
   if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
      return ERROR_MESSAGE_TOO_LONG;

   //The second pass encodes the service name using DNS notation
   n = mdnsEncodeName("", service->name,
      ".local", record->rdata);

   //Convert length field to network byte order
   record->rdlength = htons(n);

   //Number of resource records in the answer section
   message->dnsHeader->ancount++;
   //Update the length of the DNS message
   message->length = offset + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format PTR resource record
 * @param[in] interface Underlying network interface
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] service Pointer to a DNS-SD service
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t dnsSdFormatPtrRecord(NetInterface *interface,
   MdnsMessage *message, const DnsSdService *service, uint32_t ttl)
{
   size_t n;
   size_t offset;
   bool_t duplicate;
   DnsSdContext *context;
   DnsResourceRecord *record;

   //Point to the DNS-SD context
   context = interface->dnsSdContext;

   //Check whether the resource record is already present in the Answer
   //Section of the message
   duplicate = mdnsCheckDuplicateRecord(message, "",
      service->name, ".local", DNS_RR_TYPE_PTR, NULL, 0);

   //The duplicates should be suppressed and the resource record should
   //appear only once in the list
   if(!duplicate)
   {
      //Set the position to the end of the buffer
      offset = message->length;

      //The first pass calculates the length of the DNS encoded service name
      n = mdnsEncodeName("", service->name, ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //Encode the service name using the DNS name notation
      offset += mdnsEncodeName("", service->name,
         ".local", (uint8_t *) message->dnsHeader + offset);

      //Consider the length of the resource record itself
      if((offset + sizeof(DnsResourceRecord)) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //Point to the corresponding resource record
      record = DNS_GET_RESOURCE_RECORD(message->dnsHeader, offset);

      //Fill in resource record
      record->rtype = HTONS(DNS_RR_TYPE_PTR);
      record->rclass = HTONS(DNS_RR_CLASS_IN);
      record->ttl = htonl(ttl);

      //Advance write index
      offset += sizeof(DnsResourceRecord);

      //The first pass calculates the length of the DNS encoded instance name
      n = mdnsEncodeName(context->instanceName, service->name, ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the instance name using DNS notation
      n = mdnsEncodeName(context->instanceName,
         service->name, ".local", record->rdata);

      //Convert length field to network byte order
      record->rdlength = htons(n);

      //Number of resource records in the answer section
      message->dnsHeader->ancount++;
      //Update the length of the DNS message
      message->length = offset + n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SRV resource record
 * @param[in] interface Underlying network interface
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] service Pointer to a DNS-SD service
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t dnsSdFormatSrvRecord(NetInterface *interface, MdnsMessage *message,
   const DnsSdService *service, bool_t cacheFlush, uint32_t ttl)
{
   size_t n;
   size_t offset;
   bool_t duplicate;
   MdnsResponderContext *mdnsResponderContext;
   DnsSdContext *dnsSdContext;
   DnsSrvResourceRecord *record;

   //Point to the mDNS responder context
   mdnsResponderContext = interface->mdnsResponderContext;
   //Point to the DNS-SD context
   dnsSdContext = interface->dnsSdContext;

   //Check whether the resource record is already present in the Answer
   //Section of the message
   duplicate = mdnsCheckDuplicateRecord(message, dnsSdContext->instanceName,
      service->name, ".local", DNS_RR_TYPE_SRV, NULL, 0);

   //The duplicates should be suppressed and the resource record should
   //appear only once in the list
   if(!duplicate)
   {
      //Set the position to the end of the buffer
      offset = message->length;

      //The first pass calculates the length of the DNS encoded instance name
      n = mdnsEncodeName(dnsSdContext->instanceName,
         service->name, ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the instance name using DNS notation
      offset += mdnsEncodeName(dnsSdContext->instanceName,
         service->name, ".local", (uint8_t *) message->dnsHeader + offset);

      //Consider the length of the resource record itself
      if((offset + sizeof(DnsSrvResourceRecord)) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //Point to the corresponding resource record
      record = (DnsSrvResourceRecord *) DNS_GET_RESOURCE_RECORD(message->dnsHeader, offset);

      //Fill in resource record
      record->rtype = HTONS(DNS_RR_TYPE_SRV);
      record->rclass = HTONS(DNS_RR_CLASS_IN);
      record->ttl = htonl(ttl);
      record->priority = htons(service->priority);
      record->weight = htons(service->weight);
      record->port = htons(service->port);

      //Check whether the cache-flush bit should be set
      if(cacheFlush)
      {
         record->rclass |= HTONS(MDNS_RCLASS_CACHE_FLUSH);
      }

      //Advance write index
      offset += sizeof(DnsSrvResourceRecord);

      //The first pass calculates the length of the DNS encoded target name
      n = mdnsEncodeName("", mdnsResponderContext->hostname,
         ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the target name using DNS notation
      n = mdnsEncodeName("", mdnsResponderContext->hostname,
         ".local", record->target);

      //Calculate data length
      record->rdlength = htons(sizeof(DnsSrvResourceRecord) -
         sizeof(DnsResourceRecord) + n);

      //Number of resource records in the answer section
      message->dnsHeader->ancount++;
      //Update the length of the DNS message
      message->length = offset + n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format TXT resource record
 * @param[in] interface Underlying network interface
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] service Pointer to a DNS-SD service
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t dnsSdFormatTxtRecord(NetInterface *interface, MdnsMessage *message,
   const DnsSdService *service, bool_t cacheFlush, uint32_t ttl)
{
   size_t n;
   size_t offset;
   bool_t duplicate;
   DnsSdContext *context;
   DnsResourceRecord *record;

   //Point to the DNS-SD context
   context = interface->dnsSdContext;

   //Check whether the resource record is already present in the Answer
   //Section of the message
   duplicate = mdnsCheckDuplicateRecord(message, context->instanceName,
      service->name, ".local", DNS_RR_TYPE_TXT, NULL, 0);

   //The duplicates should be suppressed and the resource record should
   //appear only once in the list
   if(!duplicate)
   {
      //Set the position to the end of the buffer
      offset = message->length;

      //The first pass calculates the length of the DNS encoded instance name
      n = mdnsEncodeName(context->instanceName, service->name, ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the instance name using DNS notation
      offset += mdnsEncodeName(context->instanceName,
         service->name, ".local", (uint8_t *) message->dnsHeader + offset);

      //Consider the length of the resource record itself
      if((offset + sizeof(DnsResourceRecord)) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //Point to the corresponding resource record
      record = DNS_GET_RESOURCE_RECORD(message->dnsHeader, offset);

      //Fill in resource record
      record->rtype = HTONS(DNS_RR_TYPE_TXT);
      record->rclass = HTONS(DNS_RR_CLASS_IN);
      record->ttl = htonl(ttl);
      record->rdlength = htons(service->metadataLength);

      //Check whether the cache-flush bit should be set
      if(cacheFlush)
      {
         record->rclass |= HTONS(MDNS_RCLASS_CACHE_FLUSH);
      }

      //Advance write index
      offset += sizeof(DnsResourceRecord);

      //Check the length of the resulting mDNS message
      if((offset + service->metadataLength) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //Copy metadata
      osMemcpy(record->rdata, service->metadata, service->metadataLength);

      //Update the length of the DNS message
      message->length = offset + service->metadataLength;
      //Number of resource records in the answer section
      message->dnsHeader->ancount++;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format NSEC resource record
 * @param[in] interface Underlying network interface
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] service Pointer to a DNS-SD service
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t dnsSdFormatNsecRecord(NetInterface *interface, MdnsMessage *message,
   const DnsSdService *service, bool_t cacheFlush, uint32_t ttl)
{
   size_t n;
   size_t offset;
   bool_t duplicate;
   size_t bitmapLength;
   uint8_t bitmap[8];
   DnsSdContext *context;
   DnsResourceRecord *record;

   //Point to the DNS-SD context
   context = interface->dnsSdContext;

   //Check whether the resource record is already present in the Answer
   //Section of the message
   duplicate = mdnsCheckDuplicateRecord(message, context->instanceName,
      service->name, ".local", DNS_RR_TYPE_NSEC, NULL, 0);

   //The duplicates should be suppressed and the resource record should
   //appear only once in the list
   if(!duplicate)
   {
      //The bitmap identifies the resource record types that exist
      osMemset(bitmap, 0, sizeof(bitmap));

      //TXT resource record is supported
      DNS_SET_NSEC_BITMAP(bitmap, DNS_RR_TYPE_TXT);
      //SRV resource record is supported
      DNS_SET_NSEC_BITMAP(bitmap, DNS_RR_TYPE_SRV);

      //Compute the length of the bitmap
      for(bitmapLength = sizeof(bitmap); bitmapLength > 0; bitmapLength--)
      {
         //Trailing zero octets in the bitmap must be omitted...
         if(bitmap[bitmapLength - 1] != 0x00)
            break;
      }

      //Set the position to the end of the buffer
      offset = message->length;

      //The first pass calculates the length of the DNS encoded instance name
      n = mdnsEncodeName(context->instanceName, service->name, ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the instance name using the DNS name notation
      offset += mdnsEncodeName(context->instanceName, service->name,
         ".local", (uint8_t *) message->dnsHeader + offset);

      //Consider the length of the resource record itself
      if((offset + sizeof(DnsResourceRecord)) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //Point to the corresponding resource record
      record = DNS_GET_RESOURCE_RECORD(message->dnsHeader, offset);

      //Fill in resource record
      record->rtype = HTONS(DNS_RR_TYPE_NSEC);
      record->rclass = HTONS(DNS_RR_CLASS_IN);
      record->ttl = htonl(ttl);

      //Check whether the cache-flush bit should be set
      if(cacheFlush)
      {
         record->rclass |= HTONS(MDNS_RCLASS_CACHE_FLUSH);
      }

      //Advance write index
      offset += sizeof(DnsResourceRecord);

      //Check the length of the resulting mDNS message
      if((offset + n + 2) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The Next Domain Name field contains the record's own name
      mdnsEncodeName(context->instanceName, service->name,
         ".local", record->rdata);

      //DNS NSEC record is limited to Window Block number zero
      record->rdata[n++] = 0;
      //The Bitmap Length is a value in the range 1-32
      record->rdata[n++] = bitmapLength;

      //The Bitmap data identifies the resource record types that exist
      osMemcpy(record->rdata + n, bitmap, bitmapLength);

      //Convert length field to network byte order
      record->rdlength = htons(n + bitmapLength);

      //Number of resource records in the answer section
      message->dnsHeader->ancount++;
      //Update the length of the DNS message
      message->length = offset + n + bitmapLength;
   }

   //Successful processing
   return NO_ERROR;
}

#endif

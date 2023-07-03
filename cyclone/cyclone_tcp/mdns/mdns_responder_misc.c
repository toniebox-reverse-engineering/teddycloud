/**
 * @file mdns_responder_misc.c
 * @brief Helper functions for mDNS responder
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
#include "mdns/mdns_responder.h"
#include "mdns/mdns_responder_misc.h"
#include "dns_sd/dns_sd.h"
#include "dns_sd/dns_sd_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (MDNS_RESPONDER_SUPPORT == ENABLED)


/**
 * @brief Update FSM state
 * @param[in] context Pointer to the mDNS responder context
 * @param[in] newState New state to switch to
 * @param[in] delay Initial delay
 **/

void mdnsResponderChangeState(MdnsResponderContext *context,
   MdnsState newState, systime_t delay)
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
 * @brief Programmatically change the host name
 * @param[in] context Pointer to the mDNS responder context
 **/

void mdnsResponderChangeHostname(MdnsResponderContext *context)
{
   size_t i;
   size_t m;
   size_t n;
   uint32_t index;
   char_t s[16];

   //Retrieve the length of the string
   n = osStrlen(context->hostname);

   //Parse the string backwards
   for(i = n; i > 0; i--)
   {
      //Check whether the current character is a digit
      if(!osIsdigit(context->hostname[i - 1]))
         break;
   }

   //Any number following the host name?
   if(context->hostname[i] != '\0')
   {
      //Retrieve the number at the end of the name
      index = atoi(context->hostname + i);
      //Increment the value
      index++;

      //Strip the digits
      context->hostname[i] = '\0';
   }
   else
   {
      //Append the digit "2" to the name
      index = 2;
   }

   //Convert the number to a string of characters
   m = osSprintf(s, "%" PRIu32, index);

   //Sanity check
   if((i + m) <= NET_MAX_HOSTNAME_LEN)
   {
      //Add padding if necessary
      while((i + m) < n)
      {
         context->hostname[i++] = '0';
      }

      //Properly terminate the string
      context->hostname[i] = '\0';
      //Programmatically change the host name
      osStrcat(context->hostname, s);
   }
}


/**
 * @brief Send probe packet
 * @param[in] context Pointer to the mDNS responder context
 * @return Error code
 **/

error_t mdnsResponderSendProbe(MdnsResponderContext *context)
{
   error_t error;
   NetInterface *interface;
   DnsQuestion *dnsQuestion;
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
      //Encode the host name using the DNS name notation
      message.length += mdnsEncodeName(context->hostname, "",
         ".local", message.dnsHeader->questions);

      //Point to the corresponding question structure
      dnsQuestion = DNS_GET_QUESTION(message.dnsHeader, message.length);

      //The probes should be sent as QU questions with the unicast-response
      //bit set, to allow a defending host to respond immediately via unicast
      dnsQuestion->qtype = HTONS(DNS_RR_TYPE_ANY);
      dnsQuestion->qclass = HTONS(MDNS_QCLASS_QU | DNS_RR_CLASS_IN);

      //Update the length of the mDNS query message
      message.length += sizeof(DnsQuestion);

      //Generate A resource records
      error = mdnsResponderGenerateIpv4AddrRecords(context, &message, FALSE,
         MDNS_DEFAULT_RR_TTL);
      //Any error to report?
      if(error)
         break;

      //Generate AAAA resource records
      error = mdnsResponderGenerateIpv6AddrRecords(context, &message, FALSE,
         MDNS_DEFAULT_RR_TTL);
      //Any error to report?
      if(error)
         break;

      //Number of questions in the Question Section
      message.dnsHeader->qdcount = 1;
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
 * @param[in] context Pointer to the mDNS responder context
 * @return Error code
 **/

error_t mdnsResponderSendAnnouncement(MdnsResponderContext *context)
{
   error_t error;
   NetInterface *interface;
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
      //Generate A resource records
      error = mdnsResponderGenerateIpv4AddrRecords(context, &message, TRUE,
         MDNS_DEFAULT_RR_TTL);
      //Any error to report?
      if(error)
         break;

      //Generate reverse address mapping PTR resource records (IPv4)
      error = mdnsResponderGenerateIpv4PtrRecords(context, &message, TRUE,
         MDNS_DEFAULT_RR_TTL);
      //Any error to report?
      if(error)
         break;

      //Generate AAAA resource records
      error = mdnsResponderGenerateIpv6AddrRecords(context, &message, TRUE,
         MDNS_DEFAULT_RR_TTL);
      //Any error to report?
      if(error)
         break;

      //Generate reverse address mapping PTR resource records (IPv6)
      error = mdnsResponderGenerateIpv6PtrRecords(context, &message, TRUE,
         MDNS_DEFAULT_RR_TTL);
      //Any error to report?
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
 * @param[in] context Pointer to the mDNS responder context
 * @return Error code
 **/

error_t mdnsResponderSendGoodbye(MdnsResponderContext *context)
{
   error_t error;
   NetInterface *interface;
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
      //Generate A resource records
      error = mdnsResponderGenerateIpv4AddrRecords(context, &message, TRUE, 0);
      //Any error to report?
      if(error)
         break;

      //Generate reverse address mapping PTR resource records (IPv4)
      error = mdnsResponderGenerateIpv4PtrRecords(context, &message, TRUE, 0);
      //Any error to report?
      if(error)
         break;

      //Generate AAAA resource records
      error = mdnsResponderGenerateIpv6AddrRecords(context, &message, TRUE, 0);
      //Any error to report?
      if(error)
         break;

      //Generate reverse address mapping PTR resource records (IPv6)
      error = mdnsResponderGenerateIpv6PtrRecords(context, &message, TRUE, 0);
      //Any error to report?
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
 * @brief Process mDNS query message
 * @param[in] interface Underlying network interface
 * @param[in] query Incoming mDNS query message
 **/

void mdnsResponderProcessQuery(NetInterface *interface, MdnsMessage *query)
{
   error_t error;
   uint_t i;
   size_t k;
   size_t n;
   size_t offset;
   DnsQuestion *question;
   DnsResourceRecord *record;
   MdnsResponderContext *context;
   MdnsMessage *response;
   uint16_t destPort;
   IpAddr destIpAddr;

   //Point to the mDNS responder context
   context = interface->mdnsResponderContext;
   //Make sure the mDNS responder has been properly instantiated
   if(context == NULL)
      return;

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 query received?
   if(query->pseudoHeader->length == sizeof(Ipv4PseudoHeader))
   {
      //If the source UDP port in a received Multicast DNS query is not port 5353,
      //this indicates that the querier originating the query is a simple resolver
      if(ntohs(query->udpHeader->srcPort) != MDNS_PORT)
      {
         //The mDNS responder must send a UDP response directly back to the querier,
         //via unicast, to the query packet's source IP address and port
         destIpAddr.length = sizeof(Ipv4Addr);
         destIpAddr.ipv4Addr = query->pseudoHeader->ipv4Data.srcAddr;
      }
      else
      {
         //Use mDNS IPv4 multicast address
         destIpAddr.length = sizeof(Ipv4Addr);
         destIpAddr.ipv4Addr = MDNS_IPV4_MULTICAST_ADDR;
      }

      //Point to the mDNS response message
      response = &context->ipv4Response;
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 query received?
   if(query->pseudoHeader->length == sizeof(Ipv6PseudoHeader))
   {
      //If the source UDP port in a received Multicast DNS query is not port 5353,
      //this indicates that the querier originating the query is a simple resolver
      if(ntohs(query->udpHeader->srcPort) != MDNS_PORT)
      {
         //The mDNS responder must send a UDP response directly back to the querier,
         //via unicast, to the query packet's source IP address and port
         destIpAddr.length = sizeof(Ipv6Addr);
         destIpAddr.ipv6Addr = query->pseudoHeader->ipv6Data.srcAddr;
      }
      else
      {
         //Use mDNS IPv6 multicast address
         destIpAddr.length = sizeof(Ipv6Addr);
         destIpAddr.ipv6Addr = MDNS_IPV6_MULTICAST_ADDR;
      }

      //Point to the mDNS response message
      response = &context->ipv6Response;
   }
   else
#endif
   //Invalid query received?
   {
      //Discard the mDNS query message
      return;
   }

   //Check whether the querier originating the query is a simple resolver
   if(ntohs(query->udpHeader->srcPort) != MDNS_PORT)
   {
      //Silently discard malformed one-shot mDNS queries
      if(ntohs(query->dnsHeader->qdcount) != 1 ||
         ntohs(query->dnsHeader->ancount) != 0 ||
         ntohs(query->dnsHeader->nscount) != 0)
      {
         return;
      }

      //Release pending mDNS response, if any
      if(response->buffer != NULL)
      {
         mdnsDeleteMessage(response);
      }
   }

   //When possible, a responder should, for the sake of network efficiency,
   //aggregate as many responses as possible into a single mDNS response message
   if(response->buffer == NULL)
   {
      //Create an empty mDNS response message
      error = mdnsCreateMessage(response, TRUE);
      //Any error to report?
      if(error)
         return;
   }

   //Take the identifier from the query message
   response->dnsHeader->id = query->dnsHeader->id;

   //Point to the first question
   offset = sizeof(DnsHeader);

   //Start of exception handling block
   do
   {
      //Parse the Question Section
      for(i = 0; i < ntohs(query->dnsHeader->qdcount); i++)
      {
         //Parse resource record name
         n = dnsParseName(query->dnsHeader, query->length, offset, NULL, 0);
         //Invalid name?
         if(!n)
            break;
         //Malformed mDNS message?
         if((n + sizeof(DnsQuestion)) > query->length)
            break;

         //Point to the corresponding entry
         question = DNS_GET_QUESTION(query->dnsHeader, n);

         //Parse question
         error = mdnsResponderParseQuestion(interface, query,
            offset, question, response);
         //Any error to report?
         if(error)
            break;

#if (DNS_SD_SUPPORT == ENABLED)
         //Parse resource record
         error = dnsSdParseQuestion(interface, query, offset,
            question, response);
         //Any error to report?
         if(error)
            break;
#endif
         //Point to the next question
         offset = n + sizeof(DnsQuestion);
      }

      //Any error while parsing the Question Section?
      if(i != ntohs(query->dnsHeader->qdcount))
         break;

      //Parse the Known-Answer Section
      for(i = 0; i < ntohs(query->dnsHeader->ancount); i++)
      {
         //Parse resource record name
         n = dnsParseName(query->dnsHeader, query->length, offset, NULL, 0);
         //Invalid name?
         if(!n)
            break;

         //Point to the associated resource record
         record = DNS_GET_RESOURCE_RECORD(query->dnsHeader, n);
         //Point to the resource data
         n += sizeof(DnsResourceRecord);

         //Make sure the resource record is valid
         if(n > query->length)
            break;
         if((n + ntohs(record->rdlength)) > query->length)
            break;

         //Parse resource record
         mdnsResponderParseKnownAnRecord(interface, query, offset,
            record, response);

         //Point to the next resource record
         offset = n + ntohs(record->rdlength);
      }

      //Any error while parsing the Answer Section?
      if(i != ntohs(query->dnsHeader->ancount))
         break;

      k = offset;

      //Parse Authority Section
      for(i = 0; i < ntohs(query->dnsHeader->nscount); i++)
      {
         //Parse resource record name
         n = dnsParseName(query->dnsHeader, query->length, offset, NULL, 0);
         //Invalid name?
         if(!n)
            break;

         //Point to the associated resource record
         record = DNS_GET_RESOURCE_RECORD(query->dnsHeader, n);
         //Point to the resource data
         n += sizeof(DnsResourceRecord);

         //Make sure the resource record is valid
         if(n > query->length)
            break;
         if((n + ntohs(record->rdlength)) > query->length)
            break;

#if (DNS_SD_SUPPORT == ENABLED)
         //Check for service instance name conflict
         dnsSdParseNsRecord(interface, query, offset, record);
#endif
         //Point to the next resource record
         offset = n + ntohs(record->rdlength);
      }

      //Any error while parsing the Authority Section?
      if(i != ntohs(query->dnsHeader->nscount))
         break;

      //When a host that is probing for a record sees another host issue a query
      //for the same record, it consults the Authority Section of that query.
      //If it finds any resource record there which answers the query, then it
      //compares the data of that resource record with its own tentative data
      mdnsResponderParseNsRecords(context, query, k);

      //End of exception handling block
   } while(0);

   //Should a mDNS message be send in response to the query?
   if(response->dnsHeader->ancount > 0)
   {
      //If the source UDP port in a received Multicast DNS query is not port 5353,
      //this indicates that the querier originating the query is a simple resolver
      if(ntohs(query->udpHeader->srcPort) != MDNS_PORT)
      {
#if (DNS_SD_SUPPORT == ENABLED)
         //Generate additional records (DNS-SD)
         dnsSdGenerateAdditionalRecords(interface, response, TRUE);
#endif
         //Generate additional records (mDNS)
         mdnsResponderGenerateAdditionalRecords(context, response, TRUE);

         //Destination port
         destPort = ntohs(query->udpHeader->srcPort);

         //Send mDNS response message
         mdnsSendMessage(interface, response, &destIpAddr, destPort);
         //Free previously allocated memory
         mdnsDeleteMessage(response);
      }
      else
      {
         //Check whether the answer should be delayed
         if(query->dnsHeader->tc)
         {
            //In the case where the query has the TC (truncated) bit set, indicating
            //that subsequent Known-Answer packets will follow, responders should
            //delay their responses by a random amount of time selected with uniform
            //random distribution in the range 400-500 ms
            response->timeout = netGenerateRandRange(400, 500);

            //Save current time
            response->timestamp = osGetSystemTime();
         }
         else if(response->sharedRecordCount > 0)
         {
            //In any case where there may be multiple responses, such as queries
            //where the answer is a member of a shared resource record set, each
            //responder should delay its response by a random amount of time
            //selected with uniform random distribution in the range 20-120 ms
            response->timeout = netGenerateRandRange(20, 120);

            //Save current time
            response->timestamp = osGetSystemTime();
         }
         else
         {
#if (DNS_SD_SUPPORT == ENABLED)
            //Generate additional records (refer to RFC 6763 section 12)
            dnsSdGenerateAdditionalRecords(interface, response, FALSE);
#endif
            //Generate additional records (mDNS)
            mdnsResponderGenerateAdditionalRecords(context, response, FALSE);

            //Send mDNS response message
            mdnsSendMessage(interface, response, &destIpAddr, MDNS_PORT);
            //Free previously allocated memory
            mdnsDeleteMessage(response);
         }
      }
   }
   else
   {
      //Free mDNS response message
      mdnsDeleteMessage(response);
   }
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

error_t mdnsResponderParseQuestion(NetInterface *interface,
   const MdnsMessage *query, size_t offset, const DnsQuestion *question,
   MdnsMessage *response)
{
   error_t error;
   uint_t i;
   uint16_t qclass;
   uint16_t qtype;
   uint32_t ttl;
   bool_t cacheFlush;
   MdnsResponderContext *context;

   //Point to the mDNS responder context
   context = interface->mdnsResponderContext;

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

   //Check the class of the query
   if(qclass == DNS_RR_CLASS_IN || qclass == DNS_RR_CLASS_ANY)
   {
      //Compare domain name
      if(!mdnsCompareName(query->dnsHeader, query->length, offset,
         context->hostname, "", ".local", 0))
      {
         //Check whether the querier originating the query is a simple resolver
         if(ntohs(query->udpHeader->srcPort) != MDNS_PORT)
         {
            DnsQuestion *dnsQuestion;

            //This unicast response must be a conventional unicast response as
            //would be generated by a conventional unicast DNS server. It must
            //repeat the question given in the query message (refer to RFC 6762,
            //section 6.7)
            response->length += mdnsEncodeName(context->hostname, "", ".local",
               response->dnsHeader->questions);

            //Point to the corresponding question structure
            dnsQuestion = DNS_GET_QUESTION(response->dnsHeader, response->length);

            //Fill in question structure
            dnsQuestion->qtype = htons(qtype);
            dnsQuestion->qclass = htons(qclass);

            //Update the length of the mDNS response message
            response->length += sizeof(DnsQuestion);
            //Number of questions in the Question Section
            response->dnsHeader->qdcount++; 
         }

#if (IPV4_SUPPORT == ENABLED)
         //A query?
         if(qtype == DNS_RR_TYPE_A)
         {
            //Generate A resource records
            error = mdnsResponderGenerateIpv4AddrRecords(context, response,
               cacheFlush, ttl);
            //Any error to report?
            if(error)
               return error;
         }
         else
#endif
#if (IPV6_SUPPORT == ENABLED)
         //AAAA query?
         if(qtype == DNS_RR_TYPE_AAAA)
         {
            //Generate AAAA resource records
            error = mdnsResponderGenerateIpv6AddrRecords(context, response,
               cacheFlush, ttl);
            //Any error to report?
            if(error)
               return error;
         }
         else
#endif
         //ANY query?
         if(qtype == DNS_RR_TYPE_ANY)
         {
            //Generate A resource records
            error = mdnsResponderGenerateIpv4AddrRecords(context, response,
               cacheFlush, ttl);
            //Any error to report?
            if(error)
               return error;

            //Generate AAAA resource records
            error = mdnsResponderGenerateIpv6AddrRecords(context, response,
               cacheFlush, ttl);
            //Any error to report?
            if(error)
               return error;

            //Generate NSEC resource record
            error = mdnsResponderFormatNsecRecord(context, response,
               cacheFlush, ttl);
            //Any error to report?
            if(error)
               return error;
         }
         else
         {
            //Generate NSEC resource record
            error = mdnsResponderFormatNsecRecord(context, response,
               cacheFlush, ttl);
            //Any error to report?
            if(error)
               return error;
         }
      }

      //PTR query?
      if(qtype == DNS_RR_TYPE_PTR || qtype == DNS_RR_TYPE_ANY)
      {
#if (IPV4_SUPPORT == ENABLED)
         //Loop through the list of IPv4 addresses assigned to the interface
         for(i = 0; i < IPV4_ADDR_LIST_SIZE; i++)
         {
            //Valid entry?
            if(context->ipv4AddrList[i].valid)
            {
               //Reverse DNS lookup?
               if(!mdnsCompareName(query->dnsHeader, query->length, offset,
                  context->ipv4AddrList[i].reverseName, "in-addr", ".arpa", 0))
               {
                  //Format reverse address mapping PTR resource record (IPv4)
                  error = mdnsResponderFormatIpv4PtrRecord(context, response,
                     context->ipv4AddrList[i].reverseName, cacheFlush, ttl);
                  //Any error to report?
                  if(error)
                     return error;
               }
            }
         }
#endif

#if (IPV6_SUPPORT == ENABLED)
         //Loop through the list of IPv6 addresses assigned to the interface
         for(i = 0; i < IPV6_ADDR_LIST_SIZE; i++)
         {
            //Valid entry?
            if(context->ipv6AddrList[i].valid)
            {
               //Reverse DNS lookup?
               if(!mdnsCompareName(query->dnsHeader, query->length, offset,
                  context->ipv6AddrList[i].reverseName, "ip6", ".arpa", 0))
               {
                  //Format reverse address mapping PTR resource record (IPv6)
                  error = mdnsResponderFormatIpv6PtrRecord(context, response,
                     context->ipv6AddrList[i].reverseName, cacheFlush, ttl);
                  //Any error to report?
                  if(error)
                     return error;
               }
            }
         }
#endif
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse a resource record from the Known-Answer Section
 * @param[in] interface Underlying network interface
 * @param[in] query Incoming mDNS query message
 * @param[in] queryOffset Offset to first byte of the resource record
 * @param[in] queryRecord Pointer to the resource record
 * @param[in,out] response mDNS response message
 **/

void mdnsResponderParseKnownAnRecord(NetInterface *interface,
   const MdnsMessage *query, size_t queryOffset,
   const DnsResourceRecord *queryRecord, MdnsMessage *response)
{
   size_t i;
   size_t n;
   size_t responseOffset;
   DnsResourceRecord *responseRecord;

   //mDNS responses must not contain any questions in the Question Section
   if(response->dnsHeader->qdcount == 0)
   {
      //Point to the first resource record
      responseOffset = sizeof(DnsHeader);

      //Parse the Answer Section of the response
      for(i = 0; i < response->dnsHeader->ancount; i++)
      {
         //Parse resource record name
         n = dnsParseName(response->dnsHeader, response->length, responseOffset,
            NULL, 0);
         //Invalid name?
         if(!n)
            break;

         //Point to the associated resource record
         responseRecord = DNS_GET_RESOURCE_RECORD(response->dnsHeader, n);
         //Point to the resource data
         n += sizeof(DnsResourceRecord);

         //Make sure the resource record is valid
         if(n > response->length)
            break;

         //Point to the end of the resource record
         n += ntohs(responseRecord->rdlength);

         //Make sure the resource record is valid
         if(n > response->length)
            break;

         //Compare resource record names
         if(!dnsCompareEncodedName(query->dnsHeader, query->length, queryOffset,
            response->dnsHeader, response->length, responseOffset, 0))
         {
            //Compare the contents of the resource records
            if(!mdnsCompareRecord(query, queryRecord, response, responseRecord))
            {
               //A mDNS responder must not answer a mDNS query if the answer
               //it would give is already included in the Answer Section with
               //an RR TTL at least half the correct value
               if(ntohl(queryRecord->ttl) >= (ntohl(responseRecord->ttl) / 2))
               {
                  //Perform Known-Answer Suppression
                  osMemmove((uint8_t *) response->dnsHeader + responseOffset,
                     (uint8_t *) response->dnsHeader + n, response->length - n);

                  //Update the length of the mDNS response message
                  response->length -= (n - responseOffset);
                  //Update the number of resource records in the Answer Section
                  response->dnsHeader->ancount--;

                  //Keep at the same position
                  n = responseOffset;
                  i--;
               }
            }
         }

         //Point to the next resource record
         responseOffset = n;
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

void mdnsResponderParseAnRecord(NetInterface *interface,
   const MdnsMessage *response, size_t offset, const DnsResourceRecord *record)
{
   uint_t i;
   bool_t conflict;
   uint16_t rclass;
   MdnsResponderContext *context;

   //Point to the mDNS responder context
   context = interface->mdnsResponderContext;

   //Check for conflicts
   if(!mdnsCompareName(response->dnsHeader, response->length, offset,
      context->hostname, "", ".local", 0))
   {
      //Convert the class to host byte order
      rclass = ntohs(record->rclass);
      //Discard Cache Flush flag
      rclass &= ~MDNS_RCLASS_CACHE_FLUSH;

      //Check the class of the resource record
      if(rclass == DNS_RR_CLASS_IN)
      {
#if (IPV4_SUPPORT == ENABLED)
         //A resource record found?
         if(ntohs(record->rtype) == DNS_RR_TYPE_A)
         {
            //A conflict occurs when a mDNS responder has a unique record for
            //which it is currently authoritative, and it receives a mDNS
            //response message containing a record with the same name, rrtype
            //and rrclass, but inconsistent rdata
            conflict = TRUE;

            //Verify the length of the data field
            if(ntohs(record->rdlength) == sizeof(Ipv4Addr))
            {
               //Loop through the list of IPv4 addresses assigned to the interface
               for(i = 0; i < IPV4_ADDR_LIST_SIZE; i++)
               {
                  //Valid IPv4 address?
                  if(context->ipv4AddrList[i].valid)
                  {
                     //Check whether the rdata field is consistent
                     if(ipv4CompAddr(context->ipv4AddrList[i].record.rdata,
                        record->rdata))
                     {
                        conflict = FALSE;
                     }
                  }
               }
            }

            //Check whether the host name is already in use by some other host
            if(conflict)
            {
               context->conflict = TRUE;
            }
         }
#endif
#if (IPV6_SUPPORT == ENABLED)
         //AAAA resource record found?
         if(ntohs(record->rtype) == DNS_RR_TYPE_AAAA)
         {
            //A conflict occurs when a mDNS responder has a unique record for
            //which it is currently authoritative, and it receives a mDNS
            //response message containing a record with the same name, rrtype
            //and rrclass, but inconsistent rdata
            conflict = TRUE;

            //Verify the length of the data field
            if(ntohs(record->rdlength) == sizeof(Ipv6Addr))
            {
               //Loop through the list of IPv6 addresses assigned to the interface
               for(i = 0; i < IPV6_ADDR_LIST_SIZE; i++)
               {
                  //Valid IPv6 address?
                  if(context->ipv6AddrList[i].valid)
                  {
                     //Check whether the rdata field is consistent
                     if(ipv6CompAddr(context->ipv6AddrList[i].record.rdata,
                        record->rdata))
                     {
                        conflict = FALSE;
                     }
                  }
               }
            }

            //Check whether the host name is already in use by some other host
            if(conflict)
            {
               context->conflict = TRUE;
            }
         }
#endif
      }
   }
}


/**
 * @brief Parse the Authority Section
 * @param[in] context Pointer to the mDNS responder context
 * @param[in] query Incoming mDNS query message
 * @param[in] offset Offset to first byte of the Authority Section
 **/

void mdnsResponderParseNsRecords(MdnsResponderContext *context,
   const MdnsMessage *query, size_t offset)
{
   int_t res;
   DnsResourceRecord *record1;
   DnsResourceRecord *record2;

   //Get the first tiebreaker record in lexicographical order
   record1 = mdnsResponderGetNextTiebreakerRecord(context, query, offset, NULL);
   //Get the first host record in lexicographical order
   record2 = mdnsResponderGetNextHostRecord(context, NULL);

   //Check whether the Authority Section of the query contains any tiebreaker
   //record
   if(record1 != NULL)
   {
      //When a host is probing for a set of records with the same name, or a
      //message is received containing multiple tiebreaker records answering
      //a given probe question in the Question Section, the host's records
      //and the tiebreaker records from the message are each sorted into order
      while(1)
      {
         //The records are compared pairwise
         if(record1 == NULL && record2 == NULL)
         {
            //If both lists run out of records at the same time without any
            //difference being found, then this indicates that two devices are
            //advertising identical sets of records, as is sometimes done for
            //fault tolerance, and there is, in fact, no conflict
            break;
         }
         else if(record1 != NULL && record2 == NULL)
         {
            //If either list of records runs out of records before any difference
            //is found, then the list with records remaining is deemed to have won
            //the tiebreak
            context->tieBreakLost = TRUE;
            break;
         }
         else if(record1 == NULL && record2 != NULL)
         {
            //The host has won the tiebreak
            break;
         }
         else
         {
            //The two records are compared and the lexicographically later data wins
            res = mdnsCompareRecord(query, record1, NULL, record2);

            //Check comparison result
            if(res > 0)
            {
               //If the host finds that its own data is lexicographically earlier,
               //then it defers to the winning host by waiting one second, and then
               //begins probing for this record again
               context->tieBreakLost = TRUE;
               break;
            }
            else if(res < 0)
            {
               //If the host finds that its own data is lexicographically later,
               //it simply ignores the other host's probe
               break;
            }
            else
            {
               //When comparing the records, if the first records match perfectly,
               //then the second records are compared, and so on
            }
         }

         //Get the next tiebreaker record in lexicographical order
         record1 = mdnsResponderGetNextTiebreakerRecord(context, query, offset,
            record1);

         //Get the next host record in lexicographical order
         record2 = mdnsResponderGetNextHostRecord(context, record2);
      }
   }
}


/**
 * @brief Generate additional records
 * @param[in] context Pointer to the mDNS responder context
 * @param[in,out] response mDNS response message
 * @param[in] legacyUnicast This flag is set for legacy unicast responses
 **/

void mdnsResponderGenerateAdditionalRecords(MdnsResponderContext *context,
   MdnsMessage *response, bool_t legacyUnicast)
{
   error_t error;
   uint_t i;
   uint_t k;
   size_t n;
   size_t offset;
   uint_t ancount;
   uint16_t rclass;
   uint32_t ttl;
   bool_t cacheFlush;
   DnsResourceRecord *record;

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

   //Point to the first question
   offset = sizeof(DnsHeader);

   //Skip the question section
   for(i = 0; i < response->dnsHeader->qdcount; i++)
   {
      //Parse domain name
      offset = dnsParseName(response->dnsHeader, response->length, offset, NULL, 0);
      //Invalid name?
      if(!offset)
         break;

      //Point to the next question
      offset += sizeof(DnsQuestion);
      //Make sure the mDNS message is valid
      if(offset > response->length)
         break;
   }

   //Save the number of resource records in the Answer Section
   ancount = response->dnsHeader->ancount;

   //Compute the total number of resource records
   k = response->dnsHeader->ancount + response->dnsHeader->nscount +
      response->dnsHeader->arcount;

   //Loop through the resource records
   for(i = 0; i < k; i++)
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

      //Check the class of the resource record
      if(rclass == DNS_RR_CLASS_IN)
      {
         //A record?
         if(ntohs(record->rtype) == DNS_RR_TYPE_A)
         {
            //When a mDNS responder places an IPv4 address record into a
            //response message, it should also place any IPv6 address records
            //with the same name into the Additional Section
            if(context->ipv6AddrCount > 0)
            {
               //Generate AAAA resource records
               error = mdnsResponderGenerateIpv6AddrRecords(context, response,
                  cacheFlush, ttl);
            }
            else
            {
               //In the event that a device has only IPv4 addresses but no IPv6
               //addresses, then the appropriate NSEC record should be placed
               //into the Additional Section
               error = mdnsResponderFormatNsecRecord(context, response,
                  cacheFlush, ttl);
            }

            //Any error to report?
            if(error)
               return;
         }
         //AAAA record?
         else if(ntohs(record->rtype) == DNS_RR_TYPE_AAAA)
         {
            //When a mDNS responder places an IPv6 address record into a
            //response message, it should also place any IPv4 address records
            //with the same name into the Additional Section
            if(context->ipv4AddrCount > 0)
            {
               //Generate A resource records
               error = mdnsResponderGenerateIpv4AddrRecords(context, response,
                  cacheFlush, ttl);
            }
            else
            {
               //In the event that a device has only IPv6 addresses but no IPv4
               //addresses, then the appropriate NSEC record should be placed
               //into the Additional Section
               error = mdnsResponderFormatNsecRecord(context, response,
                  cacheFlush, ttl);;
            }

            //Any error to report?
            if(error)
               return;
         }
         //SRV record?
         else if(ntohs(record->rtype) == DNS_RR_TYPE_SRV)
         {
            //Generate A resource records
            error = mdnsResponderGenerateIpv4AddrRecords(context, response,
               cacheFlush, ttl);
            //Any error to report?
            if(error)
               return;

            //Generate AAAA resource records
            error = mdnsResponderGenerateIpv6AddrRecords(context, response,
               cacheFlush, ttl);
            //Any error to report?
            if(error)
               return;

            //In the event that a device has only IPv4 addresses but no IPv6
            //addresses, or vice versa, then the appropriate NSEC record should
            //be placed into the additional section, so that queriers can know
            //with certainty that the device has no addresses of that kind
            if(context->ipv4AddrCount == 0 || context->ipv6AddrCount == 0)
            {
               //Generate NSEC resource record
               error = mdnsResponderFormatNsecRecord(context, response,
                  cacheFlush, ttl);
               //Any error to report?
               if(error)
                  return;
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
 * @brief Generate A resource records
 * @param[in] context Pointer to the mDNS responder context
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t mdnsResponderGenerateIpv4AddrRecords(MdnsResponderContext *context,
   MdnsMessage *message, bool_t cacheFlush, uint32_t ttl)
{
#if (IPV4_SUPPORT == ENABLED)
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of IPv4 addresses assigned to the interface
   for(i = 0; i < IPV4_ADDR_LIST_SIZE && !error; i++)
   {
      //Valid entry?
      if(context->ipv4AddrList[i].valid)
      {
         //Format A resource record
         error = mdnsResponderFormatIpv4AddrRecord(context, message,
            context->ipv4AddrList[i].record.rdata, cacheFlush, ttl);
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return NO_ERROR;
#endif
}


/**
 * @brief Generate AAAA resource records
 * @param[in] context Pointer to the mDNS responder context
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t mdnsResponderGenerateIpv6AddrRecords(MdnsResponderContext *context,
   MdnsMessage *message, bool_t cacheFlush, uint32_t ttl)
{
#if (IPV6_SUPPORT == ENABLED)
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of IPv6 addresses assigned to the interface
   for(i = 0; i < IPV6_ADDR_LIST_SIZE && !error; i++)
   {
      //Valid entry?
      if(context->ipv6AddrList[i].valid)
      {
         //Format AAAA resource record
         error = mdnsResponderFormatIpv6AddrRecord(context, message,
            context->ipv6AddrList[i].record.rdata, cacheFlush, ttl);
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return NO_ERROR;
#endif
}


/**
 * @brief Generate reverse address mapping PTR resource record (IPv4)
 * @param[in] context Pointer to the mDNS responder context
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t mdnsResponderGenerateIpv4PtrRecords(MdnsResponderContext *context,
   MdnsMessage *message, bool_t cacheFlush, uint32_t ttl)
{
#if (IPV4_SUPPORT == ENABLED)
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of IPv4 addresses assigned to the interface
   for(i = 0; i < IPV4_ADDR_LIST_SIZE && !error; i++)
   {
      //Valid entry?
      if(context->ipv4AddrList[i].valid)
      {
         //Format reverse address mapping PTR resource record (IPv4)
         error = mdnsResponderFormatIpv4PtrRecord(context, message,
            context->ipv4AddrList[i].reverseName, cacheFlush, ttl);
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return NO_ERROR;
#endif
}


/**
 * @brief Generate reverse address mapping PTR resource record (IPv6)
 * @param[in] context Pointer to the mDNS responder context
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t mdnsResponderGenerateIpv6PtrRecords(MdnsResponderContext *context,
   MdnsMessage *message, bool_t cacheFlush, uint32_t ttl)
{
#if (IPV6_SUPPORT == ENABLED)
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of IPv6 addresses assigned to the interface
   for(i = 0; i < IPV6_ADDR_LIST_SIZE && !error; i++)
   {
      //Valid entry?
      if(context->ipv6AddrList[i].valid)
      {
         //Format reverse address mapping PTR resource record (IPv6)
         error = mdnsResponderFormatIpv6PtrRecord(context, message,
            context->ipv6AddrList[i].reverseName, cacheFlush, ttl);
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return NO_ERROR;
#endif
}


/**
 * @brief Format A resource record
 * @param[in] context Pointer to the mDNS responder context
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] ipv4Addr Pointer to the IPv4 address
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t mdnsResponderFormatIpv4AddrRecord(MdnsResponderContext *context,
   MdnsMessage *message, const uint8_t *ipv4Addr, bool_t cacheFlush,
   uint32_t ttl)
{
   size_t n;
   size_t offset;
   bool_t duplicate;
   DnsResourceRecord *record;

   //Check whether the resource record is already present in the Answer
   //Section of the message
   duplicate = mdnsCheckDuplicateRecord(message, context->hostname,
      "", ".local", DNS_RR_TYPE_A, ipv4Addr, sizeof(Ipv4Addr));

   //The duplicates should be suppressed and the resource record should
   //appear only once in the list
   if(!duplicate)
   {
      //Set the position to the end of the buffer
      offset = message->length;

      //The first pass calculates the length of the DNS encoded host name
      n = mdnsEncodeName(context->hostname, "", ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the host name using the DNS name notation
      offset += mdnsEncodeName(context->hostname, "", ".local",
         (uint8_t *) message->dnsHeader + offset);

      //Consider the length of the resource record itself
      n = sizeof(DnsResourceRecord) + sizeof(Ipv4Addr);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //Point to the corresponding resource record
      record = DNS_GET_RESOURCE_RECORD(message->dnsHeader, offset);

      //Fill in resource record
      record->rtype = HTONS(DNS_RR_TYPE_A);
      record->rclass = HTONS(DNS_RR_CLASS_IN);
      record->ttl = htonl(ttl);
      record->rdlength = HTONS(sizeof(Ipv4Addr));

      //Check whether the cache-flush bit should be set
      if(cacheFlush)
      {
         record->rclass |= HTONS(MDNS_RCLASS_CACHE_FLUSH);
      }

      //Copy IPv4 address
      ipv4CopyAddr(record->rdata, ipv4Addr);

      //Number of resource records in the answer section
      message->dnsHeader->ancount++;
      //Update the length of the mDNS response message
      message->length = offset + n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format AAAA resource record
 * @param[in] context Pointer to the mDNS responder context
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] ipv6Addr Pointer to the IPv6 address
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t mdnsResponderFormatIpv6AddrRecord(MdnsResponderContext *context,
   MdnsMessage *message, const uint8_t *ipv6Addr, bool_t cacheFlush,
   uint32_t ttl)
{
   size_t n;
   size_t offset;
   bool_t duplicate;
   DnsResourceRecord *record;

   //Check whether the resource record is already present in the Answer
   //Section of the message
   duplicate = mdnsCheckDuplicateRecord(message, context->hostname,
      "", ".local", DNS_RR_TYPE_AAAA, ipv6Addr, sizeof(Ipv6Addr));

   //The duplicates should be suppressed and the resource record should
   //appear only once in the list
   if(!duplicate)
   {
      //Set the position to the end of the buffer
      offset = message->length;

      //The first pass calculates the length of the DNS encoded host name
      n = mdnsEncodeName(context->hostname, "", ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the host name using the DNS name notation
      offset += mdnsEncodeName(context->hostname, "", ".local",
         (uint8_t *) message->dnsHeader + offset);

      //Consider the length of the resource record itself
      n = sizeof(DnsResourceRecord) + sizeof(Ipv6Addr);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //Point to the corresponding resource record
      record = DNS_GET_RESOURCE_RECORD(message->dnsHeader, offset);

      //Fill in resource record
      record->rtype = HTONS(DNS_RR_TYPE_AAAA);
      record->rclass = HTONS(DNS_RR_CLASS_IN);
      record->ttl = htonl(ttl);
      record->rdlength = HTONS(sizeof(Ipv6Addr));

      //Check whether the cache-flush bit should be set
      if(cacheFlush)
      {
         record->rclass |= HTONS(MDNS_RCLASS_CACHE_FLUSH);
      }

      //Copy IPv6 address
      ipv6CopyAddr(record->rdata, ipv6Addr);

      //Number of resource records in the answer section
      message->dnsHeader->ancount++;
      //Update the length of the mDNS response message
      message->length = offset + n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format reverse address mapping PTR resource record (IPv4)
 * @param[in] context Pointer to the mDNS responder context
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] reverseName Domain name for reverse DNS lookup
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t mdnsResponderFormatIpv4PtrRecord(MdnsResponderContext *context,
   MdnsMessage *message, const char_t *reverseName, bool_t cacheFlush,
   uint32_t ttl)
{
   size_t n;
   size_t offset;
   bool_t duplicate;
   DnsResourceRecord *record;

   //Check whether the resource record is already present in the Answer Section
   //of the message
   duplicate = mdnsCheckDuplicateRecord(message, reverseName, "in-addr", ".arpa",
      DNS_RR_TYPE_PTR, NULL, 0);

   //The duplicates should be suppressed and the resource record should appear
   //only once in the list
   if(!duplicate)
   {
      //Set the position to the end of the buffer
      offset = message->length;

      //The first pass calculates the length of the DNS encoded reverse name
      n = mdnsEncodeName(reverseName, "in-addr", ".arpa", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the reverse name using the DNS name notation
      offset += mdnsEncodeName(reverseName, "in-addr", ".arpa",
         (uint8_t *) message->dnsHeader + offset);

      //Consider the length of the resource record itself
      n = sizeof(DnsResourceRecord) + sizeof(Ipv4Addr);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //Point to the corresponding resource record
      record = DNS_GET_RESOURCE_RECORD(message->dnsHeader, offset);

      //Fill in resource record
      record->rtype = HTONS(DNS_RR_TYPE_PTR);
      record->rclass = HTONS(DNS_RR_CLASS_IN);
      record->ttl = htonl(ttl);

      //Check whether the cache-flush bit should be set
      if(cacheFlush)
      {
         record->rclass |= HTONS(MDNS_RCLASS_CACHE_FLUSH);
      }

      //Advance write index
      offset += sizeof(DnsResourceRecord);

      //The first pass calculates the length of the DNS encoded host name
      n = mdnsEncodeName("", context->hostname, ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the host name using DNS notation
      n = mdnsEncodeName("", context->hostname, ".local", record->rdata);

      //Convert length field to network byte order
      record->rdlength = htons(n);

      //Number of resource records in the answer section
      message->dnsHeader->ancount++;
      //Update the length of the mDNS response message
      message->length = offset + n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format reverse address mapping PTR resource record (IPv6)
 * @param[in] context Pointer to the mDNS responder context
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] reverseName Domain name for reverse DNS lookup
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t mdnsResponderFormatIpv6PtrRecord(MdnsResponderContext *context,
   MdnsMessage *message, const char_t *reverseName, bool_t cacheFlush,
   uint32_t ttl)
{
   size_t n;
   size_t offset;
   bool_t duplicate;
   DnsResourceRecord *record;

   //Check whether the resource record is already present in the Answer Section
   //of the message
   duplicate = mdnsCheckDuplicateRecord(message, reverseName, "ip6", ".arpa",
      DNS_RR_TYPE_PTR, NULL, 0);

   //The duplicates should be suppressed and the resource record should appear
   //only once in the list
   if(!duplicate)
   {
      //Set the position to the end of the buffer
      offset = message->length;

      //The first pass calculates the length of the DNS encoded reverse name
      n = mdnsEncodeName(reverseName, "ip6", ".arpa", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the reverse name using the DNS name notation
      offset += mdnsEncodeName(reverseName, "ip6", ".arpa",
         (uint8_t *) message->dnsHeader + offset);

      //Consider the length of the resource record itself
      n = sizeof(DnsResourceRecord) + sizeof(Ipv4Addr);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //Point to the corresponding resource record
      record = DNS_GET_RESOURCE_RECORD(message->dnsHeader, offset);

      //Fill in resource record
      record->rtype = HTONS(DNS_RR_TYPE_PTR);
      record->rclass = HTONS(DNS_RR_CLASS_IN);
      record->ttl = htonl(ttl);

      //Check whether the cache-flush bit should be set
      if(cacheFlush)
      {
         record->rclass |= HTONS(MDNS_RCLASS_CACHE_FLUSH);
      }

      //Advance write index
      offset += sizeof(DnsResourceRecord);

      //The first pass calculates the length of the DNS encoded host name
      n = mdnsEncodeName("", context->hostname, ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the host name using DNS notation
      n = mdnsEncodeName("", context->hostname, ".local", record->rdata);

      //Convert length field to network byte order
      record->rdlength = htons(n);

      //Number of resource records in the answer section
      message->dnsHeader->ancount++;
      //Update the length of the mDNS response message
      message->length = offset + n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format NSEC resource record
 * @param[in] context Pointer to the mDNS responder context
 * @param[in,out] message Pointer to the mDNS message
 * @param[in] cacheFlush Cache-flush bit
 * @param[in] ttl Resource record TTL (cache lifetime)
 * @return Error code
 **/

error_t mdnsResponderFormatNsecRecord(MdnsResponderContext *context,
   MdnsMessage *message, bool_t cacheFlush, uint32_t ttl)
{
   size_t n;
   size_t offset;
   bool_t duplicate;
   size_t bitmapLen;
   uint8_t bitmap[8];
   DnsResourceRecord *record;

   //Check whether the resource record is already present in the Answer
   //Section of the message
   duplicate = mdnsCheckDuplicateRecord(message, context->hostname,
      "", ".local", DNS_RR_TYPE_NSEC, NULL, 0);

   //The duplicates should be suppressed and the resource record should
   //appear only once in the list
   if(!duplicate)
   {
      //The bitmap identifies the resource record types that exist
      osMemset(bitmap, 0, sizeof(bitmap));

      //Check whether the host has A records
      if(context->ipv4AddrCount > 0)
      {
         DNS_SET_NSEC_BITMAP(bitmap, DNS_RR_TYPE_A);
      }

      //Check whether the host has AAAA records
      if(context->ipv6AddrCount > 0)
      {
         DNS_SET_NSEC_BITMAP(bitmap, DNS_RR_TYPE_AAAA);
      }

      //Compute the length of the bitmap
      for(bitmapLen = sizeof(bitmap); bitmapLen > 0; bitmapLen--)
      {
         //Trailing zero octets in the bitmap must be omitted...
         if(bitmap[bitmapLen - 1] != 0x00)
            break;
      }

      //Set the position to the end of the buffer
      offset = message->length;

      //The first pass calculates the length of the DNS encoded host name
      n = mdnsEncodeName(context->hostname, "", ".local", NULL);

      //Check the length of the resulting mDNS message
      if((offset + n) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The second pass encodes the host name using the DNS name notation
      offset += mdnsEncodeName(context->hostname, "", ".local",
         (uint8_t *) message->dnsHeader + offset);

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
      if((offset + n + 2 + bitmapLen) > MDNS_MESSAGE_MAX_SIZE)
         return ERROR_MESSAGE_TOO_LONG;

      //The Next Domain Name field contains the record's own name
      mdnsEncodeName(context->hostname, "", ".local", record->rdata);

      //DNS NSEC record is limited to Window Block number zero
      record->rdata[n++] = 0;
      //The Bitmap Length is a value in the range 1-32
      record->rdata[n++] = bitmapLen;

      //The Bitmap data identifies the resource record types that exist
      osMemcpy(record->rdata + n, bitmap, bitmapLen);

      //Convert length field to network byte order
      record->rdlength = htons(n + bitmapLen);

      //Number of resource records in the answer section
      message->dnsHeader->ancount++;
      //Update the length of the DNS message
      message->length = offset + n + bitmapLen;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Sort the host records in lexicographical order
 * @param[in] context Pointer to the mDNS responder context
 * @param[in] record Pointer to the current record
 * @return Pointer to the next record, if any
 **/

DnsResourceRecord *mdnsResponderGetNextHostRecord(MdnsResponderContext *context,
   DnsResourceRecord *record)
{
   uint_t i;
   int_t res;
   DnsResourceRecord *curRecord;
   DnsResourceRecord *nextRecord;

   //Initialize record pointer
   nextRecord = NULL;

#if (IPV4_SUPPORT == ENABLED)
   //Loop through the list of IPv4 addresses assigned to the interface
   for(i = 0; i < IPV4_ADDR_LIST_SIZE; i++)
   {
      //Valid IPv4 address?
      if(context->ipv4AddrList[i].valid)
      {
         //Point to the A resource record
         curRecord = (DnsResourceRecord *) &context->ipv4AddrList[i].record;

         //Perform lexicographical comparison
         if(record != NULL)
         {
            res = mdnsCompareRecord(NULL, curRecord, NULL, record);
         }
         else
         {
            res = 1;
         }

         //Check whether the record is lexicographically later
         if(res > 0)
         {
            if(nextRecord == NULL)
            {
               nextRecord = curRecord;
            }
            else if(mdnsCompareRecord(NULL, curRecord, NULL, nextRecord) < 0)
            {
               nextRecord = curRecord;
            }
         }
      }
   }
#endif

#if (IPV6_SUPPORT == ENABLED)
   //Loop through the list of IPv6 addresses assigned to the interface
   for(i = 0; i < IPV6_ADDR_LIST_SIZE; i++)
   {
      //Valid IPv6 address?
      if(context->ipv6AddrList[i].valid)
      {
         //Point to the AAAA resource record
         curRecord = (DnsResourceRecord *) &context->ipv6AddrList[i].record;

         //Perform lexicographical comparison
         if(record != NULL)
         {
            res = mdnsCompareRecord(NULL, curRecord, NULL, record);
         }
         else
         {
            res = 1;
         }

         //Check whether the record is lexicographically later
         if(res > 0)
         {
            if(nextRecord == NULL)
            {
               nextRecord = curRecord;
            }
            else if(mdnsCompareRecord(NULL, curRecord, NULL, nextRecord) < 0)
            {
               nextRecord = curRecord;
            }
         }
      }
   }
#endif

   //Return the pointer to the next record
   return nextRecord;
}


/**
 * @brief Sort the tiebreaker records in lexicographical order
 * @param[in] context Pointer to the mDNS responder context
 * @param[in] query Incoming mDNS query message
 * @param[in] offset Offset to first byte of the Authority Section
 * @param[in] record Pointer to the current record
 * @return Pointer to the next record, if any
 **/

DnsResourceRecord *mdnsResponderGetNextTiebreakerRecord(MdnsResponderContext *context,
   const MdnsMessage *query, size_t offset, DnsResourceRecord *record)
{
   uint_t i;
   size_t n;
   int_t res;
   DnsResourceRecord *curRecord;
   DnsResourceRecord *nextRecord;

   //Initialize record pointer
   nextRecord = NULL;

   //Parse Authority Section
   for(i = 0; i < ntohs(query->dnsHeader->nscount); i++)
   {
      //Parse resource record name
      n = dnsParseName(query->dnsHeader, query->length, offset, NULL, 0);
      //Invalid name?
      if(!n)
         break;

      //Point to the associated resource record
      curRecord = DNS_GET_RESOURCE_RECORD(query->dnsHeader, n);
      //Point to the resource data
      n += sizeof(DnsResourceRecord);

      //Make sure the resource record is valid
      if(n > query->length)
         break;
      if((n + ntohs(curRecord->rdlength)) > query->length)
         break;

      //Matching host name?
      if(!mdnsCompareName(query->dnsHeader, query->length, offset,
         context->hostname, "", ".local", 0))
      {
         //Perform lexicographical comparison
         if(record != NULL)
         {
            res = mdnsCompareRecord(query, curRecord, query, record);
         }
         else
         {
            res = 1;
         }

         //Check whether the record is lexicographically later
         if(res > 0)
         {
            if(nextRecord == NULL)
            {
               nextRecord = curRecord;
            }
            else if(mdnsCompareRecord(query, curRecord, query, nextRecord) < 0)
            {
               nextRecord = curRecord;
            }
         }
      }

      //Point to the next resource record
      offset = n + ntohs(curRecord->rdlength);
   }

   //Return the pointer to the next record
   return nextRecord;
}

#endif

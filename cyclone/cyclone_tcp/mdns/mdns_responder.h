/**
 * @file mdns_responder.h
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

#ifndef _MDNS_RESPONDER_H
#define _MDNS_RESPONDER_H

//Dependencies
#include "core/net.h"
#include "core/udp.h"
#include "dns/dns_common.h"
#include "mdns/mdns_common.h"

//mDNS responder support
#ifndef MDNS_RESPONDER_SUPPORT
   #define MDNS_RESPONDER_SUPPORT DISABLED
#elif (MDNS_RESPONDER_SUPPORT != ENABLED && MDNS_RESPONDER_SUPPORT != DISABLED)
   #error MDNS_RESPONDER_SUPPORT parameter is not valid
#endif

//mDNS responder tick interval
#ifndef MDNS_RESPONDER_TICK_INTERVAL
   #define MDNS_RESPONDER_TICK_INTERVAL 250
#elif (MDNS_RESPONDER_TICK_INTERVAL < 10)
   #error MDNS_RESPONDER_TICK_INTERVAL parameter is not valid
#endif

//Maximum length of host name
#ifndef MDNS_RESPONDER_MAX_HOSTNAME_LEN
   #define MDNS_RESPONDER_MAX_HOSTNAME_LEN 32
#elif (MDNS_RESPONDER_MAX_HOSTNAME_LEN < 1)
   #error MDNS_RESPONDER_MAX_HOSTNAME_LEN parameter is not valid
#endif

//Initial delay
#ifndef MDNS_INIT_DELAY
   #define MDNS_INIT_DELAY 1000
#elif (MDNS_INIT_DELAY < 0)
   #error MDNS_INIT_DELAY parameter is not valid
#endif

//Initial random delay (minimum value)
#ifndef MDNS_RAND_DELAY_MIN
   #define MDNS_RAND_DELAY_MIN 0
#elif (MDNS_RAND_DELAY_MIN < 0)
   #error MDNS_RAND_DELAY_MIN parameter is not valid
#endif

//Initial random delay (maximum value)
#ifndef MDNS_RAND_DELAY_MAX
   #define MDNS_RAND_DELAY_MAX 250
#elif (MDNS_RAND_DELAY_MAX < 0)
   #error MDNS_RAND_DELAY_MAX parameter is not valid
#endif

//Number of probe packets
#ifndef MDNS_PROBE_NUM
   #define MDNS_PROBE_NUM 3
#elif (MDNS_PROBE_NUM < 1)
   #error MDNS_PROBE_NUM parameter is not valid
#endif

//Time interval between subsequent probe packets
#ifndef MDNS_PROBE_DELAY
   #define MDNS_PROBE_DELAY 250
#elif (MDNS_PROBE_DELAY < 100)
   #error MDNS_PROBE_DELAY parameter is not valid
#endif

//Delay before probing again after any failed probe attempt
#ifndef MDNS_PROBE_CONFLICT_DELAY
   #define MDNS_PROBE_CONFLICT_DELAY 1000
#elif (MDNS_PROBE_CONFLICT_DELAY < 100)
   #error MDNS_PROBE_CONFLICT_DELAY parameter is not valid
#endif

//Delay before probing again when deferring to the winning host
#ifndef MDNS_PROBE_DEFER_DELAY
   #define MDNS_PROBE_DEFER_DELAY 1000
#elif (MDNS_PROBE_DEFER_DELAY < 100)
   #error MDNS_PROBE_DEFER_DELAY parameter is not valid
#endif

//Number of announcement packets
#ifndef MDNS_ANNOUNCE_NUM
   #define MDNS_ANNOUNCE_NUM 2
#elif (MDNS_ANNOUNCE_NUM < 1)
   #error MDNS_ANNOUNCE_NUM parameter is not valid
#endif

//Time interval between subsequent announcement packets
#ifndef MDNS_ANNOUNCE_DELAY
   #define MDNS_ANNOUNCE_DELAY 1000
#elif (MDNS_ANNOUNCE_DELAY < 100)
   #error MDNS_ANNOUNCE_DELAY parameter is not valid
#endif

//Forward declaration of DnsSdContext structure
struct _MdnsResponderContext;
#define MdnsResponderContext struct _MdnsResponderContext

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief mDNS responder states
 **/

typedef enum
{
   MDNS_STATE_INIT       = 0,
   MDNS_STATE_WAITING    = 1,
   MDNS_STATE_PROBING    = 2,
   MDNS_STATE_ANNOUNCING = 3,
   MDNS_STATE_IDLE       = 4
} MdnsState;


/**
 * @brief FSM state change callback
 **/

typedef void (*MdnsResponderStateChangeCallback)(MdnsResponderContext *context,
   NetInterface *interface, MdnsState state);


/**
 * @brief IPv4 address entry
 **/

typedef struct
{
   bool_t valid;                                          ///<Valid entry
   DnsIpv4AddrResourceRecord record;                      ///<A resource record
   char_t reverseName[DNS_MAX_IPV4_REVERSE_NAME_LEN + 1]; ///<Reverse DNS lookup for IPv4
} MdnsIpv4AddrEntry;


/**
 * @brief IPv6 address entry
 **/

typedef struct
{
   bool_t valid;                                          ///<Valid entry
   DnsIpv6AddrResourceRecord record;                      ///<AAAA resource record
   char_t reverseName[DNS_MAX_IPV6_REVERSE_NAME_LEN + 1]; ///<Reverse DNS lookup for IPv6
} MdnsIpv6AddrEntry;


/**
 * @brief mDNS responder settings
 **/

typedef struct
{
   NetInterface *interface;                           ///<Underlying network interface
   uint_t numAnnouncements;                           ///<Number of announcement packets
   uint32_t ttl;                                      ///<TTL resource record
   MdnsResponderStateChangeCallback stateChangeEvent; ///<FSM state change event
} MdnsResponderSettings;


/**
 * @brief mDNS responder context
 **/

struct _MdnsResponderContext
{
   MdnsResponderSettings settings;                            ///<DNS-SD settings
   bool_t running;                                            ///<mDNS responder is currently running
   MdnsState state;                                           ///<FSM state
   bool_t conflict;                                           ///<Conflict detected
   bool_t tieBreakLost;                                       ///<Tie-break lost
   systime_t timestamp;                                       ///<Timestamp to manage retransmissions
   systime_t timeout;                                         ///<Timeout value
   uint_t retransmitCount;                                    ///<Retransmission counter
   char_t hostname[MDNS_RESPONDER_MAX_HOSTNAME_LEN + 1];      ///<Host name
   bool_t ipv4AddrCount;                                      ///<Number of valid IPv4 addresses
   bool_t ipv6AddrCount;                                      ///<Number of valid IPv6 addresses
#if (IPV4_SUPPORT == ENABLED)
   MdnsIpv4AddrEntry ipv4AddrList[IPV4_ADDR_LIST_SIZE];       ///<IPv4 address list
   MdnsMessage ipv4Response;                                  ///<IPv4 response message
#endif
#if (IPV6_SUPPORT == ENABLED)
   MdnsIpv6AddrEntry ipv6AddrList[IPV6_ADDR_LIST_SIZE];       ///<IPv6 address list
   MdnsMessage ipv6Response;                                  ///<IPv6 response message
#endif
};


//Tick counter to handle periodic operations
extern systime_t mdnsResponderTickCounter;

//mDNS related functions
void mdnsResponderGetDefaultSettings(MdnsResponderSettings *settings);

error_t mdnsResponderInit(MdnsResponderContext *context,
   const MdnsResponderSettings *settings);

error_t mdnsResponderStart(MdnsResponderContext *context);
error_t mdnsResponderStop(MdnsResponderContext *context);
MdnsState mdnsResponderGetState(MdnsResponderContext *context);

error_t mdnsResponderSetHostname(MdnsResponderContext *context,
   const char_t *hostname);

error_t mdnsResponderStartProbing(MdnsResponderContext *context);

void mdnsResponderTick(MdnsResponderContext *context);
void mdnsResponderLinkChangeEvent(MdnsResponderContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

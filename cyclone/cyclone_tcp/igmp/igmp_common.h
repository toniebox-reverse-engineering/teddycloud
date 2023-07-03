/**
 * @file igmp_common.h
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

#ifndef _IGMP_COMMON_H
#define _IGMP_COMMON_H

//Dependencies
#include "core/net.h"

//IGMP tick interval
#ifndef IGMP_TICK_INTERVAL
   #define IGMP_TICK_INTERVAL 1000
#elif (IGMP_TICK_INTERVAL < 10)
   #error IGMP_TICK_INTERVAL parameter is not valid
#endif

//Robustness Variable
#ifndef IGMP_ROBUSTNESS_VARIABLE
   #define IGMP_ROBUSTNESS_VARIABLE 2
#elif (IGMP_ROBUSTNESS_VARIABLE < 1)
   #error IGMP_ROBUSTNESS_VARIABLE parameter is not valid
#endif

//Query Interval
#ifndef IGMP_QUERY_INTERVAL
   #define IGMP_QUERY_INTERVAL 125000
#elif (IGMP_QUERY_INTERVAL < 1000)
   #error IGMP_QUERY_INTERVAL parameter is not valid
#endif

//Query Response Interval
#ifndef IGMP_QUERY_RESPONSE_INTERVAL
   #define IGMP_QUERY_RESPONSE_INTERVAL 10000
#elif (IGMP_QUERY_RESPONSE_INTERVAL < 1000 || IGMP_QUERY_RESPONSE_INTERVAL > IGMP_QUERY_INTERVAL)
   #error IGMP_QUERY_RESPONSE_INTERVAL parameter is not valid
#endif

//Group Membership Interval
#define IGMP_GROUP_MEMBERSHIP_INTERVAL ((IGMP_ROBUSTNESS_VARIABLE * \
   IGMP_QUERY_INTERVAL) + IGMP_QUERY_RESPONSE_INTERVAL)

//Other Querier Present Interval
#define IGMP_OTHER_QUERIER_PRESENT_INTERVAL ((IGMP_ROBUSTNESS_VARIABLE * \
   IGMP_QUERY_INTERVAL) + (IGMP_QUERY_RESPONSE_INTERVAL / 2))

//Startup Query Interval
#ifndef IGMP_STARTUP_QUERY_INTERVAL
   #define IGMP_STARTUP_QUERY_INTERVAL (IGMP_QUERY_INTERVAL / 4)
#elif (IGMP_STARTUP_QUERY_INTERVAL < 1000)
   #error IGMP_STARTUP_QUERY_INTERVAL parameter is not valid
#endif

//Startup Query Count
#ifndef IGMP_STARTUP_QUERY_COUNT
   #define IGMP_STARTUP_QUERY_COUNT IGMP_ROBUSTNESS_VARIABLE
#elif (IGMP_STARTUP_QUERY_COUNT < 1)
   #error IGMP_STARTUP_QUERY_COUNT parameter is not valid
#endif

//Last Member Query Interval
#ifndef IGMP_LAST_MEMBER_QUERY_INTERVAL
   #define IGMP_LAST_MEMBER_QUERY_INTERVAL 1000
#elif (IGMP_LAST_MEMBER_QUERY_INTERVAL < 100)
   #error IGMP_LAST_MEMBER_QUERY_INTERVAL parameter is not valid
#endif

//Last Member Query Count
#ifndef IGMP_LAST_MEMBER_QUERY_COUNT
   #define IGMP_LAST_MEMBER_QUERY_COUNT IGMP_ROBUSTNESS_VARIABLE
#elif (IGMP_LAST_MEMBER_QUERY_COUNT < 1)
   #error IGMP_LAST_MEMBER_QUERY_COUNT parameter is not valid
#endif

//Last Member Query Time
#define IGMP_LAST_MEMBER_QUERY_TIME (IGMP_LAST_MEMBER_QUERY_COUNT * \
   IGMP_LAST_MEMBER_QUERY_INTERVAL)

//Unsolicited Report Interval
#ifndef IGMP_UNSOLICITED_REPORT_INTERVAL
   #define IGMP_UNSOLICITED_REPORT_INTERVAL 10000
#elif (IGMP_UNSOLICITED_REPORT_INTERVAL < 1000)
   #error IGMP_UNSOLICITED_REPORT_INTERVAL parameter is not valid
#endif

//Version 1 Router Present Timeout
#ifndef IGMP_V1_ROUTER_PRESENT_TIMEOUT
   #define IGMP_V1_ROUTER_PRESENT_TIMEOUT 400000
#elif (IGMP_V1_ROUTER_PRESENT_TIMEOUT < 1000)
   #error IGMP_V1_ROUTER_PRESENT_TIMEOUT parameter is not valid
#endif

//Maximum response time for IGMPv1 queries
#ifndef IGMP_V1_MAX_RESPONSE_TIME
   #define IGMP_V1_MAX_RESPONSE_TIME 10000
#elif (IGMP_V1_MAX_RESPONSE_TIME < 1000)
   #error IGMP_V1_MAX_RESPONSE_TIME parameter is not valid
#endif

//TTL used by IGMP messages
#define IGMP_TTL 1

//All-Systems address
#define IGMP_ALL_SYSTEMS_ADDR IPV4_ADDR(224, 0, 0, 1)
//All-Routers address
#define IGMP_ALL_ROUTERS_ADDR IPV4_ADDR(224, 0, 0, 2)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief IGMP message type
 **/

typedef enum
{
   IGMP_TYPE_MEMBERSHIP_QUERY     = 0x11,
   IGMP_TYPE_MEMBERSHIP_REPORT_V1 = 0x12,
   IGMP_TYPE_MEMBERSHIP_REPORT_V2 = 0x16,
   IGMP_TYPE_LEAVE_GROUP          = 0x17,
   IGMP_TYPE_MEMBERSHIP_REPORT_V3 = 0x22
} IgmpType;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief General IGMP message format
 **/

typedef __start_packed struct
{
   uint8_t type;        //0
   uint8_t maxRespTime; //1
   uint16_t checksum;   //2-3
   Ipv4Addr groupAddr;  //4-7
} __end_packed IgmpMessage;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//Tick counter to handle periodic operations
extern systime_t igmpTickCounter;

//IGMP related functions
error_t igmpInit(NetInterface *interface);
void igmpTick(NetInterface *interface);
void igmpLinkChangeEvent(NetInterface *interface);

error_t igmpSendMessage(NetInterface *interface, Ipv4Addr destAddr,
   const IgmpMessage *message, size_t length);

void igmpProcessMessage(NetInterface *interface,
   Ipv4PseudoHeader *pseudoHeader, const NetBuffer *buffer,
   size_t offset, NetRxAncillary *ancillary);

void igmpDumpMessage(const IgmpMessage *message);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

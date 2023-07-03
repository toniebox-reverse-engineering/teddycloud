/**
 * @file dhcp_client.h
 * @brief DHCP client (Dynamic Host Configuration Protocol)
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

#ifndef _DHCP_CLIENT_H
#define _DHCP_CLIENT_H

//Dependencies
#include "core/net.h"
#include "core/socket.h"
#include "core/udp.h"
#include "dhcp/dhcp_common.h"

//DHCP client support
#ifndef DHCP_CLIENT_SUPPORT
   #define DHCP_CLIENT_SUPPORT ENABLED
#elif (DHCP_CLIENT_SUPPORT != ENABLED && DHCP_CLIENT_SUPPORT != DISABLED)
   #error DHCP_CLIENT_SUPPORT parameter is not valid
#endif

//DHCP client tick interval
#ifndef DHCP_CLIENT_TICK_INTERVAL
   #define DHCP_CLIENT_TICK_INTERVAL 200
#elif (DHCP_CLIENT_TICK_INTERVAL < 10)
   #error DHCP_CLIENT_TICK_INTERVAL parameter is not valid
#endif

//Random delay before sending the first message
#ifndef DHCP_CLIENT_INIT_DELAY
   #define DHCP_CLIENT_INIT_DELAY 2000
#elif (DHCP_CLIENT_INIT_DELAY < 0)
   #error DHCP_CLIENT_INIT_DELAY parameter is not valid
#endif

//Initial retransmission timeout (DHCPDISCOVER)
#ifndef DHCP_CLIENT_DISCOVER_INIT_RT
   #define DHCP_CLIENT_DISCOVER_INIT_RT 4000
#elif (DHCP_CLIENT_DISCOVER_INIT_RT < 1000)
   #error DHCP_CLIENT_DISCOVER_INIT_RT parameter is not valid
#endif

//Maximum retransmission timeout (DHCPDISCOVER)
#ifndef DHCP_CLIENT_DISCOVER_MAX_RT
   #define DHCP_CLIENT_DISCOVER_MAX_RT 16000
#elif (DHCP_CLIENT_DISCOVER_MAX_RT < 1000)
   #error DHCP_CLIENT_DISCOVER_MAX_RT parameter is not valid
#endif

//Maximum retransmission count (DHCPREQUEST)
#ifndef DHCP_CLIENT_REQUEST_MAX_RC
   #define DHCP_CLIENT_REQUEST_MAX_RC 4
#elif (DHCP_CLIENT_REQUEST_MAX_RC < 1)
   #error DHCP_CLIENT_REQUEST_MAX_RC parameter is not valid
#endif

//Initial retransmission timeout (DHCPREQUEST)
#ifndef DHCP_CLIENT_REQUEST_INIT_RT
   #define DHCP_CLIENT_REQUEST_INIT_RT 4000
#elif (DHCP_CLIENT_REQUEST_INIT_RT < 1000)
   #error DHCP_CLIENT_REQUEST_INIT_RT parameter is not valid
#endif

//Maximum retransmission timeout (DHCPREQUEST)
#ifndef DHCP_CLIENT_REQUEST_MAX_RT
   #define DHCP_CLIENT_REQUEST_MAX_RT 64000
#elif (DHCP_CLIENT_REQUEST_MAX_RT < 1000)
   #error DHCP_CLIENT_REQUEST_MAX_RT parameter is not valid
#endif

//Minimum delay between DHCPREQUEST messages in RENEWING and REBINDING states
#ifndef DHCP_CLIENT_REQUEST_MIN_DELAY
   #define DHCP_CLIENT_REQUEST_MIN_DELAY 60000
#elif (DHCP_CLIENT_REQUEST_MIN_DELAY < 1000)
   #error DHCP_CLIENT_REQUEST_MIN_DELAY parameter is not valid
#endif

//Number of probe packets
#ifndef DHCP_CLIENT_PROBE_NUM
   #define DHCP_CLIENT_PROBE_NUM 1
#elif (DHCP_CLIENT_PROBE_NUM < 0)
   #error DHCP_CLIENT_PROBE_NUM parameter is not valid
#endif

//Delay until repeated probe
#ifndef DHCP_CLIENT_PROBE_DELAY
   #define DHCP_CLIENT_PROBE_DELAY 1000
#elif (DHCP_CLIENT_PROBE_DELAY < 100)
   #error DHCP_CLIENT_PROBE_DELAY parameter is not valid
#endif

//Number of announcement packets
#ifndef DHCP_CLIENT_ANNOUNCE_NUM
   #define DHCP_CLIENT_ANNOUNCE_NUM 1
#elif (DHCP_CLIENT_ANNOUNCE_NUM < 0)
   #error DHCP_CLIENT_ANNOUNCE_NUM parameter is not valid
#endif

//Time between announcement packets
#ifndef DHCP_CLIENT_ANNOUNCE_INTERVAL
   #define DHCP_CLIENT_ANNOUNCE_INTERVAL 1000
#elif (DHCP_CLIENT_ANNOUNCE_INTERVAL < 100)
   #error DHCP_CLIENT_ANNOUNCE_INTERVAL parameter is not valid
#endif

//Random factor used to determine the delay between retransmissions
#ifndef DHCP_CLIENT_RAND_FACTOR
   #define DHCP_CLIENT_RAND_FACTOR 1000
#elif (DHCP_CLIENT_RAND_FACTOR < 100)
   #error DHCP_CLIENT_RAND_FACTOR parameter is not valid
#endif

//Application specific context
#ifndef DHCP_CLIENT_PRIVATE_CONTEXT
   #define DHCP_CLIENT_PRIVATE_CONTEXT
#endif

//Forward declaration of DhcpClientContext structure
struct _DhcpClientContext;
#define DhcpClientContext struct _DhcpClientContext

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief DHCP FSM states
 **/

typedef enum
{
   DHCP_STATE_INIT        = 0,
   DHCP_STATE_SELECTING   = 1,
   DHCP_STATE_REQUESTING  = 2,
   DHCP_STATE_INIT_REBOOT = 3,
   DHCP_STATE_REBOOTING   = 4,
   DHCP_STATE_PROBING     = 5,
   DHCP_STATE_ANNOUNCING  = 6,
   DHCP_STATE_BOUND       = 7,
   DHCP_STATE_RENEWING    = 8,
   DHCP_STATE_REBINDING   = 9
} DhcpState;


/**
 * @brief DHCP configuration timeout callback
 **/

typedef void (*DhcpTimeoutCallback)(DhcpClientContext *context,
   NetInterface *interface);


/**
 * @brief Link state change callback
 **/

typedef void (*DhcpLinkChangeCallback)(DhcpClientContext *context,
   NetInterface *interface, bool_t linkState);


/**
 * @brief FSM state change callback
 **/

typedef void (*DhcpStateChangeCallback)(DhcpClientContext *context,
   NetInterface *interface, DhcpState state);


/**
 * @brief Add DHCP options callback
 **/

typedef void (*DhcpAddOptionsCallback)(DhcpClientContext *context,
   DhcpMessage *message, size_t *length, DhcpMessageType type);


/**
 * @brief Parse DHCP options callback
 **/

typedef error_t (*DhcpParseOptionsCallback)(DhcpClientContext *context,
   const DhcpMessage *message, size_t length, DhcpMessageType type);


/**
 * @brief DHCP client settings
 **/

typedef struct
{
   NetInterface *interface;                       ///<Network interface to configure
   uint_t ipAddrIndex;                            ///<Index of the IP address to be configured
   bool_t rapidCommit;                            ///<Quick configuration using rapid commit
   bool_t manualDnsConfig;                        ///<Force manual DNS configuration
   systime_t timeout;                             ///<DHCP configuration timeout
   DhcpTimeoutCallback timeoutEvent;              ///<DHCP configuration timeout event
   DhcpLinkChangeCallback linkChangeEvent;        ///<Link state change event
   DhcpStateChangeCallback stateChangeEvent;      ///<FSM state change event
   DhcpAddOptionsCallback addOptionsCallback;     ///<Add DHCP options callback
   DhcpParseOptionsCallback parseOptionsCallback; ///<Parse DHCP options callback
} DhcpClientSettings;


/**
 * @brief DHCP client context
 **/

struct _DhcpClientContext
{
   DhcpClientSettings settings; ///<DHCP client settings
   bool_t running;              ///<This flag tells whether the DHCP client is running or not
   DhcpState state;             ///<Current state of the FSM
   bool_t timeoutEventDone;     ///<Timeout callback function has been called
   systime_t timestamp;         ///<Timestamp to manage retransmissions
   systime_t timeout;           ///<Timeout value
   systime_t retransmitTimeout; ///<Retransmission timeout
   uint_t retransmitCount;      ///<Retransmission counter
   Ipv4Addr serverIpAddr;       ///<DHCP server IPv4 address
   Ipv4Addr requestedIpAddr;    ///<Requested IPv4 address
   uint32_t transactionId;      ///<Value to match requests with replies
   systime_t configStartTime;   ///<Address acquisition or renewal process start time
   systime_t leaseStartTime;    ///<Lease start time
   uint32_t leaseTime;          ///<Lease time
   uint32_t t1;                 ///<Time at which the client enters the RENEWING state
   uint32_t t2;                 ///<Time at which the client enters the REBINDING state
   DHCP_CLIENT_PRIVATE_CONTEXT  ///<Application specific context
};


//DHCP client related functions
void dhcpClientGetDefaultSettings(DhcpClientSettings *settings);

error_t dhcpClientInit(DhcpClientContext *context,
   const DhcpClientSettings *settings);

error_t dhcpClientStart(DhcpClientContext *context);
error_t dhcpClientStop(DhcpClientContext *context);

error_t dhcpClientRelease(DhcpClientContext *context);
DhcpState dhcpClientGetState(DhcpClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

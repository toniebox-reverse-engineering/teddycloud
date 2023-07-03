/**
 * @file dhcpv6_client_misc.h
 * @brief Helper functions for DHCPv6 client
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

#ifndef _DHCPV6_CLIENT_MISC_H
#define _DHCPV6_CLIENT_MISC_H

//Dependencies
#include "core/net.h"
#include "dhcpv6/dhcpv6_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Tick counter to handle periodic operations
extern systime_t dhcpv6ClientTickCounter;

//DHCPv6 client related functions
void dhcpv6ClientTick(Dhcpv6ClientContext *context);
void dhcpv6ClientLinkChangeEvent(Dhcpv6ClientContext *context);

error_t dhcpv6ClientSendMessage(Dhcpv6ClientContext *context,
   Dhcpv6MessageType type);

void dhcpv6ClientProcessMessage(NetInterface *interface,
   const IpPseudoHeader *pseudoHeader, const UdpHeader *udpHeader,
   const NetBuffer *buffer, size_t offset, const NetRxAncillary *ancillary,
   void *param);

void dhcpv6ClientParseAdvertise(Dhcpv6ClientContext *context,
   const Dhcpv6Message *message, size_t length);

void dhcpv6ClientParseReply(Dhcpv6ClientContext *context,
   const Dhcpv6Message *message, size_t length);

error_t dhcpv6ClientParseIaNaOption(Dhcpv6ClientContext *context,
   const Dhcpv6Option *option);

error_t dhcpv6ClientParseIaAddrOption(Dhcpv6ClientContext *context,
   const Dhcpv6Option *option);

void dhcpv6ClientAddAddr(Dhcpv6ClientContext *context, const Ipv6Addr *addr,
   uint32_t validLifetime, uint32_t preferredLifetime);

void dhcpv6ClientRemoveAddr(Dhcpv6ClientContext *context, const Ipv6Addr *addr);

void dhcpv6ClientFlushAddrList(Dhcpv6ClientContext *context);

error_t dhcpv6ClientGenerateDuid(Dhcpv6ClientContext *context);
error_t dhcpv6ClientGenerateLinkLocalAddr(Dhcpv6ClientContext *context);

bool_t dhcpv6ClientCheckServerId(Dhcpv6ClientContext *context,
   Dhcpv6Option *serverIdOption);

void dhcpv6ClientCheckTimeout(Dhcpv6ClientContext *context);

uint16_t dhcpv6ClientComputeElapsedTime(Dhcpv6ClientContext *context);

void dhcpv6ClientChangeState(Dhcpv6ClientContext *context,
   Dhcpv6State newState, systime_t delay);

void dhcpv6ClientDumpConfig(Dhcpv6ClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

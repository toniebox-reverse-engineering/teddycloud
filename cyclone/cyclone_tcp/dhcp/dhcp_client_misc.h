/**
 * @file dhcp_client_misc.h
 * @brief Helper functions for DHCP client
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

#ifndef _DHCP_CLIENT_MISC_H
#define _DHCP_CLIENT_MISC_H

//Dependencies
#include "core/net.h"
#include "dhcp/dhcp_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Tick counter to handle periodic operations
extern systime_t dhcpClientTickCounter;

//DHCP client related functions
void dhcpClientTick(DhcpClientContext *context);
void dhcpClientLinkChangeEvent(DhcpClientContext *context);

error_t dhcpClientSendDiscover(DhcpClientContext *context);
error_t dhcpClientSendRequest(DhcpClientContext *context);
error_t dhcpClientSendDecline(DhcpClientContext *context);
error_t dhcpClientSendRelease(DhcpClientContext *context);

void dhcpClientProcessMessage(NetInterface *interface,
   const IpPseudoHeader *pseudoHeader, const UdpHeader *udpHeader,
   const NetBuffer *buffer, size_t offset, const NetRxAncillary *ancillary,
   void *param);

void dhcpClientParseOffer(DhcpClientContext *context,
   const DhcpMessage *message, size_t length);

void dhcpClientParseAck(DhcpClientContext *context,
   const DhcpMessage *message, size_t length);

void dhcpClientParseNak(DhcpClientContext *context,
   const DhcpMessage *message, size_t length);

void dhcpClientCheckTimeout(DhcpClientContext *context);

uint16_t dhcpClientComputeElapsedTime(DhcpClientContext *context);

void dhcpClientChangeState(DhcpClientContext *context,
   DhcpState newState, systime_t delay);

void dhcpClientResetConfig(DhcpClientContext *context);
void dhcpClientDumpConfig(DhcpClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

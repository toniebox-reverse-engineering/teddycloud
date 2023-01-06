/**
 * @file dhcpv6_client_fsm.h
 * @brief DHCPv6 client finite state machine
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

#ifndef _DHCPV6_CLIENT_FSM_H
#define _DHCPV6_CLIENT_FSM_H

//Dependencies
#include "core/net.h"
#include "dhcpv6/dhcpv6_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//DHCPv6 client related functions
void dhcpv6ClientStateInit(Dhcpv6ClientContext *context);
void dhcpv6ClientStateSolicit(Dhcpv6ClientContext *context);
void dhcpv6ClientStateRequest(Dhcpv6ClientContext *context);
void dhcpv6ClientStateInitConfirm(Dhcpv6ClientContext *context);
void dhcpv6ClientStateConfirm(Dhcpv6ClientContext *context);
void dhcpv6ClientStateDad(Dhcpv6ClientContext *context);
void dhcpv6ClientStateBound(Dhcpv6ClientContext *context);
void dhcpv6ClientStateRenew(Dhcpv6ClientContext *context);
void dhcpv6ClientStateRebind(Dhcpv6ClientContext *context);
void dhcpv6ClientStateRelease(Dhcpv6ClientContext *context);
void dhcpv6ClientStateDecline(Dhcpv6ClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

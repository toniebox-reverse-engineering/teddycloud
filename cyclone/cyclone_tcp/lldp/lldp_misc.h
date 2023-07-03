/**
 * @file lldp_misc.h
 * @brief Helper functions for LLDP
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

#ifndef _LLDP_MISC_H
#define _LLDP_MISC_H

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//LLDP multicast address (refer to IEEE Std 802.1AB-2005, section 8.1)
extern const MacAddr LLDP_MULTICAST_ADDR;

//LLDP agent related functions
void lldpTick(LldpAgentContext *context);

void lldpProcessFrame(LldpAgentContext *context);

error_t lldpCheckDataUnit(LldpPortEntry *port, LldpDataUnit *lldpdu);

LldpNeighborEntry *lldpCreateNeighborEntry(LldpAgentContext *context);

LldpNeighborEntry *lldpFindNeighborEntry(LldpAgentContext *context,
   LldpDataUnit *lldpdu);

void lldpDeleteNeighborEntry(LldpNeighborEntry *entry);

bool_t lldpGetLinkState(LldpAgentContext *context, uint_t portIndex);

error_t lldpAcceptMulticastAddr(LldpAgentContext *context);
error_t lldpDropMulticastAddr(LldpAgentContext *context);

void lldpGeneratePortAddr(LldpPortEntry *port);

error_t lldpGetMsapId(LldpDataUnit *lldpdu, LldpMsapId *msapId);
bool_t lldpCompareMsapId(const LldpMsapId *msapId1, const LldpMsapId *msapId2);

void lldpSomethingChangedLocal(LldpAgentContext *context);
void lldpDecrementTimer(uint_t *x);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

/**
 * @file igmp_snooping_misc.h
 * @brief Helper functions for IGMP snooping switch
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

#ifndef _IGMP_SNOOPING_MISC_H
#define _IGMP_SNOOPING_MISC_H

//Dependencies
#include "core/net.h"
#include "igmp/igmp_snooping.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IGMP snooping related functions
void igmpSnoopingProcessMessage(IgmpSnoopingContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length, NetRxAncillary *ancillary);

void igmpSnoopingProcessMembershipQuery(IgmpSnoopingContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length, NetRxAncillary *ancillary);

void igmpSnoopingProcessMembershipReport(IgmpSnoopingContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length, NetRxAncillary *ancillary);

void igmpSnoopingProcessLeaveGroup(IgmpSnoopingContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length, NetRxAncillary *ancillary);

void igmpSnoopingProcessUnknownMessage(IgmpSnoopingContext *context,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length, NetRxAncillary *ancillary);

error_t igmpSnoopingForwardMessage(IgmpSnoopingContext *context,
   uint32_t forwardPorts, const MacAddr *destMacAddr,
   Ipv4PseudoHeader *pseudoHeader, const IgmpMessage *message,
   size_t length);

IgmpSnoopingGroup *igmpSnoopingCreateGroup(IgmpSnoopingContext *context,
   Ipv4Addr groupAddr, uint8_t port);

IgmpSnoopingGroup *igmpSnoopingFindGroup(IgmpSnoopingContext *context,
   Ipv4Addr groupAddr, uint8_t port);

void igmpSnoopingDeleteGroup(IgmpSnoopingContext *context,
   IgmpSnoopingGroup *group);

void igmpSnoopingEnableMonitoring(IgmpSnoopingContext *context, bool_t enable);

void igmpSnoopingUpdateStaticFdbEntry(IgmpSnoopingContext *context,
   Ipv4Addr groupAddr);

void igmpSnoopingSetUnknownMcastFwdPorts(IgmpSnoopingContext *context,
   bool_t enable, uint32_t forwardPorts);

uint32_t igmpSnoopingGetRouterPorts(IgmpSnoopingContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

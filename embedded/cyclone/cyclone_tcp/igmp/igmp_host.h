/**
 * @file igmp_host.h
 * @brief IGMP host
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

#ifndef _IGMP_HOST_H
#define _IGMP_HOST_H

//Dependencies
#include "core/net.h"
#include "igmp/igmp_common.h"

//IGMP host support
#ifndef IGMP_HOST_SUPPORT
   #define IGMP_HOST_SUPPORT ENABLED
#elif (IGMP_HOST_SUPPORT != ENABLED && IGMP_HOST_SUPPORT != DISABLED)
   #error IGMP_HOST_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Multicast group states
 **/

typedef enum
{
   IGMP_HOST_GROUP_STATE_NON_MEMBER      = 0,
   IGMP_HOST_GROUP_STATE_DELAYING_MEMBER = 1,
   IGMP_HOST_GROUP_STATE_IDLE_MEMBER     = 2
} IgmpHostGroupState;


/**
 * @brief IGMP host context
 **/

typedef struct
{
   bool_t igmpv1RouterPresent; ///<An IGMPv1 query has been recently heard
   NetTimer timer;             ///<IGMPv1 router present timer
} IgmpHostContext;


//IGMP host related functions
error_t igmpHostInit(NetInterface *interface);
error_t igmpHostJoinGroup(NetInterface *interface, Ipv4FilterEntry *entry);
error_t igmpHostLeaveGroup(NetInterface *interface, Ipv4FilterEntry *entry);

void igmpHostTick(NetInterface *interface);
void igmpHostLinkChangeEvent(NetInterface *interface);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

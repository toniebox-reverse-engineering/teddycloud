/**
 * @file igmp_snooping.h
 * @brief IGMP snooping switch
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

#ifndef _IGMP_SNOOPING_H
#define _IGMP_SNOOPING_H

//Dependencies
#include "core/net.h"
#include "igmp/igmp_common.h"

//IGMP snooping support
#ifndef IGMP_SNOOPING_SUPPORT
   #define IGMP_SNOOPING_SUPPORT DISABLED
#elif (IGMP_SNOOPING_SUPPORT != ENABLED && IGMP_SNOOPING_SUPPORT != DISABLED)
   #error IGMP_SNOOPING_SUPPORT parameter is not valid
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
   IGMP_SNOOPING_GROUP_STATE_NO_MEMBERS_PRESENT  = 0,
   IGMP_SNOOPING_GROUP_STATE_MEMBERS_PRESENT     = 1,
   IGMP_SNOOPING_GROUP_STATE_CHECKING_MEMBERSHIP = 2
} IgmpSnoopingGroupState;


/**
 * @brief Snooping switch port
 **/

typedef struct
{
   bool_t routerPresent;
   NetTimer timer;
} IgmpSnoopingPort;


/**
 * @brief Multicast group
 **/

typedef struct
{
   IgmpSnoopingGroupState state; ///<Multicast group state
   Ipv4Addr addr;                ///<Multicast group address
   uint8_t port;
   NetTimer timer;
} IgmpSnoopingGroup;


/**
 * @brief IGMP snooping settings
 **/

typedef struct
{
   NetInterface *interface;             ///<Underlying network interface
   uint_t numPorts;                     ///<Number of ports
   IgmpSnoopingPort *ports;             ///<Ports
   uint_t numGroups;                    ///<Maximum number of multicast groups
   IgmpSnoopingGroup *groups;           ///<Multicast groups
   bool_t floodReports;                 ///<Flood IGMP report messages to all ports (not only to router ports)
   bool_t floodUnknownMulticastPackets; ///<Flood unregistered multicast traffic to all ports
   systime_t lastMemberQueryTime;       ///<Leave latency
} IgmpSnoopingSettings;


/**
 * @brief IGMP snooping switch context
 **/

typedef struct
{
   bool_t running;
   NetInterface *interface;             ///<The primary interface on an attached network
   uint_t numPorts;                     ///<Number of ports
   IgmpSnoopingPort *ports;             ///<Ports
   uint_t numGroups;                    ///<Maximum number of multicast groups
   IgmpSnoopingGroup *groups;           ///<Multicast groups
   bool_t floodReports;                 ///<Flood IGMP report messages to all ports (not only to router ports)
   bool_t floodUnknownMulticastPackets; ///<Flood unregistered multicast traffic to all ports
   systime_t lastMemberQueryTime;       ///<Leave latency
} IgmpSnoopingContext;


//IGMP snooping related functions
void igmpSnoopingGetDefaultSettings(IgmpSnoopingSettings *settings);

error_t igmpSnoopingInit(IgmpSnoopingContext *context,
   const IgmpSnoopingSettings *settings);

error_t igmpSnoopingStart(IgmpSnoopingContext *context);
error_t igmpSnoopingStop(IgmpSnoopingContext *context);

void igmpSnoopingTick(IgmpSnoopingContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

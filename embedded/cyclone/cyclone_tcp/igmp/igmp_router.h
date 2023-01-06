/**
 * @file igmp_router.h
 * @brief IGMP router
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

#ifndef _IGMP_ROUTER_H
#define _IGMP_ROUTER_H

//Dependencies
#include "core/net.h"
#include "igmp/igmp_common.h"

//IGMP router support
#ifndef IGMP_ROUTER_SUPPORT
   #define IGMP_ROUTER_SUPPORT DISABLED
#elif (IGMP_ROUTER_SUPPORT != ENABLED && IGMP_ROUTER_SUPPORT != DISABLED)
   #error IGMP_ROUTER_SUPPORT parameter is not valid
#endif

//Forward declaration of DhcpClientContext structure
struct _IgmpRouterContext;
#define IgmpRouterContext struct _IgmpRouterContext

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief IGMP versions
 **/

typedef enum
{
   IGMP_VERSION_1 = 1,
   IGMP_VERSION_2 = 2,
   IGMP_VERSION_3 = 3
} IgmpVersion;


/**
 * @brief IGMP router states
 **/

typedef enum
{
   IGMP_ROUTER_STATE_INIT        = 0,
   IGMP_ROUTER_STATE_QUERIER     = 1,
   IGMP_ROUTER_STATE_NON_QUERIER = 2
} IgmpRouterState;


/**
 * @brief Multicast group states
 **/

typedef enum
{
   IGMP_ROUTER_GROUP_STATE_NO_MEMBERS_PRESENT  = 0,
   IGMP_ROUTER_GROUP_STATE_MEMBERS_PRESENT     = 1,
   IGMP_ROUTER_GROUP_STATE_V1_MEMBERS_PRESENT  = 2,
   IGMP_ROUTER_GROUP_STATE_CHECKING_MEMBERSHIP = 3
} IgmpRouterGroupState;


/**
 * @brief Add multicast route callback
 **/

typedef void (*IgmpRouterAddMcastRouteCallback)(IgmpRouterContext *context,
   Ipv4Addr groupAddr, NetInterface *interface);


/**
 * @brief Delete multicast route callback
 **/

typedef void (*IgmpRouterDeleteMcastRouteCallback)(IgmpRouterContext *context,
   Ipv4Addr groupAddr, NetInterface *interface);


/**
 * @brief Multicast group
 **/

typedef struct
{
   IgmpRouterGroupState state;  ///<Multicast group state
   Ipv4Addr addr;               ///<Multicast group address
   uint_t lastMemberQueryCount; ///<Number of Group-Specific Queries to be sent
   NetTimer timer;              ///<Timer for the group membership
   NetTimer v1HostTimer;        ///<IGMPv1 Host timer
   NetTimer retransmitTimer;    ///<Retransmit timer for the group membership
} IgmpRouterGroup;


/**
 * @brief IGMP router settings
 **/

typedef struct
{
   NetInterface *interface;                                     ///<Underlying network interface
   IgmpVersion version;                                         ///<IGMP version
   uint_t numGroups;                                            ///<Maximum number of multicast groups
   IgmpRouterGroup *groups;                                     ///<Multicast groups
   IgmpRouterAddMcastRouteCallback addMcastRouteCallback;       ///<Add multicast route callback
   IgmpRouterDeleteMcastRouteCallback deleteMcastRouteCallback; ///<Delete multicast route callback
} IgmpRouterSettings;


/**
 * @brief IGMP router context
 **/

struct _IgmpRouterContext
{
   NetInterface *interface;                                     ///<The primary interface on an attached network
   IgmpVersion version;                                         ///<IGMP version
   uint_t numGroups;                                            ///<Maximum number of multicast groups
   IgmpRouterGroup *groups;                                     ///<Multicast groups
   IgmpRouterAddMcastRouteCallback addMcastRouteCallback;       ///<Add multicast route callback
   IgmpRouterDeleteMcastRouteCallback deleteMcastRouteCallback; ///<Delete multicast route callback
   bool_t running;                                              ///<IGMP router operation state
   IgmpRouterState state;                                       ///<IGMP router state
   uint_t startupQueryCount;                                    ///<Number of General Queries to be sent on startup
   NetTimer generalQueryTimer;                                  ///<General Query timer
   NetTimer otherQuerierPresentTimer;                           ///<Other Querier Present timer
};


//IGMP router related functions
void igmpRouterGetDefaultSettings(IgmpRouterSettings *settings);

error_t igmpRouterInit(IgmpRouterContext *context,
   const IgmpRouterSettings *settings);

error_t igmpRouterStart(IgmpRouterContext *context);
error_t igmpRouterStop(IgmpRouterContext *context);

void igmpRouterTick(IgmpRouterContext *context);
void igmpRouterFsm(IgmpRouterContext *context);
void igmpRouterGroupFsm(IgmpRouterContext *context, IgmpRouterGroup *group);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

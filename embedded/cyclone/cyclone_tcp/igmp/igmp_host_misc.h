/**
 * @file igmp_host_misc.h
 * @brief Helper functions for IGMP host
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

#ifndef _IGMP_HOST_MISC_H
#define _IGMP_HOST_MISC_H

//Dependencies
#include "core/net.h"
#include "igmp/igmp_host.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IGMP host related functions
error_t igmpHostSendMembershipReport(NetInterface *interface, Ipv4Addr ipAddr);
error_t igmpHostSendLeaveGroup(NetInterface *interface, Ipv4Addr ipAddr);

void igmpHostProcessMessage(NetInterface *interface,
   const IgmpMessage *message, size_t length);

void igmpHostProcessMembershipQuery(NetInterface *interface,
   const IgmpMessage *message, size_t length);

void igmpHostProcessMembershipReport(NetInterface *interface,
   const IgmpMessage *message, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

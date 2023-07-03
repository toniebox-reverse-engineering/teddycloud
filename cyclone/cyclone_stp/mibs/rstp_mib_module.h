/**
 * @file rstp_mib_module.h
 * @brief RSTP MIB module
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSTP Open.
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

#ifndef _RSTP_MIB_MODULE_H
#define _RSTP_MIB_MODULE_H

//Dependencies
#include "mibs/mib_common.h"
#include "rstp/rstp.h"

//RSTP MIB module support
#ifndef RSTP_MIB_SUPPORT
   #define RSTP_MIB_SUPPORT DISABLED
#elif (RSTP_MIB_SUPPORT != ENABLED && RSTP_MIB_SUPPORT != DISABLED)
   #error RSTP_MIB_SUPPORT parameter is not valid
#endif

//Support for SET operations
#ifndef RSTP_MIB_SET_SUPPORT
   #define RSTP_MIB_SET_SUPPORT DISABLED
#elif (RSTP_MIB_SET_SUPPORT != ENABLED && RSTP_MIB_SET_SUPPORT != DISABLED)
   #error RSTP_MIB_SET_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Administrative point-to-point status
 **/

typedef enum
{
   RSTP_MIB_PORT_ADMIN_P2P_FORCE_TRUE  = 0,
   RSTP_MIB_PORT_ADMIN_P2P_FORCE_FALSE = 1,
   RSTP_MIB_PORT_ADMIN_P2P_AUTO        = 2,
} RstpMibPortAdminPointToPoint;


/**
 * @brief RSTP MIB base
 **/

typedef struct
{
   RstpBridgeContext *rstpBridgeContext;
} RstpMibBase;


//RSTP MIB related constants
extern RstpMibBase rstpMibBase;
extern const MibObject rstpMibObjects[];
extern const MibModule rstpMibModule;

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

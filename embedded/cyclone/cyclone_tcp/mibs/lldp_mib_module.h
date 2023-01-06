/**
 * @file lldp_mib_module.h
 * @brief LLDP MIB module
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

#ifndef _LLDP_MIB_MODULE_H
#define _LLDP_MIB_MODULE_H

//Dependencies
#include "mibs/mib_common.h"
#include "lldp/lldp.h"

//LLDP MIB module support
#ifndef LLDP_MIB_SUPPORT
   #define LLDP_MIB_SUPPORT DISABLED
#elif (LLDP_MIB_SUPPORT != ENABLED && LLDP_MIB_SUPPORT != DISABLED)
   #error LLDP_MIB_SUPPORT parameter is not valid
#endif

//Support for SET operations
#ifndef LLDP_MIB_SET_SUPPORT
   #define LLDP_MIB_SET_SUPPORT DISABLED
#elif (LLDP_MIB_SET_SUPPORT != ENABLED && LLDP_MIB_SET_SUPPORT != DISABLED)
   #error LLDP_MIB_SET_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Administrative status
 **/

typedef enum
{
   LLDP_MIB_ADMIN_STATUS_INVALID         = 0,
   LLDP_MIB_ADMIN_STATUS_ENABLED_TX_ONLY = 1,
   LLDP_MIB_ADMIN_STATUS_ENABLED_RX_ONLY = 2,
   LLDP_MIB_ADMIN_STATUS_ENABLED_TX_RX   = 3,
   LLDP_MIB_ADMIN_STATUS_DISABLED        = 4
} LldpMibAdminStatus;


/**
 * @brief Type of interface associated with a management address
 **/

typedef enum
{
   LLDP_MIB_MAN_ADDR_IF_SUBTYPE_UNKNOWN      = 1, ///<Unknown
   LLDP_MIB_MAN_ADDR_IF_SUBTYPE_IF_INDEX     = 2, ///<Interface index
   LLDP_MIB_MAN_ADDR_IF_SUBTYPE_SYS_PORT_NUM = 3  ///<System port number
} LldpMibManAddrIfSubtype;


/**
 * @brief LLDP MIB base
 **/

typedef struct
{
   LldpAgentContext *lldpAgentContext;
} LldpMibBase;


//LLDP MIB related constants
extern LldpMibBase lldpMibBase;
extern const MibObject lldpMibObjects[];
extern const MibModule lldpMibModule;

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

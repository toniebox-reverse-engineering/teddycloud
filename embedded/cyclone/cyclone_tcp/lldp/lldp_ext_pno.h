/**
 * @file lldp_ext_pno.h
 * @brief PROFINET extension
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

#ifndef _LLDP_EXT_PNO_H
#define _LLDP_EXT_PNO_H

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief PROFINET subtypes
 **/

typedef enum
{
   LLDP_PNO_SUBTYPE_RESERVED              = 0, ///<Reserved
   LLDP_PNO_SUBTYPE_MEASURED_DELAY_VALUES = 1, ///<Measured Delay Values
   LLDP_PNO_SUBTYPE_PORT_STATUS           = 2, ///<Port Status
   LLDP_PNO_SUBTYPE_ALIAS                 = 3, ///<Alias
   LLDP_PNO_SUBTYPE_MRP_PORT_STATUS       = 4, ///<MRP Port Status
   LLDP_PNO_SUBTYPE_INTERFACE_MAC_ADDR    = 5, ///<Interface MAC address
   LLDP_PNO_SUBTYPE_PTCP_STATUS           = 6  ///<PTCP Status
} LldpPnoSubtype;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif

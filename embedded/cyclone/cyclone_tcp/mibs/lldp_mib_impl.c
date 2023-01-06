/**
 * @file lldp_mib_impl.c
 * @brief LLDP MIB module implementation
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SNMP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "mibs/mib_common.h"
#include "mibs/lldp_mib_module.h"
#include "mibs/lldp_mib_impl.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "lldp/lldp_mgmt.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_MIB_SUPPORT == ENABLED)


/**
 * @brief LLDP MIB module initialization
 * @return Error code
 **/

error_t lldpMibInit(void)
{
   //Debug message
   TRACE_INFO("Initializing LLDP MIB base...\r\n");

   //Clear LLDP MIB base
   memset(&lldpMibBase, 0, sizeof(lldpMibBase));

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Lock LLDP MIB base
 **/

void lldpMibLock(void)
{
   //Acquire exclusive access to the LLDP agent context
   lldpMgmtLock(lldpMibBase.lldpAgentContext);
}


/**
 * @brief Unlock LLDP MIB base
 **/

void lldpMibUnlock(void)
{
   //Release exclusive access to the LLDP agent context
   lldpMgmtUnlock(lldpMibBase.lldpAgentContext);
}


/**
 * @brief Attach LLDP agent context
 * @param[in] context Pointer to the LLDP agent context
 * @return Error code
 **/

error_t lldpMibSetLldpAgentContext(LldpAgentContext *context)
{
   //Attach LLDP agent context
   lldpMibBase.lldpAgentContext = context;

   //Successful processing
   return NO_ERROR;
}

#endif

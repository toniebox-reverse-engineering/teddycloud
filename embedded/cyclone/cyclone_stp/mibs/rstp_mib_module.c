/**
 * @file rstp_mib_module.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SNMP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "mibs/mib_common.h"
#include "mibs/rstp_mib_module.h"
#include "mibs/rstp_mib_impl.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_MIB_SUPPORT == ENABLED)


/**
 * @brief RSTP MIB base
 **/

RstpMibBase rstpMibBase;


/**
 * @brief RSTP MIB objects
 **/

const MibObject rstpMibObjects[] =
{
   //dot1dStpVersion object (1.3.6.1.2.1.17.2.16)
   {
      "dot1dStpVersion",
      {43, 6, 1, 2, 1, 17, 2, 16},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      rstpMibSetDot1dStpVersion,
      rstpMibGetDot1dStpVersion,
      NULL
   },
   //dot1dStpTxHoldCount object (1.3.6.1.2.1.17.2.17)
   {
      "dot1dStpTxHoldCount",
      {43, 6, 1, 2, 1, 17, 2, 17},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      rstpMibSetDot1dStpTxHoldCount,
      rstpMibGetDot1dStpTxHoldCount,
      NULL
   },
   //dot1dStpPortProtocolMigration object (1.3.6.1.2.1.17.2.19.1.1)
   {
      "dot1dStpPortProtocolMigration",
      {43, 6, 1, 2, 1, 17, 2, 19, 1, 1},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      rstpMibSetDot1dStpExtPortEntry,
      rstpMibGetDot1dStpExtPortEntry,
      rstpMibGetNextDot1dStpExtPortEntry
   },
   //dot1dStpPortAdminEdgePort object (1.3.6.1.2.1.17.2.19.1.2)
   {
      "dot1dStpPortAdminEdgePort",
      {43, 6, 1, 2, 1, 17, 2, 19, 1, 2},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      rstpMibSetDot1dStpExtPortEntry,
      rstpMibGetDot1dStpExtPortEntry,
      rstpMibGetNextDot1dStpExtPortEntry
   },
   //dot1dStpPortOperEdgePort object (1.3.6.1.2.1.17.2.19.1.3)
   {
      "dot1dStpPortOperEdgePort",
      {43, 6, 1, 2, 1, 17, 2, 19, 1, 3},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      rstpMibGetDot1dStpExtPortEntry,
      rstpMibGetNextDot1dStpExtPortEntry
   },
   //dot1dStpPortAdminPointToPoint object (1.3.6.1.2.1.17.2.19.1.4)
   {
      "dot1dStpPortAdminPointToPoint",
      {43, 6, 1, 2, 1, 17, 2, 19, 1, 4},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      rstpMibSetDot1dStpExtPortEntry,
      rstpMibGetDot1dStpExtPortEntry,
      rstpMibGetNextDot1dStpExtPortEntry
   },
   //dot1dStpPortOperPointToPoint object (1.3.6.1.2.1.17.2.19.1.5)
   {
      "dot1dStpPortOperPointToPoint",
      {43, 6, 1, 2, 1, 17, 2, 19, 1, 5},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      rstpMibGetDot1dStpExtPortEntry,
      rstpMibGetNextDot1dStpExtPortEntry
   },
   //dot1dStpPortAdminPathCost object (1.3.6.1.2.1.17.2.19.1.6)
   {
      "dot1dStpPortAdminPathCost",
      {43, 6, 1, 2, 1, 17, 2, 19, 1, 6},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      rstpMibSetDot1dStpExtPortEntry,
      rstpMibGetDot1dStpExtPortEntry,
      rstpMibGetNextDot1dStpExtPortEntry
   }
};


/**
 * @brief RSTP MIB module
 **/

const MibModule rstpMibModule =
{
   "RSTP-MIB",
   {43, 6, 1, 2, 1, 129, 6},
   7,
   rstpMibObjects,
   arraysize(rstpMibObjects),
   rstpMibInit,
   NULL,
   NULL,
   NULL,
   NULL
};

#endif

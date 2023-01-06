/**
 * @file bridge_mib_module.c
 * @brief Bridge MIB module
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
#include "mibs/bridge_mib_module.h"
#include "mibs/bridge_mib_impl.h"
#include "mibs/bridge_mib_impl_base.h"
#include "mibs/bridge_mib_impl_stp.h"
#include "mibs/bridge_mib_impl_tp.h"
#include "mibs/bridge_mib_impl_static.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (BRIDGE_MIB_SUPPORT == ENABLED)


/**
 * @brief Bridge MIB base
 **/

BridgeMibBase bridgeMibBase;


/**
 * @brief Bridge MIB objects
 **/

const MibObject bridgeMibObjects[] =
{
   //dot1dBaseBridgeAddress object (1.3.6.1.2.1.17.1.1)
   {
      "dot1dBaseBridgeAddress",
      {43, 6, 1, 2, 1, 17, 1, 1},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      bridgeMibGetDot1dBaseBridgeAddress,
      NULL
   },
   //dot1dBaseNumPorts object (1.3.6.1.2.1.17.1.2)
   {
      "dot1dBaseNumPorts",
      {43, 6, 1, 2, 1, 17, 1, 2},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dBaseNumPorts,
      NULL
   },
   //dot1dBaseType object (1.3.6.1.2.1.17.1.3)
   {
      "dot1dBaseType",
      {43, 6, 1, 2, 1, 17, 1, 3},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dBaseType,
      NULL
   },
   //dot1dBasePort object (1.3.6.1.2.1.17.1.4.1.1)
   {
      "dot1dBasePort",
      {43, 6, 1, 2, 1, 17, 1, 4, 1, 1},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dBasePortEntry,
      bridgeMibGetNextDot1dBasePortEntry
   },
   //dot1dBasePortIfIndex object (1.3.6.1.2.1.17.1.4.1.2)
   {
      "dot1dBasePortIfIndex",
      {43, 6, 1, 2, 1, 17, 1, 4, 1, 2},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dBasePortEntry,
      bridgeMibGetNextDot1dBasePortEntry
   },
   //dot1dBasePortCircuit object (1.3.6.1.2.1.17.1.4.1.3)
   {
      "dot1dBasePortCircuit",
      {43, 6, 1, 2, 1, 17, 1, 4, 1, 3},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OBJECT_IDENTIFIER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      bridgeMibGetDot1dBasePortEntry,
      bridgeMibGetNextDot1dBasePortEntry
   },
   //dot1dBasePortDelayExceededDiscards object (1.3.6.1.2.1.17.1.4.1.4)
   {
      "dot1dBasePortDelayExceededDiscards",
      {43, 6, 1, 2, 1, 17, 1, 4, 1, 4},
      10,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      bridgeMibGetDot1dBasePortEntry,
      bridgeMibGetNextDot1dBasePortEntry
   },
   //dot1dBasePortMtuExceededDiscards object (1.3.6.1.2.1.17.1.4.1.5)
   {
      "dot1dBasePortMtuExceededDiscards",
      {43, 6, 1, 2, 1, 17, 1, 4, 1, 5},
      10,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      bridgeMibGetDot1dBasePortEntry,
      bridgeMibGetNextDot1dBasePortEntry
   },
   //dot1dStpProtocolSpecification object (1.3.6.1.2.1.17.2.1)
   {
      "dot1dStpProtocolSpecification",
      {43, 6, 1, 2, 1, 17, 2, 1},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dStpProtocolSpecification,
      NULL
   },
   //dot1dStpPriority object (1.3.6.1.2.1.17.2.2)
   {
      "dot1dStpPriority",
      {43, 6, 1, 2, 1, 17, 2, 2},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dStpPriority,
      bridgeMibGetDot1dStpPriority,
      NULL
   },
   //dot1dStpTimeSinceTopologyChange object (1.3.6.1.2.1.17.2.3)
   {
      "dot1dStpTimeSinceTopologyChange",
      {43, 6, 1, 2, 1, 17, 2, 3},
      8,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_TIME_TICKS,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      bridgeMibGetDot1dStpTimeSinceTopologyChange,
      NULL
   },
   //dot1dStpTopChanges object (1.3.6.1.2.1.17.2.4)
   {
      "dot1dStpTopChanges",
      {43, 6, 1, 2, 1, 17, 2, 4},
      8,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      bridgeMibGetDot1dStpTopChanges,
      NULL
   },
   //dot1dStpDesignatedRoot object (1.3.6.1.2.1.17.2.5)
   {
      "dot1dStpDesignatedRoot",
      {43, 6, 1, 2, 1, 17, 2, 5},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      bridgeMibGetDot1dStpDesignatedRoot,
      NULL
   },
   //dot1dStpRootCost object (1.3.6.1.2.1.17.2.6)
   {
      "dot1dStpRootCost",
      {43, 6, 1, 2, 1, 17, 2, 6},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dStpRootCost,
      NULL
   },
   //dot1dStpRootPort object (1.3.6.1.2.1.17.2.7)
   {
      "dot1dStpRootPort",
      {43, 6, 1, 2, 1, 17, 2, 7},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dStpRootPort,
      NULL
   },
   //dot1dStpMaxAge object (1.3.6.1.2.1.17.2.8)
   {
      "dot1dStpMaxAge",
      {43, 6, 1, 2, 1, 17, 2, 8},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dStpMaxAge,
      NULL
   },
   //dot1dStpHelloTime object (1.3.6.1.2.1.17.2.9)
   {
      "dot1dStpHelloTime",
      {43, 6, 1, 2, 1, 17, 2, 9},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dStpHelloTime,
      NULL
   },
   //dot1dStpHoldTime object (1.3.6.1.2.1.17.2.10)
   {
      "dot1dStpHoldTime",
      {43, 6, 1, 2, 1, 17, 2, 10},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dStpHoldTime,
      NULL
   },
   //dot1dStpForwardDelay object (1.3.6.1.2.1.17.2.11)
   {
      "dot1dStpForwardDelay",
      {43, 6, 1, 2, 1, 17, 2, 11},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dStpForwardDelay,
      NULL
   },
   //dot1dStpBridgeMaxAge object (1.3.6.1.2.1.17.2.12)
   {
      "dot1dStpBridgeMaxAge",
      {43, 6, 1, 2, 1, 17, 2, 12},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dStpBridgeMaxAge,
      bridgeMibGetDot1dStpBridgeMaxAge,
      NULL
   },
   //dot1dStpBridgeHelloTime object (1.3.6.1.2.1.17.2.13)
   {
      "dot1dStpBridgeHelloTime",
      {43, 6, 1, 2, 1, 17, 2, 13},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dStpBridgeHelloTime,
      bridgeMibGetDot1dStpBridgeHelloTime,
      NULL
   },
   //dot1dStpBridgeForwardDelay object (1.3.6.1.2.1.17.2.14)
   {
      "dot1dStpBridgeForwardDelay",
      {43, 6, 1, 2, 1, 17, 2, 14},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dStpBridgeForwardDelay,
      bridgeMibGetDot1dStpBridgeForwardDelay,
      NULL
   },
   //dot1dStpPort object (1.3.6.1.2.1.17.2.15.1.1)
   {
      "dot1dStpPort",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 1},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dStpPortPriority object (1.3.6.1.2.1.17.2.15.1.2)
   {
      "dot1dStpPortPriority",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 2},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dStpPortEntry,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dStpPortState object (1.3.6.1.2.1.17.2.15.1.3)
   {
      "dot1dStpPortState",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 3},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dStpPortEnable object (1.3.6.1.2.1.17.2.15.1.4)
   {
      "dot1dStpPortEnable",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 4},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dStpPortEntry,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dStpPortPathCost object (1.3.6.1.2.1.17.2.15.1.5)
   {
      "dot1dStpPortPathCost",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 5},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dStpPortEntry,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dStpPortDesignatedRoot object (1.3.6.1.2.1.17.2.15.1.6)
   {
      "dot1dStpPortDesignatedRoot",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 6},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dStpPortDesignatedCost object (1.3.6.1.2.1.17.2.15.1.7)
   {
      "dot1dStpPortDesignatedCost",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 7},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dStpPortDesignatedBridge object (1.3.6.1.2.1.17.2.15.1.8)
   {
      "dot1dStpPortDesignatedBridge",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 8},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dStpPortDesignatedPort object (1.3.6.1.2.1.17.2.15.1.9)
   {
      "dot1dStpPortDesignatedPort",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 9},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dStpPortForwardTransitions object (1.3.6.1.2.1.17.2.15.1.10)
   {
      "dot1dStpPortForwardTransitions",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 10},
      10,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dStpPortPathCost32 object (1.3.6.1.2.1.17.2.15.1.11)
   {
      "dot1dStpPortPathCost32",
      {43, 6, 1, 2, 1, 17, 2, 15, 1, 11},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dStpPortEntry,
      bridgeMibGetDot1dStpPortEntry,
      bridgeMibGetNextDot1dStpPortEntry
   },
   //dot1dTpLearnedEntryDiscards object (1.3.6.1.2.1.17.4.1)
   {
      "dot1dTpLearnedEntryDiscards",
      {43, 6, 1, 2, 1, 17, 4, 1},
      8,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      bridgeMibGetDot1dTpLearnedEntryDiscards,
      NULL
   },
   //dot1dTpAgingTime object (1.3.6.1.2.1.17.4.2)
   {
      "dot1dTpAgingTime",
      {43, 6, 1, 2, 1, 17, 4, 2},
      8,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dTpAgingTime,
      bridgeMibGetDot1dTpAgingTime,
      NULL
   },
   //dot1dTpFdbAddress object (1.3.6.1.2.1.17.4.3.1.1)
   {
      "dot1dTpFdbAddress",
      {43, 6, 1, 2, 1, 17, 4, 3, 1, 1},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      bridgeMibGetDot1dTpFdbEntry,
      bridgeMibGetNextDot1dTpFdbEntry
   },
   //dot1dTpFdbPort object (1.3.6.1.2.1.17.4.3.1.2)
   {
      "dot1dTpFdbPort",
      {43, 6, 1, 2, 1, 17, 4, 3, 1, 2},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dTpFdbEntry,
      bridgeMibGetNextDot1dTpFdbEntry
   },
   //dot1dTpFdbStatus object (1.3.6.1.2.1.17.4.3.1.3)
   {
      "dot1dTpFdbStatus",
      {43, 6, 1, 2, 1, 17, 4, 3, 1, 3},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dTpFdbEntry,
      bridgeMibGetNextDot1dTpFdbEntry
   },
   //dot1dTpPort object (1.3.6.1.2.1.17.4.4.1.1)
   {
      "dot1dTpPort",
      {43, 6, 1, 2, 1, 17, 4, 4, 1, 1},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dTpPortEntry,
      bridgeMibGetNextDot1dTpPortEntry
   },
   //dot1dTpPortMaxInfo object (1.3.6.1.2.1.17.4.4.1.2)
   {
      "dot1dTpPortMaxInfo",
      {43, 6, 1, 2, 1, 17, 4, 4, 1, 2},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      bridgeMibGetDot1dTpPortEntry,
      bridgeMibGetNextDot1dTpPortEntry
   },
   //dot1dTpPortInFrames object (1.3.6.1.2.1.17.4.4.1.3)
   {
      "dot1dTpPortInFrames",
      {43, 6, 1, 2, 1, 17, 4, 4, 1, 3},
      10,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      bridgeMibGetDot1dTpPortEntry,
      bridgeMibGetNextDot1dTpPortEntry
   },
   //dot1dTpPortOutFrames object (1.3.6.1.2.1.17.4.4.1.4)
   {
      "dot1dTpPortOutFrames",
      {43, 6, 1, 2, 1, 17, 4, 4, 1, 4},
      10,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      bridgeMibGetDot1dTpPortEntry,
      bridgeMibGetNextDot1dTpPortEntry
   },
   //dot1dTpPortInDiscards object (1.3.6.1.2.1.17.4.4.1.5)
   {
      "dot1dTpPortInDiscards",
      {43, 6, 1, 2, 1, 17, 4, 4, 1, 5},
      10,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      bridgeMibGetDot1dTpPortEntry,
      bridgeMibGetNextDot1dTpPortEntry
   },
   //dot1dStaticAddress object (1.3.6.1.2.1.17.5.1.1.1)
   {
      "dot1dStaticAddress",
      {43, 6, 1, 2, 1, 17, 5, 1, 1, 1},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_CREATE,
      NULL,
      NULL,
      0,
      bridgeMibSetDot1dStaticEntry,
      bridgeMibGetDot1dStaticEntry,
      bridgeMibGetNextDot1dStaticEntry
   },
   //dot1dStaticReceivePort object (1.3.6.1.2.1.17.5.1.1.2)
   {
      "dot1dStaticReceivePort",
      {43, 6, 1, 2, 1, 17, 5, 1, 1, 2},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_CREATE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dStaticEntry,
      bridgeMibGetDot1dStaticEntry,
      bridgeMibGetNextDot1dStaticEntry
   },
   //dot1dStaticAllowedToGoTo object (1.3.6.1.2.1.17.5.1.1.3)
   {
      "dot1dStaticAllowedToGoTo",
      {43, 6, 1, 2, 1, 17, 5, 1, 1, 3},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_CREATE,
      NULL,
      NULL,
      0,
      bridgeMibSetDot1dStaticEntry,
      bridgeMibGetDot1dStaticEntry,
      bridgeMibGetNextDot1dStaticEntry
   },
   //dot1dStaticStatus object (1.3.6.1.2.1.17.5.1.1.4)
   {
      "dot1dStaticStatus",
      {43, 6, 1, 2, 1, 17, 5, 1, 1, 4},
      10,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_CREATE,
      NULL,
      NULL,
      sizeof(int32_t),
      bridgeMibSetDot1dStaticEntry,
      bridgeMibGetDot1dStaticEntry,
      bridgeMibGetNextDot1dStaticEntry
   }
};


/**
 * @brief Bridge MIB module
 **/

const MibModule bridgeMibModule =
{
   "BRIDGE-MIB",
   {43, 6, 1, 2, 1, 17},
   6,
   bridgeMibObjects,
   arraysize(bridgeMibObjects),
   bridgeMibInit,
   NULL,
   NULL,
   NULL,
   NULL
};

#endif

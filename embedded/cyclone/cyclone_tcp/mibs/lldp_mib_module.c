/**
 * @file lldp_mib_module.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SNMP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "mibs/mib_common.h"
#include "mibs/lldp_mib_module.h"
#include "mibs/lldp_mib_impl.h"
#include "mibs/lldp_mib_impl_config.h"
#include "mibs/lldp_mib_impl_stats.h"
#include "mibs/lldp_mib_impl_local.h"
#include "mibs/lldp_mib_impl_remote.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "lldp/lldp.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_MIB_SUPPORT == ENABLED)


/**
 * @brief LLDP MIB base
 **/

LldpMibBase lldpMibBase;


/**
 * @brief LLDP MIB objects
 **/

const MibObject lldpMibObjects[] =
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //lldpMessageTxInterval object (1.0.8802.1.1.2.1.1.1)
   {
      "lldpMessageTxInterval",
      {40, 196, 98, 1, 1, 2, 1, 1, 1},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      lldpMibSetLldpMessageTxInterval,
      lldpMibGetLldpMessageTxInterval,
      NULL
   },
   //lldpMessageTxHoldMultiplier object (1.0.8802.1.1.2.1.1.2)
   {
      "lldpMessageTxHoldMultiplier",
      {40, 196, 98, 1, 1, 2, 1, 1, 2},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      lldpMibSetLldpMessageTxHoldMultiplier,
      lldpMibGetLldpMessageTxHoldMultiplier,
      NULL
   },
   //lldpReinitDelay object (1.0.8802.1.1.2.1.1.3)
   {
      "lldpReinitDelay",
      {40, 196, 98, 1, 1, 2, 1, 1, 3},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      lldpMibSetLldpReinitDelay,
      lldpMibGetLldpReinitDelay,
      NULL
   },
   //lldpTxDelay object (1.0.8802.1.1.2.1.1.4)
   {
      "lldpTxDelay",
      {40, 196, 98, 1, 1, 2, 1, 1, 4},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      lldpMibSetLldpTxDelay,
      lldpMibGetLldpTxDelay,
      NULL
   },
#endif
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //lldpNotificationInterval object (1.0.8802.1.1.2.1.1.5)
   {
      "lldpNotificationInterval",
      {40, 196, 98, 1, 1, 2, 1, 1, 5},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      lldpMibSetLldpNotificationInterval,
      lldpMibGetLldpNotificationInterval,
      NULL
   },
#endif
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //lldpPortConfigAdminStatus object (1.0.8802.1.1.2.1.1.6.1.2)
   {
      "lldpPortConfigAdminStatus",
      {40, 196, 98, 1, 1, 2, 1, 1, 6, 1, 2},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      lldpMibSetLldpPortConfigEntry,
      lldpMibGetLldpPortConfigEntry,
      lldpMibGetNextLldpPortConfigEntry
   },
#endif
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //lldpPortConfigNotificationEnable object (1.0.8802.1.1.2.1.1.6.1.3)
   {
      "lldpPortConfigNotificationEnable",
      {40, 196, 98, 1, 1, 2, 1, 1, 6, 1, 3},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      lldpMibSetLldpPortConfigEntry,
      lldpMibGetLldpPortConfigEntry,
      lldpMibGetNextLldpPortConfigEntry
   },
#endif
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //lldpPortConfigTLVsTxEnable object (1.0.8802.1.1.2.1.1.6.1.4)
   {
      "lldpPortConfigTLVsTxEnable",
      {40, 196, 98, 1, 1, 2, 1, 1, 6, 1, 4},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      0,
      lldpMibSetLldpPortConfigEntry,
      lldpMibGetLldpPortConfigEntry,
      lldpMibGetNextLldpPortConfigEntry
   },
   //lldpConfigManAddrPortsTxEnable object (1.0.8802.1.1.2.1.1.7.1.1)
   {
      "lldpConfigManAddrPortsTxEnable",
      {40, 196, 98, 1, 1, 2, 1, 1, 7, 1, 1},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      0,
      lldpMibSetLldpConfigManAddrEntry,
      lldpMibGetLldpConfigManAddrEntry,
      lldpMibGetNextLldpConfigManAddrEntry
   },
#endif
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //lldpStatsRemTablesLastChangeTime object (1.0.8802.1.1.2.1.2.1)
   {
      "lldpStatsRemTablesLastChangeTime",
      {40, 196, 98, 1, 1, 2, 1, 2, 1},
      9,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_TIME_TICKS,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRemTablesLastChangeTime,
      NULL
   },
   //lldpStatsRemTablesInserts object (1.0.8802.1.1.2.1.2.2)
   {
      "lldpStatsRemTablesInserts",
      {40, 196, 98, 1, 1, 2, 1, 2, 2},
      9,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_GAUGE32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRemTablesInserts,
      NULL
   },
   //lldpStatsRemTablesDeletes object (1.0.8802.1.1.2.1.2.3)
   {
      "lldpStatsRemTablesDeletes",
      {40, 196, 98, 1, 1, 2, 1, 2, 3},
      9,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_GAUGE32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRemTablesDeletes,
      NULL
   },
   //lldpStatsRemTablesDrops object (1.0.8802.1.1.2.1.2.4)
   {
      "lldpStatsRemTablesDrops",
      {40, 196, 98, 1, 1, 2, 1, 2, 4},
      9,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_GAUGE32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRemTablesDrops,
      NULL
   },
   //lldpStatsRemTablesAgeouts object (1.0.8802.1.1.2.1.2.5)
   {
      "lldpStatsRemTablesAgeouts",
      {40, 196, 98, 1, 1, 2, 1, 2, 5},
      9,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_GAUGE32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRemTablesAgeouts,
      NULL
   },
#endif
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //lldpStatsTxPortFramesTotal object (1.0.8802.1.1.2.1.2.6.1.2)
   {
      "lldpStatsTxPortFramesTotal",
      {40, 196, 98, 1, 1, 2, 1, 2, 6, 1, 2},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsTxPortEntry,
      lldpMibGetNextLldpStatsTxPortEntry
   },
#endif
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //lldpStatsRxPortFramesDiscardedTotal object (1.0.8802.1.1.2.1.2.7.1.2)
   {
      "lldpStatsRxPortFramesDiscardedTotal",
      {40, 196, 98, 1, 1, 2, 1, 2, 7, 1, 2},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRxPortEntry,
      lldpMibGetNextLldpStatsRxPortEntry
   },
   //lldpStatsRxPortFramesErrors object (1.0.8802.1.1.2.1.2.7.1.3)
   {
      "lldpStatsRxPortFramesErrors",
      {40, 196, 98, 1, 1, 2, 1, 2, 7, 1, 3},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRxPortEntry,
      lldpMibGetNextLldpStatsRxPortEntry
   },
   //lldpStatsRxPortFramesTotal object (1.0.8802.1.1.2.1.2.7.1.4)
   {
      "lldpStatsRxPortFramesTotal",
      {40, 196, 98, 1, 1, 2, 1, 2, 7, 1, 4},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRxPortEntry,
      lldpMibGetNextLldpStatsRxPortEntry
   },
   //lldpStatsRxPortTLVsDiscardedTotal object (1.0.8802.1.1.2.1.2.7.1.5)
   {
      "lldpStatsRxPortTLVsDiscardedTotal",
      {40, 196, 98, 1, 1, 2, 1, 2, 7, 1, 5},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRxPortEntry,
      lldpMibGetNextLldpStatsRxPortEntry
   },
   //lldpStatsRxPortTLVsUnrecognizedTotal object (1.0.8802.1.1.2.1.2.7.1.6)
   {
      "lldpStatsRxPortTLVsUnrecognizedTotal",
      {40, 196, 98, 1, 1, 2, 1, 2, 7, 1, 6},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRxPortEntry,
      lldpMibGetNextLldpStatsRxPortEntry
   },
   //lldpStatsRxPortAgeoutsTotal object (1.0.8802.1.1.2.1.2.7.1.7)
   {
      "lldpStatsRxPortAgeoutsTotal",
      {40, 196, 98, 1, 1, 2, 1, 2, 7, 1, 7},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_GAUGE32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      lldpMibGetLldpStatsRxPortEntry,
      lldpMibGetNextLldpStatsRxPortEntry
   },
#endif
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //lldpLocChassisIdSubtype object (1.0.8802.1.1.2.1.3.1)
   {
      "lldpLocChassisIdSubtype",
      {40, 196, 98, 1, 1, 2, 1, 3, 1},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      lldpMibGetLldpLocChassisIdSubtype,
      NULL
   },
   //lldpLocChassisId object (1.0.8802.1.1.2.1.3.2)
   {
      "lldpLocChassisId",
      {40, 196, 98, 1, 1, 2, 1, 3, 2},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpLocChassisId,
      NULL
   },
   //lldpLocSysName object (1.0.8802.1.1.2.1.3.3)
   {
      "lldpLocSysName",
      {40, 196, 98, 1, 1, 2, 1, 3, 3},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpLocSysName,
      NULL
   },
   //lldpLocSysDesc object (1.0.8802.1.1.2.1.3.4)
   {
      "lldpLocSysDesc",
      {40, 196, 98, 1, 1, 2, 1, 3, 4},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpLocSysDesc,
      NULL
   },
   //lldpLocSysCapSupported object (1.0.8802.1.1.2.1.3.5)
   {
      "lldpLocSysCapSupported",
      {40, 196, 98, 1, 1, 2, 1, 3, 5},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpLocSysCapSupported,
      NULL
   },
   //lldpLocSysCapEnabled object (1.0.8802.1.1.2.1.3.6)
   {
      "lldpLocSysCapEnabled",
      {40, 196, 98, 1, 1, 2, 1, 3, 6},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpLocSysCapEnabled,
      NULL
   },
   //lldpLocPortIdSubtype object (1.0.8802.1.1.2.1.3.7.1.2)
   {
      "lldpLocPortIdSubtype",
      {40, 196, 98, 1, 1, 2, 1, 3, 7, 1, 2},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      lldpMibGetLldpLocPortEntry,
      lldpMibGetNextLldpLocPortEntry
   },
   //lldpLocPortId object (1.0.8802.1.1.2.1.3.7.1.3)
   {
      "lldpLocPortId",
      {40, 196, 98, 1, 1, 2, 1, 3, 7, 1, 3},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpLocPortEntry,
      lldpMibGetNextLldpLocPortEntry
   },
   //lldpLocPortDesc object (1.0.8802.1.1.2.1.3.7.1.4)
   {
      "lldpLocPortDesc",
      {40, 196, 98, 1, 1, 2, 1, 3, 7, 1, 4},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpLocPortEntry,
      lldpMibGetNextLldpLocPortEntry
   },
   //lldpLocManAddrLen object (1.0.8802.1.1.2.1.3.8.1.3)
   {
      "lldpLocManAddrLen",
      {40, 196, 98, 1, 1, 2, 1, 3, 8, 1, 3},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      lldpMibGetLldpLocManAddrEntry,
      lldpMibGetNextLldpLocManAddrEntry
   },
   //lldpLocManAddrIfSubtype object (1.0.8802.1.1.2.1.3.8.1.4)
   {
      "lldpLocManAddrIfSubtype",
      {40, 196, 98, 1, 1, 2, 1, 3, 8, 1, 4},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      lldpMibGetLldpLocManAddrEntry,
      lldpMibGetNextLldpLocManAddrEntry
   },
   //lldpLocManAddrIfId object (1.0.8802.1.1.2.1.3.8.1.5)
   {
      "lldpLocManAddrIfId",
      {40, 196, 98, 1, 1, 2, 1, 3, 8, 1, 5},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      lldpMibGetLldpLocManAddrEntry,
      lldpMibGetNextLldpLocManAddrEntry
   },
   //lldpLocManAddrOID object (1.0.8802.1.1.2.1.3.8.1.6)
   {
      "lldpLocManAddrOID",
      {40, 196, 98, 1, 1, 2, 1, 3, 8, 1, 6},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OBJECT_IDENTIFIER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpLocManAddrEntry,
      lldpMibGetNextLldpLocManAddrEntry
   },
#endif
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //lldpRemChassisIdSubtype object (1.0.8802.1.1.2.1.4.1.1.4)
   {
      "lldpRemChassisIdSubtype",
      {40, 196, 98, 1, 1, 2, 1, 4, 1, 1, 4},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      lldpMibGetLldpRemEntry,
      lldpMibGetNextLldpRemEntry
   },
   //lldpRemChassisId object (1.0.8802.1.1.2.1.4.1.1.5)
   {
      "lldpRemChassisId",
      {40, 196, 98, 1, 1, 2, 1, 4, 1, 1, 5},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpRemEntry,
      lldpMibGetNextLldpRemEntry
   },
   //lldpRemPortIdSubtype object (1.0.8802.1.1.2.1.4.1.1.6)
   {
      "lldpRemPortIdSubtype",
      {40, 196, 98, 1, 1, 2, 1, 4, 1, 1, 6},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      lldpMibGetLldpRemEntry,
      lldpMibGetNextLldpRemEntry
   },
   //lldpRemPortId object (1.0.8802.1.1.2.1.4.1.1.7)
   {
      "lldpRemPortId",
      {40, 196, 98, 1, 1, 2, 1, 4, 1, 1, 7},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpRemEntry,
      lldpMibGetNextLldpRemEntry
   },
   //lldpRemPortDesc object (1.0.8802.1.1.2.1.4.1.1.8)
   {
      "lldpRemPortDesc",
      {40, 196, 98, 1, 1, 2, 1, 4, 1, 1, 8},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpRemEntry,
      lldpMibGetNextLldpRemEntry
   },
   //lldpRemSysName object (1.0.8802.1.1.2.1.4.1.1.9)
   {
      "lldpRemSysName",
      {40, 196, 98, 1, 1, 2, 1, 4, 1, 1, 9},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpRemEntry,
      lldpMibGetNextLldpRemEntry
   },
   //lldpRemSysDesc object (1.0.8802.1.1.2.1.4.1.1.10)
   {
      "lldpRemSysDesc",
      {40, 196, 98, 1, 1, 2, 1, 4, 1, 1, 10},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpRemEntry,
      lldpMibGetNextLldpRemEntry
   },
   //lldpRemSysCapSupported object (1.0.8802.1.1.2.1.4.1.1.11)
   {
      "lldpRemSysCapSupported",
      {40, 196, 98, 1, 1, 2, 1, 4, 1, 1, 11},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpRemEntry,
      lldpMibGetNextLldpRemEntry
   },
   //lldpRemSysCapEnabled object (1.0.8802.1.1.2.1.4.1.1.12)
   {
      "lldpRemSysCapEnabled",
      {40, 196, 98, 1, 1, 2, 1, 4, 1, 1, 12},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpRemEntry,
      lldpMibGetNextLldpRemEntry
   },
   //lldpRemManAddrIfSubtype object (1.0.8802.1.1.2.1.4.2.1.3)
   {
      "lldpRemManAddrIfSubtype",
      {40, 196, 98, 1, 1, 2, 1, 4, 2, 1, 3},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      lldpMibGetLldpRemManAddrEntry,
      lldpMibGetNextLldpRemManAddrEntry
   },
   //lldpRemManAddrIfId object (1.0.8802.1.1.2.1.4.2.1.4)
   {
      "lldpRemManAddrIfId",
      {40, 196, 98, 1, 1, 2, 1, 4, 2, 1, 4},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      lldpMibGetLldpRemManAddrEntry,
      lldpMibGetNextLldpRemManAddrEntry
   },
   //lldpRemManAddrOID object (1.0.8802.1.1.2.1.4.2.1.5)
   {
      "lldpRemManAddrOID",
      {40, 196, 98, 1, 1, 2, 1, 4, 2, 1, 5},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OBJECT_IDENTIFIER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpRemManAddrEntry,
      lldpMibGetNextLldpRemManAddrEntry
   },
   //lldpRemUnknownTLVInfo object (1.0.8802.1.1.2.1.4.3.1.2)
   {
      "lldpRemUnknownTLVInfo",
      {40, 196, 98, 1, 1, 2, 1, 4, 3, 1, 2},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpRemUnknownTLVEntry,
      lldpMibGetNextLldpRemUnknownTLVEntry
   },
   //lldpRemOrgDefInfo object (1.0.8802.1.1.2.1.4.4.1.4)
   {
      "lldpRemOrgDefInfo",
      {40, 196, 98, 1, 1, 2, 1, 4, 4, 1, 4},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      lldpMibGetLldpRemOrgDefInfoEntry,
      lldpMibGetNextLldpRemOrgDefInfoEntry
   }
#endif
};


/**
 * @brief LLDP MIB module
 **/

const MibModule lldpMibModule =
{
   "LLDP-MIB",
   {40, 196, 98, 1, 1, 2},
   6,
   lldpMibObjects,
   arraysize(lldpMibObjects),
   lldpMibInit,
   NULL,
   NULL,
   lldpMibLock,
   lldpMibUnlock
};

#endif

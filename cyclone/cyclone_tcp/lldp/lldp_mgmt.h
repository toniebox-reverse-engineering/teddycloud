/**
 * @file lldp_mgmt.h
 * @brief Management of the LLDP agent
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

#ifndef _LLDP_MGMT_H
#define _LLDP_MGMT_H

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//LLDP related functions
void lldpMgmtLock(LldpAgentContext *context);
void lldpMgmtUnlock(LldpAgentContext *context);

error_t lldpMgmtSetMsgTxInterval(LldpAgentContext *context,
   uint_t msgTxInterval, bool_t commit);

error_t lldpMgmtSetMsgTxHold(LldpAgentContext *context, uint_t msgTxHold,
   bool_t commit);

error_t lldpMgmtSetReinitDelay(LldpAgentContext *context, uint_t reinitDelay,
   bool_t commit);

error_t lldpMgmtSetTxDelay(LldpAgentContext *context, uint_t txDelay,
   bool_t commit);

error_t lldpMgmtSetNotificationInterval(LldpAgentContext *context,
   uint_t notificationInterval, bool_t commit);

error_t lldpMgmtSetAdminStatus(LldpAgentContext *context,
   uint_t portIndex, LldpAdminStatus adminStatus, bool_t commit);

error_t lldpMgmtSetNotificationEnable(LldpAgentContext *context,
   uint_t portIndex, bool_t notificationEnable, bool_t commit);

error_t lldpMgmtSetBasicTlvFilter(LldpAgentContext *context, uint_t portIndex,
   uint8_t mask, bool_t commit);

error_t lldpMgmtGetMsgTxInterval(LldpAgentContext *context,
   uint_t *msgTxInterval);

error_t lldpMgmtGetMsgTxHold(LldpAgentContext *context, uint_t *msgTxHold);
error_t lldpMgmtGetReinitDelay(LldpAgentContext *context, uint_t *reinitDelay);
error_t lldpMgmtGetTxDelay(LldpAgentContext *context, uint_t *txDelay);

error_t lldpMgmtGetNotificationInterval(LldpAgentContext *context,
   uint_t *notificationInterval);

error_t lldpMgmtGetAdminStatus(LldpAgentContext *context,
   uint_t portIndex, LldpAdminStatus *adminStatus);

error_t lldpMgmtGetNotificationEnable(LldpAgentContext *context,
   uint_t portIndex, bool_t *notificationEnable);

error_t lldpMgmtGetMibBasicTlvsTxEnable(LldpAgentContext *context,
   uint_t portIndex, uint8_t *mibBasicTlvsTxEnable);

error_t lldpMgmtGetLocalChassisId(LldpAgentContext *context,
   LldpChassisIdSubtype *chassisIdSubtype, const uint8_t **chassisId,
   size_t *chassisIdLen);

error_t lldpMgmtGetLocalPortId(LldpAgentContext *context, uint_t portIndex,
   LldpPortIdSubtype *portIdSubtype, const uint8_t **portId,
   size_t *portIdLen);

error_t lldpMgmtGetLocalPortDesc(LldpAgentContext *context, uint_t portIndex,
   const char_t **portDesc, size_t *portDescLen);

error_t lldpMgmtGetLocalSysName(LldpAgentContext *context,
   const char_t **sysName, size_t *sysNameLen);

error_t lldpMgmtGetLocalSysDesc(LldpAgentContext *context,
   const char_t **sysDesc, size_t *sysDescLen);

error_t lldpMgmtGetLocalSysCap(LldpAgentContext *context,
   uint16_t *supportedCap, uint16_t *enabledCap);

int_t lldpMgmtFindLocalMgmtAddr(LldpAgentContext *context,
   uint8_t mgmtAddrSubtype, const uint8_t *mgmtAddr, size_t mgmtAddrLen);

error_t lldpMgmtGetLocalMgmtAddr(LldpAgentContext *context, uint_t index,
   LldpMgmtAddrSubtype *mgmtAddrSubtype, const uint8_t **mgmtAddr,
   size_t *mgmtAddrLen, LldpIfNumSubtype *ifNumSubtype, uint32_t *ifNum,
   const uint8_t **oid, size_t *oidLen);

LldpNeighborEntry *lldpMgmtFindRemoteTableEntry(LldpAgentContext *context,
   uint32_t timeMark, uint_t portIndex, uint32_t index);

error_t lldpMgmtGetRemoteChassisId(LldpNeighborEntry *entry,
   LldpChassisIdSubtype *chassisIdSubtype, const uint8_t **chassisId,
   size_t *chassisIdLen);

error_t lldpMgmtGetRemotePortId(LldpNeighborEntry *entry,
   LldpPortIdSubtype *portIdSubtype, const uint8_t **portId,
   size_t *portIdLen);

error_t lldpMgmtGetRemotePortDesc(LldpNeighborEntry *entry,
   const char_t **portDesc, size_t *portDescLen);

error_t lldpMgmtGetRemoteSysName(LldpNeighborEntry *entry,
   const char_t **sysName, size_t *sysNameLen);

error_t lldpMgmtGetRemoteSysDesc(LldpNeighborEntry *entry,
   const char_t **sysDesc, size_t *sysDescLen);

error_t lldpMgmtGetRemoteSysCap(LldpNeighborEntry *entry,
   uint16_t *supportedCap, uint16_t *enabledCap);

int_t lldpMgmtFindRemoteMgmtAddr(LldpNeighborEntry *entry,
   uint8_t mgmtAddrSubtype, const uint8_t *mgmtAddr, size_t mgmtAddrLen);

error_t lldpMgmtGetRemoteMgmtAddr(LldpNeighborEntry *entry, uint_t index,
   LldpMgmtAddrSubtype *mgmtAddrSubtype, const uint8_t **mgmtAddr,
   size_t *mgmtAddrLen, LldpIfNumSubtype *ifNumSubtype, uint32_t *ifNum,
   const uint8_t **oid, size_t *oidLen);

error_t lldpMgmtGetRemoteUnknownTlv(LldpNeighborEntry *entry,
   uint8_t type, uint_t index, const uint8_t **info, size_t *infoLen);

error_t lldpMgmtGetRemoteOrgDefInfo(LldpNeighborEntry *entry,
   uint32_t oui, uint8_t subtype, uint_t index, const uint8_t **info,
   size_t *infoLen);

error_t lldpMgmtGetStatsFramesOutTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsFramesOutTotal);

error_t lldpMgmtGetStatsFramesDiscardedTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsFramesDiscardedTotal);

error_t lldpMgmtGetStatsFramesInErrorsTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsFramesInErrorsTotal);

error_t lldpMgmtGetStatsFramesInTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsFramesInTotal);

error_t lldpMgmtGetStatsTLVsDiscardedTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsTLVsDiscardedTotal);

error_t lldpMgmtGetStatsTLVsUnrecognizedTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsTLVsUnrecognizedTotal);

error_t lldpMgmtGetStatsAgeoutsTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsAgeoutsTotal);

error_t lldpMgmtGetStatsRemTablesLastChangeTime(LldpAgentContext *context,
   uint32_t *statsRemTablesLastChangeTime);

error_t lldpMgmtGetStatsRemTablesInserts(LldpAgentContext *context,
   uint32_t *statsRemTablesInserts);

error_t lldpMgmtGetStatsRemTablesDeletes(LldpAgentContext *context,
   uint32_t *statsRemTablesDeletes);

error_t lldpMgmtGetStatsRemTablesDrops(LldpAgentContext *context,
   uint32_t *statsRemTablesDrops);

error_t lldpMgmtGetStatsRemTablesAgeouts(LldpAgentContext *context,
   uint32_t *statsRemTablesAgeouts);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

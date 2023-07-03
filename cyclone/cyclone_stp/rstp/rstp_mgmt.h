/**
 * @file rstp_mgmt.h
 * @brief Management of the RSTP bridge
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

#ifndef _RSTP_MGMT_H
#define _RSTP_MGMT_H

//Dependencies
#include "rstp/rstp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//RSTP related functions
error_t rstpMgmtSetVersion(RstpBridgeContext *context, uint_t value,
   bool_t commit);

error_t rstpMgmtSetBridgePriority(RstpBridgeContext *context, uint16_t value,
   bool_t commit);

error_t rstpMgmtSetBridgeMaxAge(RstpBridgeContext *context, uint_t value,
   bool_t commit);

error_t rstpMgmtSetBridgeHelloTime(RstpBridgeContext *context, uint_t value,
   bool_t commit);

error_t rstpMgmtSetBridgeForwardDelay(RstpBridgeContext *context, uint_t value,
   bool_t commit);

error_t rstpMgmtSetTxHoldCount(RstpBridgeContext *context, uint_t value,
   bool_t commit);

error_t rstpMgmtSetAgeingTime(RstpBridgeContext *context, uint_t value,
   bool_t commit);

error_t rstpMgmtGetNumPorts(RstpBridgeContext *context, uint_t *value);
error_t rstpMgmtGetVersion(RstpBridgeContext *context, uint_t *value);
error_t rstpMgmtGetBridgeAddr(RstpBridgeContext *context, MacAddr *value);
error_t rstpMgmtGetBridgePriority(RstpBridgeContext *context, uint16_t *value);
error_t rstpMgmtGetBridgeMaxAge(RstpBridgeContext *context, uint_t *value);
error_t rstpMgmtGetBridgeHelloTime(RstpBridgeContext *context, uint_t *value);
error_t rstpMgmtGetBridgeForwardDelay(RstpBridgeContext *context, uint_t *value);
error_t rstpMgmtGetTxHoldCount(RstpBridgeContext *context, uint_t *value);
error_t rstpMgmtGetAgeingTime(RstpBridgeContext *context, uint_t *value);
error_t rstpMgmtGetDesignatedRoot(RstpBridgeContext *context, StpBridgeId *value);
error_t rstpMgmtGetRootPathCost(RstpBridgeContext *context, uint32_t *value);
error_t rstpMgmtGetRootPort(RstpBridgeContext *context, uint16_t *value);
error_t rstpMgmtGetMaxAge(RstpBridgeContext *context, uint_t *value);
error_t rstpMgmtGetHelloTime(RstpBridgeContext *context, uint_t *value);
error_t rstpMgmtGetForwardDelay(RstpBridgeContext *context, uint_t *value);
error_t rstpMgmtGetTopologyChanges(RstpBridgeContext *context, uint_t *value);

error_t rstpMgmtGetTimeSinceTopologyChange(RstpBridgeContext *context,
   uint_t *value);

error_t rstpMgmtSetPortPriority(RstpBridgeContext *context, uint_t portIndex,
   uint8_t value, bool_t commit);

error_t rstpMgmtSetAdminPortState(RstpBridgeContext *context, uint_t portIndex,
   bool_t value, bool_t commit);

error_t rstpMgmtSetAdminPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t value, bool_t commit);

error_t rstpMgmtSetAdminPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, RstpAdminPointToPointMac value, bool_t commit);

error_t rstpMgmtSetAdminEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t value, bool_t commit);

error_t rstpMgmtSetAutoEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t value, bool_t commit);

error_t rstpMgmtSetProtocolMigration(RstpBridgeContext *context, uint_t portIndex,
   bool_t value, bool_t commit);

error_t rstpMgmtGetPortAddr(RstpBridgeContext *context, uint_t portIndex,
   MacAddr *value);

error_t rstpMgmtGetPortPriority(RstpBridgeContext *context, uint_t portIndex,
   uint8_t *value);

error_t rstpMgmtGetAdminPortState(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t rstpMgmtGetMacOperState(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t rstpMgmtGetAdminPortPathCost(RstpBridgeContext *context,
   uint_t portIndex, uint32_t *value);

error_t rstpMgmtGetPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t *value);

error_t rstpMgmtGetAdminPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, RstpAdminPointToPointMac *value);

error_t rstpMgmtGetOperPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, bool_t *value);

error_t rstpMgmtGetAdminEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t rstpMgmtGetAutoEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t rstpMgmtGetOperEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t rstpMgmtGetPortState(RstpBridgeContext *context, uint_t portIndex,
   StpPortState *value);

error_t rstpMgmtGetPortRole(RstpBridgeContext *context, uint_t portIndex,
   StpPortRole *value);

error_t rstpMgmtGetPortDesignatedRoot(RstpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value);

error_t rstpMgmtGetPortDesignatedCost(RstpBridgeContext *context,
   uint_t portIndex, uint32_t *value);

error_t rstpMgmtGetPortDesignatedBridge(RstpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value);

error_t rstpMgmtGetPortDesignatedPort(RstpBridgeContext *context,
   uint_t portIndex, uint16_t *value);

error_t rstpMgmtGetForwardTransitions(RstpBridgeContext *context,
   uint_t portIndex, uint_t *value);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

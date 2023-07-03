/**
 * @file stp_mgmt.h
 * @brief Management of the STP bridge
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

#ifndef _STP_MGMT_H
#define _STP_MGMT_H

//Dependencies
#include "stp/stp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//STP related functions
error_t stpMgmtSetBridgePriority(StpBridgeContext *context, uint16_t value,
   bool_t commit);

error_t stpMgmtSetBridgeMaxAge(StpBridgeContext *context, uint_t value,
   bool_t commit);

error_t stpMgmtSetBridgeHelloTime(StpBridgeContext *context, uint_t value,
   bool_t commit);

error_t stpMgmtSetBridgeForwardDelay(StpBridgeContext *context, uint_t value,
   bool_t commit);

error_t stpMgmtSetAgeingTime(StpBridgeContext *context, uint_t value,
   bool_t commit);

error_t stpMgmtGetNumPorts(StpBridgeContext *context, uint_t *value);
error_t stpMgmtGetBridgeAddr(StpBridgeContext *context, MacAddr *value);
error_t stpMgmtGetBridgePriority(StpBridgeContext *context, uint16_t *value);
error_t stpMgmtGetBridgeMaxAge(StpBridgeContext *context, uint_t *value);
error_t stpMgmtGetBridgeHelloTime(StpBridgeContext *context, uint_t *value);
error_t stpMgmtGetBridgeForwardDelay(StpBridgeContext *context, uint_t *value);
error_t stpMgmtGetHoldTime(StpBridgeContext *context, uint_t *value);
error_t stpMgmtGetAgeingTime(StpBridgeContext *context, uint_t *value);
error_t stpMgmtGetDesignatedRoot(StpBridgeContext *context, StpBridgeId *value);
error_t stpMgmtGetRootPathCost(StpBridgeContext *context, uint32_t *value);
error_t stpMgmtGetRootPort(StpBridgeContext *context, uint16_t *value);
error_t stpMgmtGetMaxAge(StpBridgeContext *context, uint_t *value);
error_t stpMgmtGetHelloTime(StpBridgeContext *context, uint_t *value);
error_t stpMgmtGetForwardDelay(StpBridgeContext *context, uint_t *value);
error_t stpMgmtGetTopologyChanges(StpBridgeContext *context, uint_t *value);

error_t stpMgmtGetTimeSinceTopologyChange(StpBridgeContext *context,
   uint_t *value);

error_t stpMgmtSetPortPriority(StpBridgeContext *context, uint_t portIndex,
   uint8_t value, bool_t commit);

error_t stpMgmtSetAdminPortState(StpBridgeContext *context, uint_t portIndex,
   bool_t value, bool_t commit);

error_t stpMgmtSetPortPathCost(StpBridgeContext *context, uint_t portIndex,
   uint32_t value, bool_t commit);

error_t stpMgmtGetPortAddr(StpBridgeContext *context, uint_t portIndex,
   MacAddr *value);

error_t stpMgmtGetPortPriority(StpBridgeContext *context, uint_t portIndex,
   uint8_t *value);

error_t stpMgmtGetAdminPortState(StpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t stpMgmtGetMacOperState(StpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t stpMgmtGetPortPathCost(StpBridgeContext *context, uint_t portIndex,
   uint32_t *value);

error_t stpMgmtGetPortState(StpBridgeContext *context, uint_t portIndex,
   StpPortState *value);

error_t stpMgmtGetPortRole(StpBridgeContext *context, uint_t portIndex,
   StpPortRole *value);

error_t stpMgmtGetPortDesignatedRoot(StpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value);

error_t stpMgmtGetPortDesignatedCost(StpBridgeContext *context,
   uint_t portIndex, uint32_t *value);

error_t stpMgmtGetPortDesignatedBridge(StpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value);

error_t stpMgmtGetPortDesignatedPort(StpBridgeContext *context,
   uint_t portIndex, uint16_t *value);

error_t stpMgmtGetForwardTransitions(StpBridgeContext *context,
   uint_t portIndex, uint_t *value);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

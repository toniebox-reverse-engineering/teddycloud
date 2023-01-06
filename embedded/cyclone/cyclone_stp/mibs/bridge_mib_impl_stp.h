/**
 * @file bridge_mib_impl.h
 * @brief Bridge MIB module implementation (dot1dStp subtree)
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

#ifndef _BRIDGE_MIB_IMPL_STP_H
#define _BRIDGE_MIB_IMPL_STP_H

//Dependencies
#include "mibs/mib_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Bridge MIB related functions
error_t bridgeMibGetDot1dStpProtocolSpecification(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibSetDot1dStpPriority(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit);

error_t bridgeMibGetDot1dStpPriority(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpTimeSinceTopologyChange(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpTopChanges(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpDesignatedRoot(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpRootCost(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpRootPort(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpMaxAge(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpHelloTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpHoldTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpForwardDelay(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibSetDot1dStpBridgeMaxAge(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit);

error_t bridgeMibGetDot1dStpBridgeMaxAge(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibSetDot1dStpBridgeHelloTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit);

error_t bridgeMibGetDot1dStpBridgeHelloTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibSetDot1dStpBridgeForwardDelay(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit);

error_t bridgeMibGetDot1dStpBridgeForwardDelay(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibSetDot1dStpPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit);

error_t bridgeMibGetDot1dStpPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen);

error_t bridgeMibGetNextDot1dStpPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen);

error_t bridgeMibSetDot1dStpPortPriority(uint16_t portNum,
   const MibVariant *value, size_t valueLen, bool_t commit);

error_t bridgeMibGetDot1dStpPortPriority(uint16_t portNum,
   MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpPortState(uint16_t portNum,
   MibVariant *value, size_t *valueLen);

error_t bridgeMibSetDot1dStpPortEnable(uint16_t portNum,
   const MibVariant *value, size_t valueLen, bool_t commit);

error_t bridgeMibGetDot1dStpPortEnable(uint16_t portNum,
   MibVariant *value, size_t *valueLen);

error_t bridgeMibSetDot1dStpPortPathCost(uint16_t portNum,
   const MibVariant *value, size_t valueLen, bool_t commit);

error_t bridgeMibGetDot1dStpPortPathCost(uint16_t portNum,
   MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpPortDesignatedRoot(uint16_t portNum,
   MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpPortDesignatedCost(uint16_t portNum,
   MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpPortDesignatedBridge(uint16_t portNum,
   MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpPortDesignatedPort(uint16_t portNum,
   MibVariant *value, size_t *valueLen);

error_t bridgeMibGetDot1dStpPortForwardTransitions(uint16_t portNum,
   MibVariant *value, size_t *valueLen);

error_t bridgeMibSetDot1dStpPortPathCost32(uint16_t portNum,
   const MibVariant *value, size_t valueLen, bool_t commit);

error_t bridgeMibGetDot1dStpPortPathCost32(uint16_t portNum,
   MibVariant *value, size_t *valueLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

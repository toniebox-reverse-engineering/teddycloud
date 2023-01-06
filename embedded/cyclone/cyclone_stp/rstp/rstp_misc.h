/**
 * @file rstp_misc.h
 * @brief RSTP helper functions
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

#ifndef _RSTP_MISC_H
#define _RSTP_MISC_H

//Dependencies
#include "rstp/rstp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Parameter value/name binding
 **/

typedef struct
{
   uint_t value;
   const char_t *name;
} RstpParamName;


//RSTP related functions
void rstpLock(RstpBridgeContext *context);
void rstpUnlock(RstpBridgeContext *context);
void rstpTick(RstpBridgeContext *context);

RstpBridgePort *rstpGetBridgePort(RstpBridgeContext *context, uint16_t portId);

int_t rstpComparePortNum(uint16_t portId1, uint16_t portId2);
int_t rstpCompareBridgeAddr(const MacAddr *addr1, const MacAddr *addr2);
int_t rstpCompareBridgeId(const StpBridgeId *id1, const StpBridgeId *id2);
int_t rstpComparePriority(const RstpPriority *p1, const RstpPriority *p2);
int_t rstpCompareTimes(const RstpTimes *t1, const RstpTimes *t2);

void rstpUpdateTopologyChangeCount(RstpBridgeContext *context);
void rstpUpdatePortPathCost(RstpBridgePort *port);
void rstpUpdateOperPointToPointMac(RstpBridgePort *port);
void rstpUpdatePortState(RstpBridgePort *port, SwitchPortState state);
void rstpUpdateAgeingTime(RstpBridgeContext *context, uint32_t ageingTime);
void rstpEnableRsvdMcastTable(RstpBridgeContext *context, bool_t enable);

error_t rstpAddStaticFdbEntry(RstpBridgeContext *context, const MacAddr *macAddr,
   bool_t override);

error_t rstpDeleteStaticFdbEntry(RstpBridgeContext *context,
   const MacAddr *macAddr);

void rstpRemoveFdbEntries(RstpBridgePort *port);
void rstpFlushFdbTable(RstpBridgePort *port);

error_t rstpConfigurePermanentDatabase(RstpBridgeContext *context);
void rstpUnconfigurePermanentDatabase(RstpBridgeContext *context);

void rstpGeneratePortAddr(RstpBridgePort *port);

bool_t rstpCheckBridgeParams(uint_t maxAge, uint_t helloTime,
   uint_t forwardDelay);

const char_t *rstpGetParamName(uint_t value, const RstpParamName *paramList,
   size_t paramListLen);

void rstpDecrementTimer(uint_t *x);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

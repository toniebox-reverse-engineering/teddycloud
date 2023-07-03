/**
 * @file stp_misc.h
 * @brief STP helper functions
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

#ifndef _STP_MISC_H
#define _STP_MISC_H

//Dependencies
#include "stp/stp.h"

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
} StpParamName;


//STP related functions
void stpLock(StpBridgeContext *context);
void stpUnlock(StpBridgeContext *context);
void stpTick(StpBridgeContext *context);

StpBridgePort *stpGetBridgePort(StpBridgeContext *context, uint16_t portId);

int_t stpComparePortNum(uint16_t portId1, uint16_t portId2);
int_t stpCompareBridgeAddr(const MacAddr *addr1, const MacAddr *addr2);
int_t stpCompareBridgeId(const StpBridgeId *id1, const StpBridgeId *id2);

void stpUpdateTopologyChange(StpBridgeContext *context, bool_t value);
void stpUpdatePortState(StpBridgePort *port, StpPortState state);
void stpUpdateAgeingTime(StpBridgeContext *context, uint32_t ageingTime);
void stpEnableRsvdMcastTable(StpBridgeContext *context, bool_t enable);

error_t stpAddStaticFdbEntry(StpBridgeContext *context, const MacAddr *macAddr,
   bool_t override);

error_t stpDeleteStaticFdbEntry(StpBridgeContext *context,
   const MacAddr *macAddr);

error_t stpConfigurePermanentDatabase(StpBridgeContext *context);
void stpUnconfigurePermanentDatabase(StpBridgeContext *context);

void stpGeneratePortAddr(StpBridgePort *port);

bool_t stpCheckBridgeParams(uint_t maxAge, uint_t helloTime,
   uint_t forwardDelay);

const char_t *stpGetParamName(uint_t value, const StpParamName *paramList,
   size_t paramListLen);

void stpStartTimer(StpTimer *timer, uint_t value);
void stpStopTimer(StpTimer *timer);
bool_t stpIncrementTimer(StpTimer *timer, uint_t timeout);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

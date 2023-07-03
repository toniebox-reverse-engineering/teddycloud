/**
 * @file bridge_mib_impl.h
 * @brief Bridge MIB module implementation
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

#ifndef _BRIDGE_MIB_IMPL_H
#define _BRIDGE_MIB_IMPL_H

//Dependencies
#include "mibs/mib_common.h"
#include "stp/stp.h"
#include "rstp/rstp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Bridge MIB related functions
error_t bridgeMibInit(void);

error_t bridgeMibSetStpBridgeContext(StpBridgeContext *context);
error_t bridgeMibSetRstpBridgeContext(RstpBridgeContext *context);

uint_t bridgeMibGetNumPorts(void);
uint_t bridgeMibGetPortIndex(uint16_t portNum);
uint16_t bridgeMibGetPortNum(uint16_t portIndex);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

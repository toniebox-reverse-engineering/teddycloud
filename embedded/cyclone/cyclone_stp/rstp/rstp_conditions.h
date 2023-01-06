/**
 * @file rstp_conditions.h
 * @brief RSTP state machine conditions
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

#ifndef _RSTP_CONDITIONS_H
#define _RSTP_CONDITIONS_H

//Dependencies
#include "rstp/rstp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//RSTP related functions
uint_t rstpAdminEdge(RstpBridgePort *port);
uint_t rstpAutoEdge(RstpBridgePort *port);
bool_t rstpAllSynced(RstpBridgeContext *context);
uint_t rstpEdgeDelay(RstpBridgePort *port);
uint_t rstpForwardDelay(RstpBridgePort *port);
uint_t rstpFwdDelay(RstpBridgePort *port);
uint_t rstpHelloTime(RstpBridgePort *port);
uint_t rstpMaxAge(RstpBridgePort *port);
uint_t rstpMigrateTime(RstpBridgeContext *context);
bool_t rstpReRooted(RstpBridgePort *port);
bool_t rstpVersion(RstpBridgeContext *context);
bool_t stpVersion(RstpBridgeContext *context);
uint_t rstpTxHoldCount(RstpBridgeContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

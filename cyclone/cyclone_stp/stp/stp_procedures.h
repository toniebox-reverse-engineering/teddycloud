/**
 * @file stp_procedures.h
 * @brief Elements of procedures
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

#ifndef _STP_PROCEDURES_H
#define _STP_PROCEDURES_H

//Dependencies
#include "stp/stp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//STP related functions
void stpInitProc(StpBridgeContext *context);
void stpTransmitConfigBpdu(StpBridgePort *port);
void stpRecordConfigInfo(StpBridgePort *port, const StpBpdu *bpdu);
void stpRecordConfigTimeoutValues(StpBridgeContext *context, const StpBpdu *bpdu);
void stpConfigBpduGeneration(StpBridgeContext *context);
void stpReplyToConfigBpdu(StpBridgePort *port);
void stpTransmitTcnBpdu(StpBridgeContext *context);
void stpConfigUpdate(StpBridgeContext *context);
void stpRootSelection(StpBridgeContext *context);
void stpDesignatedPortSelection(StpBridgeContext *context);
void stpBecomeDesignatedPort(StpBridgePort *port);
void stpPortStateSelection(StpBridgeContext *context);
void stpMakeForwarding(StpBridgePort *port);
void stpMakeBlocking(StpBridgePort *port);
void stpTopologyChangeDetection(StpBridgeContext *context);
void stpTopologyChangeAcked(StpBridgeContext *context);
void stpAckTopologyChange(StpBridgePort *port);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

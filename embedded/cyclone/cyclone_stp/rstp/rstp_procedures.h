/**
 * @file rstp_procedures.h
 * @brief RSTP state machine procedures
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

#ifndef _RSTP_PROCEDURES_H
#define _RSTP_PROCEDURES_H

//Dependencies
#include "rstp/rstp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//RSTP related functions
bool_t rstpBetterOrSameInfo(RstpBridgePort *port, RstpInfoIs newInfoIs);
void rstpClearReselectTree(RstpBridgeContext *context);
void rstpDisableForwarding(RstpBridgePort *port);
void rstpDisableLearning(RstpBridgePort *port);
void rstpEnableForwarding(RstpBridgePort *port);
void rstpEnableLearning(RstpBridgePort *port);
void rstpNewTcWhile(RstpBridgePort *port);
RstpRcvdInfo rstpRcvInfo(RstpBridgePort *port);
void rstpRecordAgreement(RstpBridgePort *port);
void rstpRecordDispute(RstpBridgePort *port);
void rstpRecordProposal(RstpBridgePort *port);
void rstpRecordPriority(RstpBridgePort *port);
void rstpRecordTimes(RstpBridgePort *port);
void rstpSetSyncTree(RstpBridgeContext *context);
void rstpSetReRootTree(RstpBridgeContext *context);
void rstpSetSelectedTree(RstpBridgeContext *context);
void rstpSetTcFlags(RstpBridgePort *port);
void rstpSetTcPropTree(RstpBridgePort *port);
void rstpTxConfig(RstpBridgePort *port);
void rstpTxRstp(RstpBridgePort *port);
void rstpTxTcn(RstpBridgePort *port);
void rstpUpdtBpduVersion(RstpBridgePort *port);
void rstpUpdtRcvdInfoWhile(RstpBridgePort *port);
void rstpUpdtRoleDisabledTree(RstpBridgeContext *context);
void rstpUpdtRolesTree(RstpBridgeContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

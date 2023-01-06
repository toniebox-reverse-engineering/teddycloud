/**
 * @file rstp_prt.h
 * @brief Port Role Transition state machine (PRT)
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

#ifndef _RSTP_PRT_H
#define _RSTP_PRT_H

//Dependencies
#include "rstp/rstp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Port Role Transition machine states
 **/

typedef enum
{
   RSTP_PRT_STATE_INIT_PORT          = 0,
   RSTP_PRT_STATE_DISABLE_PORT       = 1,
   RSTP_PRT_STATE_DISABLED_PORT      = 2,
   RSTP_PRT_STATE_ROOT_PROPOSED      = 3,
   RSTP_PRT_STATE_ROOT_AGREED        = 4,
   RSTP_PRT_STATE_REROOT             = 5,
   RSTP_PRT_STATE_ROOT_FORWARD       = 6,
   RSTP_PRT_STATE_ROOT_LEARN         = 7,
   RSTP_PRT_STATE_REROOTED           = 8,
   RSTP_PRT_STATE_ROOT_PORT          = 9,
   RSTP_PRT_STATE_DESIGNATED_PROPOSE = 10,
   RSTP_PRT_STATE_DESIGNATED_SYNCED  = 11,
   RSTP_PRT_STATE_DESIGNATED_RETIRED = 12,
   RSTP_PRT_STATE_DESIGNATED_FORWARD = 13,
   RSTP_PRT_STATE_DESIGNATED_LEARN   = 14,
   RSTP_PRT_STATE_DESIGNATED_DISCARD = 15,
   RSTP_PRT_STATE_DESIGNATED_PORT    = 16,
   RSTP_PRT_STATE_ALTERNATE_PROPOSED = 17,
   RSTP_PRT_STATE_ALTERNATE_AGREED   = 18,
   RSTP_PRT_STATE_BLOCK_PORT         = 19,
   RSTP_PRT_STATE_BACKUP_PORT        = 20,
   RSTP_PRT_STATE_ALTERNATE_PORT     = 21
} RstpPrtState;


//RSTP related functions
void rstpPrtInit(RstpBridgePort *port);
void rstpPrtFsm(RstpBridgePort *port);

void rstpPrtDisabledPortFsm(RstpBridgePort *port);
void rstpPrtDisabledPortChangeState(RstpBridgePort *port, RstpPrtState newState);

void rstpPrtRootPortFsm(RstpBridgePort *port);
void rstpPrtRootPortChangeState(RstpBridgePort *port, RstpPrtState newState);

void rstpPrtDesignatedPortFsm(RstpBridgePort *port);
void rstpPrtDesignatedPortChangeState(RstpBridgePort *port, RstpPrtState newState);

void rstpPrtAlternatePortFsm(RstpBridgePort *port);
void rstpPrtAlternatePortChangeState(RstpBridgePort *port, RstpPrtState newState);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

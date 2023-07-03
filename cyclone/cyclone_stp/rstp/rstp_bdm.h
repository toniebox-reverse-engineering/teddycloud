/**
 * @file rstp_bdm.h
 * @brief Bridge Detection state machine (BDM)
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

#ifndef _RSTP_BDM_H
#define _RSTP_BDM_H

//Dependencies
#include "rstp/rstp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Bridge Detection machine states
 **/

typedef enum
{
   RSTP_BDM_STATE_EDGE     = 0,
   RSTP_BDM_STATE_NOT_EDGE = 1
} RstpBdmState;


//RSTP related functions
void rstpBdmInit(RstpBridgePort *port);
void rstpBdmFsm(RstpBridgePort *port);
void rstpBdmChangeState(RstpBridgePort *port, RstpBdmState newState);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

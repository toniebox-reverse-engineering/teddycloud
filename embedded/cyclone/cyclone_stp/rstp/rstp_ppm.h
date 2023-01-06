/**
 * @file rstp_ppm.h
 * @brief Port Protocol Migration state machine (PPM)
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

#ifndef _RSTP_PPM_H
#define _RSTP_PPM_H

//Dependencies
#include "rstp/rstp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Port Protocol Migration states
 **/

typedef enum
{
   RSTP_PPM_STATE_CHECKING_RSTP = 0,
   RSTP_PPM_STATE_SELECTING_STP = 1,
   RSTP_PPM_STATE_SENSING       = 2
} RstpPpmState;


//RSTP related functions
void rstpPpmInit(RstpBridgePort *port);
void rstpPpmFsm(RstpBridgePort *port);
void rstpPpmChangeState(RstpBridgePort *port, RstpPpmState newState);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

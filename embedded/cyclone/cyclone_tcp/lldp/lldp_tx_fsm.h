/**
 * @file lldp_tx_fsm.h
 * @brief LLDP transmit state machine
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneTCP Open.
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

#ifndef _LLDP_TX_FSM_H
#define _LLDP_TX_FSM_H

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief LLDP transmit states
 **/

typedef enum
{
   LLDP_STATE_TX_LLDP_INITIALIZE = 0,
   LLDP_STATE_TX_IDLE            = 1,
   LLDP_STATE_TX_SHUTDOWN_FRAME  = 2,
   LLDP_STATE_TX_INFO_FRAME      = 3
} LldpTxState;


//LLDP related functions
void lldpInitTxFsm(LldpPortEntry *port);
void lldpTxFsm(LldpPortEntry *port);
void lldpChangeTxState(LldpPortEntry *port, LldpTxState newState);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

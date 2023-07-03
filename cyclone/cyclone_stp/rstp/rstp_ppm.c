/**
 * @file rstp_ppm.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL RSTP_TRACE_LEVEL

//Dependencies
#include "rstp/rstp.h"
#include "rstp/rstp_fsm.h"
#include "rstp/rstp_ppm.h"
#include "rstp/rstp_conditions.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//PPM state machine's states
const RstpParamName rstpPpmStates[] =
{
   {RSTP_PPM_STATE_CHECKING_RSTP, "CHECKING_RSTP"},
   {RSTP_PPM_STATE_SELECTING_STP, "SELECTING_STP"},
   {RSTP_PPM_STATE_SENSING,       "SENSING"}
};


/**
 * @brief PPM state machine initialization
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPpmInit(RstpBridgePort *port)
{
   //Enter initial state
   rstpPpmChangeState(port, RSTP_PPM_STATE_CHECKING_RSTP);
}


/**
 * @brief PPM state machine implementation
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPpmFsm(RstpBridgePort *port)
{
   //All conditions for the current state are evaluated continuously until one
   //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->ppmState)
   {
   //CHECKING_RSTP state?
   case RSTP_PPM_STATE_CHECKING_RSTP:
      //Evaluate conditions for the current state
      if(port->mdelayWhile == 0)
      {
         //Switch to SENSING state
         rstpPpmChangeState(port, RSTP_PPM_STATE_SENSING);
      }
      else if(port->mdelayWhile != rstpMigrateTime(port->context) &&
         !port->portEnabled)
      {
         //Switch to CHECKING_RSTP state
         rstpPpmChangeState(port, RSTP_PPM_STATE_CHECKING_RSTP);
      }
      else
      {
         //Just for sanity
      }

      break;

   //SELECTING_STP state?
   case RSTP_PPM_STATE_SELECTING_STP:
      //Evaluate conditions for the current state
      if(port->mdelayWhile == 0 || !port->portEnabled || port->mcheck)
      {
         //Switch to SENSING state
         rstpPpmChangeState(port, RSTP_PPM_STATE_SENSING);
      }

      break;

   //SENSING state?
   case RSTP_PPM_STATE_SENSING:
      //Evaluate conditions for the current state
      if(port->sendRstp && port->rcvdStp)
      {
         //Switch to SELECTING_STP state
         rstpPpmChangeState(port, RSTP_PPM_STATE_SELECTING_STP);
      }
      else if(!port->portEnabled || port->mcheck ||
         (rstpVersion(port->context) && !port->sendRstp && port->rcvdRstp))
      {
         //Switch to CHECKING_RSTP state
         rstpPpmChangeState(port, RSTP_PPM_STATE_CHECKING_RSTP);
      }
      else
      {
         //Just for sanity
      }

      break;

   //Invalid state?
   default:
      //Just for sanity
      rstpFsmError(port->context);
      break;
   }
}


/**
 * @brief Update PPM state machine state
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpPpmChangeState(RstpBridgePort *port, RstpPpmState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": PPM state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->ppmState, rstpPpmStates, arraysize(rstpPpmStates)),
      rstpGetParamName(newState, rstpPpmStates, arraysize(rstpPpmStates)));

   //Switch to the new state
   port->ppmState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->ppmState)
   {
   //CHECKING_RSTP state?
   case RSTP_PPM_STATE_CHECKING_RSTP:
      //Clear mcheck flag
      port->mcheck = FALSE;

      //Update sendRSTP to tell the Port Transmit state machine which BPDU
      //types to transmit in order to support interoperability with the
      //Spanning Tree algorithm
      port->sendRstp = rstpVersion(port->context);

      //Reload the Migration Delay timer
      port->mdelayWhile = rstpMigrateTime(port->context);
      break;

   //SELECTING_STP state?
   case RSTP_PPM_STATE_SELECTING_STP:
      //Clear sendRSTP flag
      port->sendRstp = FALSE;

      //Reload the Migration Delay timer
      port->mdelayWhile = rstpMigrateTime(port->context);
      break;

   //SENSING state?
   case RSTP_PPM_STATE_SENSING:
      //Clear sendRSTP and rcvdSTP flags
      port->rcvdRstp = FALSE;
      port->rcvdStp = FALSE;
      break;

   //Invalid state?
   default:
      //Just for sanity
      break;
   }

   //The RSTP state machine is busy
   port->context->busy = TRUE;
}

#endif

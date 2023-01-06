/**
 * @file rstp_pti.c
 * @brief Port Timers state machine (PTI)
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
#include "rstp/rstp_pti.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//PTI state machine's states
const RstpParamName rstpPtiStates[] =
{
   {RSTP_PTI_STATE_ONE_SECOND, "ONE_SECOND"},
   {RSTP_PTI_STATE_TICK,       "TICK"}
};


/**
 * @brief PTI state machine initialization
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPtiInit(RstpBridgePort *port)
{
   //During initialization, the state machine enters the ONE_SECOND state
   //and clears the tick signal
   rstpPtiChangeState(port, RSTP_PTI_STATE_ONE_SECOND);
}


/**
 * @brief PTI state machine implementation
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPtiFsm(RstpBridgePort *port)
{
   //All conditions for the current state are evaluated continuously until one
   //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->ptiState)
   {
   //ONE_SECOND state?
   case RSTP_PTI_STATE_ONE_SECOND:
      //Each tick causes a transition to the TICK state
      if(port->tick)
      {
         rstpPtiChangeState(port, RSTP_PTI_STATE_TICK);
      }

      break;

   //TICK state?
   case RSTP_PTI_STATE_TICK:
      //The state machine then unconditionally transitions to the ONE_SECOND
      //state to clear the tick variable and wait for the next tick
      rstpPtiChangeState(port, RSTP_PTI_STATE_ONE_SECOND);
      break;

   //Invalid state?
   default:
      //Just for sanity
      rstpFsmError(port->context);
      break;
   }
}


/**
 * @brief Update PTI state machine state
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpPtiChangeState(RstpBridgePort *port, RstpPtiState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": PTI state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->ptiState, rstpPtiStates, arraysize(rstpPtiStates)),
      rstpGetParamName(newState, rstpPtiStates, arraysize(rstpPtiStates)));

   //Switch to the new state
   port->ptiState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->ptiState)
   {
   //ONE_SECOND state?
   case RSTP_PTI_STATE_ONE_SECOND:
      //Clear tick variable
      port->tick = FALSE;
      break;

   //TICK state?
   case RSTP_PTI_STATE_TICK:
      //On entry to TICK, all non-zero timer variables are decremented by one
      rstpDecrementTimer(&port->helloWhen);
      rstpDecrementTimer(&port->tcWhile);
      rstpDecrementTimer(&port->fdWhile);
      rstpDecrementTimer(&port->rcvdInfoWhile);
      rstpDecrementTimer(&port->rrWhile);
      rstpDecrementTimer(&port->rbWhile);
      rstpDecrementTimer(&port->mdelayWhile);
      rstpDecrementTimer(&port->edgeDelayWhile);
      rstpDecrementTimer(&port->txCount);
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

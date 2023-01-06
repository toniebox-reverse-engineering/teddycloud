/**
 * @file rstp_bdm.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL RSTP_TRACE_LEVEL

//Dependencies
#include "rstp/rstp.h"
#include "rstp/rstp_fsm.h"
#include "rstp/rstp_bdm.h"
#include "rstp/rstp_conditions.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//BDM state machine's states
const RstpParamName rstpBdmStates[] =
{
   {RSTP_BDM_STATE_EDGE,     "EDGE"},
   {RSTP_BDM_STATE_NOT_EDGE, "NOT_EDGE"}
};


/**
 * @brief BDM state machine initialization
 * @param[in] port Pointer to the bridge port context
 **/

void rstpBdmInit(RstpBridgePort *port)
{
   //Enter initial state
   if(rstpAdminEdge(port))
   {
      rstpBdmChangeState(port, RSTP_BDM_STATE_EDGE);
   }
   else
   {
      rstpBdmChangeState(port, RSTP_BDM_STATE_NOT_EDGE);
   }
}


/**
 * @brief BDM state machine implementation
 * @param[in] port Pointer to the bridge port context
 **/

void rstpBdmFsm(RstpBridgePort *port)
{
   //All conditions for the current state are evaluated continuously until one
   //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->bdmState)
   {
   //EDGE state?
   case RSTP_BDM_STATE_EDGE:
      //Evaluate conditions for the current state
      if((!port->portEnabled && !rstpAdminEdge(port)) || !port->operEdge)
      {
         //Switch to NOT_EDGE state
         rstpBdmChangeState(port, RSTP_BDM_STATE_NOT_EDGE);
      }

      break;

   //NOT_EDGE state?
   case RSTP_BDM_STATE_NOT_EDGE:
      //Evaluate conditions for the current state
      if((!port->portEnabled && rstpAdminEdge(port)) ||
         (port->edgeDelayWhile == 0 && rstpAutoEdge(port) &&
         port->sendRstp && port->proposing))
      {
         //Switch to EDGE state
         rstpBdmChangeState(port, RSTP_BDM_STATE_EDGE);
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
 * @brief Update BDM state machine state
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpBdmChangeState(RstpBridgePort *port, RstpBdmState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": BDM state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->bdmState, rstpBdmStates, arraysize(rstpBdmStates)),
      rstpGetParamName(newState, rstpBdmStates, arraysize(rstpBdmStates)));

   //Switch to the new state
   port->bdmState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->bdmState)
   {
   //EDGE state?
   case RSTP_BDM_STATE_EDGE:
      //Set operEdge flag
      port->operEdge = TRUE;
      break;

   //NOT_EDGE state?
   case RSTP_BDM_STATE_NOT_EDGE:
      //Clear operEdge flag
      port->operEdge = FALSE;
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

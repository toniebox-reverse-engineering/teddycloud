/**
 * @file rstp_prx.c
 * @brief Port Receive state machine (PRX)
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
#include "rstp/rstp_prx.h"
#include "rstp/rstp_procedures.h"
#include "rstp/rstp_conditions.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//PRX state machine's states
const RstpParamName rstpPrxStates[] =
{
   {RSTP_PRX_STATE_DISCARD, "DISCARD"},
   {RSTP_PRX_STATE_RECEIVE, "RECEIVE"}
};


/**
 * @brief PRX state machine initialization
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPrxInit(RstpBridgePort *port)
{
   //Enter initial state
   rstpPrxChangeState(port, RSTP_PRX_STATE_DISCARD);
}


/**
 * @brief PRX state machine implementation
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPrxFsm(RstpBridgePort *port)
{
   //A global transition can occur from any of the possible states
   if((port->rcvdBpdu || port->edgeDelayWhile != rstpMigrateTime(port->context)) &&
      !port->portEnabled)
   {
      //When the condition associated with a global transition is met, it
      //supersedes all other exit conditions
      rstpPrxChangeState(port, RSTP_PRX_STATE_DISCARD);
   }
   else
   {
      //All conditions for the current state are evaluated continuously until one
      //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
      switch(port->prxState)
      {
      //DISCARD state?
      case RSTP_PRX_STATE_DISCARD:
         //Check whether a valid BPDU has been received
         if(port->rcvdBpdu && port->portEnabled)
         {
            //Switch to RECEIVE state
            rstpPrxChangeState(port, RSTP_PRX_STATE_RECEIVE);
         }

         break;

      //RECEIVE state?
      case RSTP_PRX_STATE_RECEIVE:
         //Check whether a valid BPDU has been received
         if(port->rcvdBpdu && port->portEnabled && !port->rcvdMsg)
         {
            //Switch to RECEIVE state
            rstpPrxChangeState(port, RSTP_PRX_STATE_RECEIVE);
         }

         break;

      //Invalid state?
      default:
         //Just for sanity
         rstpFsmError(port->context);
         break;
      }
   }
}


/**
 * @brief Update PRX state machine state
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpPrxChangeState(RstpBridgePort *port, RstpPrxState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": PRX state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->prxState, rstpPrxStates, arraysize(rstpPrxStates)),
      rstpGetParamName(newState, rstpPrxStates, arraysize(rstpPrxStates)));

   //Switch to the new state
   port->prxState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->prxState)
   {
   //DISCARD state?
   case RSTP_PRX_STATE_DISCARD:
      //Clear flags
      port->rcvdBpdu = FALSE;
      port->rcvdRstp = FALSE;
      port->rcvdStp = FALSE;
      port->rcvdMsg = FALSE;

      //Reload the Edge Delay timer
      port->edgeDelayWhile = rstpMigrateTime(port->context);
      break;

   //RECEIVE state?
   case RSTP_PRX_STATE_RECEIVE:
      //Either rcvdRSTP or rcvdSTP is set to communicate the BPDU's arrival
      //and type to the Port Protocol Migration state machine
      rstpUpdtBpduVersion(port);
      port->operEdge = FALSE;
      port->rcvdBpdu = FALSE;

      //Set rcvdMsg to communicate the BPDU's arrival to the Port Information
      //state machine
      port->rcvdMsg = TRUE;

      //Reload the Edge Delay timer
      port->edgeDelayWhile = rstpMigrateTime(port->context);
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

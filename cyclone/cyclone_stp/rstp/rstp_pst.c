/**
 * @file rstp_pst.c
 * @brief Port State Transition state machine (PST)
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
#include "rstp/rstp_pst.h"
#include "rstp/rstp_procedures.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//PST state machine's states
const RstpParamName rstpPstStates[] =
{
   {RSTP_PST_STATE_DISCARDING, "DISCARDING"},
   {RSTP_PST_STATE_LEARNING,   "LEARNING"},
   {RSTP_PST_STATE_FORWARDING, "FORWARDING"}
};


/**
 * @brief PST state machine initialization
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPstInit(RstpBridgePort *port)
{
   //Enter initial state
   rstpPstChangeState(port, RSTP_PST_STATE_DISCARDING);
}


/**
 * @brief PST state machine implementation
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPstFsm(RstpBridgePort *port)
{
   //All conditions for the current state are evaluated continuously until one
   //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->pstState)
   {
   //DISCARDING state?
   case RSTP_PST_STATE_DISCARDING:
      //Check the learn flag
      if(port->learn)
      {
         //Enable learning
         rstpPstChangeState(port, RSTP_PST_STATE_LEARNING);
      }

      break;

   //LEARNING state?
   case RSTP_PST_STATE_LEARNING:
      //Check the learn and forward flags
      if(port->forward)
      {
         //Enable forwarding
         rstpPstChangeState(port, RSTP_PST_STATE_FORWARDING);
      }
      else if(!port->learn)
      {
         //Disable learning
         rstpPstChangeState(port, RSTP_PST_STATE_DISCARDING);
      }
      else
      {
         //Just for sanity
      }

      break;

   //FORWARDING state?
   case RSTP_PST_STATE_FORWARDING:
      //Check the forward flag
      if(!port->forward)
      {
         //Disable learning and forwarding
         rstpPstChangeState(port, RSTP_PST_STATE_DISCARDING);
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
 * @brief Update PST state machine state
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpPstChangeState(RstpBridgePort *port, RstpPstState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": PST state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->pstState, rstpPstStates, arraysize(rstpPstStates)),
      rstpGetParamName(newState, rstpPstStates, arraysize(rstpPstStates)));

   //Switch to the new state
   port->pstState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->pstState)
   {
   //DISCARDING state?
   case RSTP_PST_STATE_DISCARDING:
      //Disable learning and forwarding
      rstpDisableLearning(port);
      port->learning = FALSE;
      rstpDisableForwarding(port);
      port->forwarding = FALSE;
      break;

   //LEARNING state?
   case RSTP_PST_STATE_LEARNING:
      //Enable learning
      rstpEnableLearning(port);
      port->learning = TRUE;
      break;

   //FORWARDING state?
   case RSTP_PST_STATE_FORWARDING:
      //Enable forwarding
      rstpEnableForwarding(port);
      port->forwarding = TRUE;
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

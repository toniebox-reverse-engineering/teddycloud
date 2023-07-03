/**
 * @file rstp_tcm.c
 * @brief Topology change state machine (TCM)
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
#include "rstp/rstp_tcm.h"
#include "rstp/rstp_procedures.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//TCM state machine's states
const RstpParamName rstpTcmStates[] =
{
   {RSTP_TCM_STATE_INACTIVE,     "INACTIVE"},
   {RSTP_TCM_STATE_LEARNING,     "LEARNING"},
   {RSTP_TCM_STATE_DETECTED,     "DETECTED"},
   {RSTP_TCM_STATE_NOTIFIED_TCN, "NOTIFIED_TCN"},
   {RSTP_TCM_STATE_NOTIFIED_TC,  "NOTIFIED_TC"},
   {RSTP_TCM_STATE_PROPAGATING,  "PROPAGATING"},
   {RSTP_TCM_STATE_ACKNOWLEDGED, "ACKNOWLEDGED"},
   {RSTP_TCM_STATE_ACTIVE,       "ACTIVE"}
};


/**
 * @brief TCM state machine initialization
 * @param[in] port Pointer to the bridge port context
 **/

void rstpTcmInit(RstpBridgePort *port)
{
   //Enter initial state
   rstpTcmChangeState(port, RSTP_TCM_STATE_INACTIVE);
}


/**
 * @brief TCM state machine implementation
 * @param[in] port Pointer to the bridge port context
 **/

void rstpTcmFsm(RstpBridgePort *port)
{
   //All conditions for the current state are evaluated continuously until one
   //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->tcmState)
   {
   //INACTIVE state?
   case RSTP_TCM_STATE_INACTIVE:
      //Evaluate conditions for the current state
      if(port->learn && !port->fdbFlush)
      {
         //Switch to LEARNING state
         rstpTcmChangeState(port, RSTP_TCM_STATE_LEARNING);
      }

      break;

   //LEARNING state?
   case RSTP_TCM_STATE_LEARNING:
      //Evaluate conditions for the current state
      if(port->rcvdTc || port->rcvdTcn || port->rcvdTcAck || port->tcProp)
      {
         //Switch to LEARNING state
         rstpTcmChangeState(port, RSTP_TCM_STATE_LEARNING);
      }
      else if((port->role == STP_PORT_ROLE_ROOT ||
         port->role == STP_PORT_ROLE_DESIGNATED) &&
         port->forward && !port->operEdge)
      {
         //Switch to DETECTED state
         rstpTcmChangeState(port, RSTP_TCM_STATE_DETECTED);
      }
      else if(port->role != STP_PORT_ROLE_ROOT &&
         port->role != STP_PORT_ROLE_DESIGNATED &&
         !(port->learn || port->learning) &&
         !(port->rcvdTc || port->rcvdTcn || port->rcvdTcAck || port->tcProp))
      {
         //Switch to INACTIVE state
         rstpTcmChangeState(port, RSTP_TCM_STATE_INACTIVE);
      }
      else
      {
         //Just for sanity
      }

      break;

   //NOTIFIED_TCN state?
   case RSTP_TCM_STATE_NOTIFIED_TCN:
      //Unconditional transition (UCT) to NOTIFIED_TC state
      rstpTcmChangeState(port, RSTP_TCM_STATE_NOTIFIED_TC);
      break;

   //DETECTED, NOTIFIED_TC, PROPAGATING or ACKNOWLEDGED state?
   case RSTP_TCM_STATE_DETECTED:
   case RSTP_TCM_STATE_NOTIFIED_TC:
   case RSTP_TCM_STATE_PROPAGATING:
   case RSTP_TCM_STATE_ACKNOWLEDGED:
      //Unconditional transition (UCT) to ACTIVE state
      rstpTcmChangeState(port, RSTP_TCM_STATE_ACTIVE);
      break;

   //ACTIVE state?
   case RSTP_TCM_STATE_ACTIVE:
      //Evaluate conditions for the current state
      if((port->role != STP_PORT_ROLE_ROOT &&
         port->role != STP_PORT_ROLE_DESIGNATED) || port->operEdge)
      {
         //Switch to LEARNING state
         rstpTcmChangeState(port, RSTP_TCM_STATE_LEARNING);
      }
      else if(port->rcvdTcn)
      {
         //Switch to NOTIFIED_TCN state
         rstpTcmChangeState(port, RSTP_TCM_STATE_NOTIFIED_TCN);
      }
      else if(port->rcvdTc)
      {
         //Switch to NOTIFIED_TC state
         rstpTcmChangeState(port, RSTP_TCM_STATE_NOTIFIED_TC);
      }
      else if(port->tcProp && !port->operEdge)
      {
         //Switch to PROPAGATING state
         rstpTcmChangeState(port, RSTP_TCM_STATE_PROPAGATING);
      }
      else if(port->rcvdTcAck)
      {
         //Switch to ACKNOWLEDGED state
         rstpTcmChangeState(port, RSTP_TCM_STATE_ACKNOWLEDGED);
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
 * @brief Update TCM state machine state
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpTcmChangeState(RstpBridgePort *port, RstpTcmState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": TCM state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->tcmState, rstpTcmStates, arraysize(rstpTcmStates)),
      rstpGetParamName(newState, rstpTcmStates, arraysize(rstpTcmStates)));

   //Switch to the new state
   port->tcmState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->tcmState)
   {
   //INACTIVE state?
   case RSTP_TCM_STATE_INACTIVE:
      port->fdbFlush = TRUE;
      port->tcWhile = 0;
      port->tcAck = FALSE;
      break;

   //LEARNING state?
   case RSTP_TCM_STATE_LEARNING:
      port->rcvdTc = FALSE;
      port->rcvdTcn = FALSE;
      port->rcvdTcAck = FALSE;
      port->tcProp = FALSE;
      break;

   //DETECTED state?
   case RSTP_TCM_STATE_DETECTED:
      rstpNewTcWhile(port);
      rstpSetTcPropTree(port);
      port->newInfo = TRUE;
      break;

   //NOTIFIED_TCN state?
   case RSTP_TCM_STATE_NOTIFIED_TCN:
      rstpNewTcWhile(port);
      break;

   //NOTIFIED_TC state?
   case RSTP_TCM_STATE_NOTIFIED_TC:
      port->rcvdTcn = FALSE;
      port->rcvdTc = FALSE;

      if(port->role == STP_PORT_ROLE_DESIGNATED)
      {
         port->tcAck = TRUE;
      }

      //Errata (refer to IEEE Std 802.1Q-2018, section 13.39)
      rstpSetTcPropTree(port);
      break;

   //PROPAGATING state?
   case RSTP_TCM_STATE_PROPAGATING:
      rstpNewTcWhile(port);
      port->fdbFlush = TRUE;
      port->tcProp = FALSE;
      break;

   //ACKNOWLEDGED state?
   case RSTP_TCM_STATE_ACKNOWLEDGED:
      port->tcWhile = 0;
      port->rcvdTcAck = FALSE;
      break;

   //ACTIVE state?
   case RSTP_TCM_STATE_ACTIVE:
      //No procedure defined for this state
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

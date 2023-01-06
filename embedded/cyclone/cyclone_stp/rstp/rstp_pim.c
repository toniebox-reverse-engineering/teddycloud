/**
 * @file rstp_pim.c
 * @brief Port Information state machine (PIM)
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
#include "rstp/rstp_pim.h"
#include "rstp/rstp_procedures.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//PIM state machine's states
const RstpParamName rstpPimStates[] =
{
   {RSTP_PIM_STATE_DISABLED,            "DISABLED"},
   {RSTP_PIM_STATE_AGED,                "AGED"},
   {RSTP_PIM_STATE_UPDATE,              "UPDATE"},
   {RSTP_PIM_STATE_SUPERIOR_DESIGNATED, "SUPERIOR_DESIGNATED"},
   {RSTP_PIM_STATE_REPEATED_DESIGNATED, "REPEATED_DESIGNATED"},
   {RSTP_PIM_STATE_INFERIOR_DESIGNATED, "INFERIOR_DESIGNATED"},
   {RSTP_PIM_STATE_NOT_DESIGNATED,      "NOT_DESIGNATED"},
   {RSTP_PIM_STATE_OTHER,               "OTHER"},
   {RSTP_PIM_STATE_CURRENT,             "CURRENT"},
   {RSTP_PIM_STATE_RECEIVE,             "RECEIVE"}
};


/**
 * @brief PIM state machine initialization
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPimInit(RstpBridgePort *port)
{
   //Enter initial state
   rstpPimChangeState(port, RSTP_PIM_STATE_DISABLED);
}


/**
 * @brief PIM state machine implementation
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPimFsm(RstpBridgePort *port)
{
   //A global transition can occur from any of the possible states
   if(!port->portEnabled && port->infoIs != RSTP_INFO_IS_DISABLED)
   {
      //When the condition associated with a global transition is met, it
      //supersedes all other exit conditions
      rstpPimChangeState(port, RSTP_PIM_STATE_DISABLED);
   }
   else
   {
      //All conditions for the current state are evaluated continuously until one
      //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
      switch(port->pimState)
      {
      //DISABLED state?
      case RSTP_PIM_STATE_DISABLED:
         //Evaluate conditions for the current state
         if(port->rcvdMsg)
         {
            //Switch to DISABLED state
            rstpPimChangeState(port, RSTP_PIM_STATE_DISABLED);
         }
         else if(port->portEnabled)
         {
            //Switch to AGED state
            rstpPimChangeState(port, RSTP_PIM_STATE_AGED);
         }
         else
         {
            //Just for sanity
         }

         break;

      //AGED state?
      case RSTP_PIM_STATE_AGED:
         //Evaluate conditions for the current state
         if(port->selected && port->updtInfo)
         {
            //Switch to UPDATE state
            rstpPimChangeState(port, RSTP_PIM_STATE_UPDATE);
         }

         break;

      //UPDATE, SUPERIOR_DESIGNATED, REPEATED_DESIGNATED, INFERIOR_DESIGNATED,
      //NOT_DESIGNATED or OTHER state?
      case RSTP_PIM_STATE_UPDATE:
      case RSTP_PIM_STATE_SUPERIOR_DESIGNATED:
      case RSTP_PIM_STATE_REPEATED_DESIGNATED:
      case RSTP_PIM_STATE_INFERIOR_DESIGNATED:
      case RSTP_PIM_STATE_NOT_DESIGNATED:
      case RSTP_PIM_STATE_OTHER:
         //Unconditional transition (UCT) to CURRENT state
         rstpPimChangeState(port, RSTP_PIM_STATE_CURRENT);
         break;

      //CURRENT state?
      case RSTP_PIM_STATE_CURRENT:
         //Evaluate conditions for the current state
         if(port->selected && port->updtInfo)
         {
            //Switch to UPDATE state
            rstpPimChangeState(port, RSTP_PIM_STATE_UPDATE);
         }
         else if(port->infoIs == RSTP_INFO_IS_RECEIVED &&
            port->rcvdInfoWhile == 0 && !port->updtInfo && !port->rcvdMsg)
         {
            //Switch to AGED state
            rstpPimChangeState(port, RSTP_PIM_STATE_AGED);
         }
         else if(port->rcvdMsg && !port->updtInfo)
         {
            //Switch to RECEIVE state
            rstpPimChangeState(port, RSTP_PIM_STATE_RECEIVE);
         }
         else
         {
            //Just for sanity
         }

         break;

      //RECEIVE state?
      case RSTP_PIM_STATE_RECEIVE:
         //Evaluate conditions for the current state
         if(port->rcvdInfo == RSTP_RCVD_INFO_SUPERIOR_DESIGNATED)
         {
            //Switch to SUPERIOR_DESIGNATED state
            rstpPimChangeState(port, RSTP_PIM_STATE_SUPERIOR_DESIGNATED);
         }
         else if(port->rcvdInfo == RSTP_RCVD_INFO_REPEATED_DESIGNATED)
         {
            //Switch to REPEATED_DESIGNATED state
            rstpPimChangeState(port, RSTP_PIM_STATE_REPEATED_DESIGNATED);
         }
         else if(port->rcvdInfo == RSTP_RCVD_INFO_INFERIOR_DESIGNATED)
         {
            //Switch to INFERIOR_DESIGNATED state
            rstpPimChangeState(port, RSTP_PIM_STATE_INFERIOR_DESIGNATED);
         }
         else if(port->rcvdInfo == RSTP_RCVD_INFO_INFERIOR_ROOT_ALTERNATE)
         {
            //Switch to NOT_DESIGNATED state
            rstpPimChangeState(port, RSTP_PIM_STATE_NOT_DESIGNATED);
         }
         else if(port->rcvdInfo == RSTP_RCVD_INFO_OTHER)
         {
            //Switch to OTHER state
            rstpPimChangeState(port, RSTP_PIM_STATE_OTHER);
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
}


/**
 * @brief Update PIM state machine state
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpPimChangeState(RstpBridgePort *port, RstpPimState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": PIM state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->pimState, rstpPimStates, arraysize(rstpPimStates)),
      rstpGetParamName(newState, rstpPimStates, arraysize(rstpPimStates)));

   //Switch to the new state
   port->pimState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->pimState)
   {
   //DISABLED state?
   case RSTP_PIM_STATE_DISABLED:
      //Clear variables
      port->rcvdMsg = FALSE;
      port->proposing = FALSE;
      port->proposed = FALSE;
      port->agree = FALSE;
      port->agreed = FALSE;
      port->rcvdInfoWhile = 0;
      port->infoIs = RSTP_INFO_IS_DISABLED;
      port->reselect = TRUE;
      port->selected = FALSE;
      break;

   //AGED state?
   case RSTP_PIM_STATE_AGED:
      //The Spanning Tree information received by this port is aged out
      port->infoIs = RSTP_INFO_IS_AGED;
      port->reselect = TRUE;
      port->selected = FALSE;
      break;

   //UPDATE state?
   case RSTP_PIM_STATE_UPDATE:
      port->proposing = FALSE;
      port->proposed = FALSE;

      //Errata (refer to IEEE Std 802.1Q-2018, section 13.35)
      port->agreed = port->agreed &&
         rstpBetterOrSameInfo(port, RSTP_INFO_IS_MINE);

#if defined(RSTP_PIM_WORKAROUND_1)
      //Errata
      if(port->forward)
      {
         port->agreed = port->sendRstp;
      }
#endif

      port->synced = port->synced && port->agreed;
      port->portPriority = port->designatedPriority;
      port->portTimes = port->designatedTimes;
      port->updtInfo = FALSE;
      port->infoIs = RSTP_INFO_IS_MINE;
      port->newInfo = TRUE;
      break;

   //SUPERIOR_DESIGNATED state?
   case RSTP_PIM_STATE_SUPERIOR_DESIGNATED:
      port->agreed = FALSE;
      port->proposing = FALSE;
      rstpRecordProposal(port);
      rstpSetTcFlags(port);

      //Errata (refer to IEEE Std 802.1Q-2018, section 13.35)
      port->agree = port->agree &&
         rstpBetterOrSameInfo(port, RSTP_INFO_IS_RECEIVED);

      rstpRecordPriority(port);
      rstpRecordTimes(port);
      rstpUpdtRcvdInfoWhile(port);
      port->infoIs = RSTP_INFO_IS_RECEIVED;
      port->reselect = TRUE;
      port->selected = FALSE;
      port->rcvdMsg = FALSE;
      break;

   //REPEATED_DESIGNATED state?
   case RSTP_PIM_STATE_REPEATED_DESIGNATED:
      rstpRecordProposal(port);
      rstpSetTcFlags(port);
      rstpUpdtRcvdInfoWhile(port);
      port->rcvdMsg = FALSE;
      break;

   //INFERIOR_DESIGNATED state?
   case RSTP_PIM_STATE_INFERIOR_DESIGNATED:
      rstpRecordDispute(port);
      port->rcvdMsg = FALSE;
      break;

   //NOT_DESIGNATED state?
   case RSTP_PIM_STATE_NOT_DESIGNATED:
      rstpRecordAgreement(port);
      rstpSetTcFlags(port);
      port->rcvdMsg = FALSE;
      break;

   //OTHER state?
   case RSTP_PIM_STATE_OTHER:
      port->rcvdMsg = FALSE;
      break;

   //CURRENT state?
   case RSTP_PIM_STATE_CURRENT:
      //No procedure defined for this state
      break;

   //RECEIVE state?
   case RSTP_PIM_STATE_RECEIVE:
      port->rcvdInfo = rstpRcvInfo(port);
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

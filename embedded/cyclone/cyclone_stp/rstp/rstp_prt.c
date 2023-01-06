/**
 * @file rstp_prt.c
 * @brief Port Role Transition state machine (PRT)
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
#include "rstp/rstp_prt.h"
#include "rstp/rstp_procedures.h"
#include "rstp/rstp_conditions.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//PRT state machine's states
const RstpParamName rstpPrtStates[] =
{
   {RSTP_PRT_STATE_INIT_PORT,          "INIT_PORT"},
   {RSTP_PRT_STATE_DISABLE_PORT,       "DISABLE_PORT"},
   {RSTP_PRT_STATE_DISABLED_PORT,      "DISABLED_PORT"},
   {RSTP_PRT_STATE_ROOT_PROPOSED,      "ROOT_PROPOSED"},
   {RSTP_PRT_STATE_ROOT_AGREED,        "ROOT_AGREED"},
   {RSTP_PRT_STATE_REROOT,             "REROOT"},
   {RSTP_PRT_STATE_ROOT_FORWARD,       "ROOT_FORWARD"},
   {RSTP_PRT_STATE_ROOT_LEARN,         "ROOT_LEARN"},
   {RSTP_PRT_STATE_REROOTED,           "REROOTED"},
   {RSTP_PRT_STATE_ROOT_PORT,          "ROOT_PORT"},
   {RSTP_PRT_STATE_DESIGNATED_PROPOSE, "DESIGNATED_PROPOSE"},
   {RSTP_PRT_STATE_DESIGNATED_SYNCED,  "DESIGNATED_SYNCED"},
   {RSTP_PRT_STATE_DESIGNATED_RETIRED, "DESIGNATED_RETIRED"},
   {RSTP_PRT_STATE_DESIGNATED_FORWARD, "DESIGNATED_FORWARD"},
   {RSTP_PRT_STATE_DESIGNATED_LEARN,   "DESIGNATED_LEARN"},
   {RSTP_PRT_STATE_DESIGNATED_DISCARD, "DESIGNATED_DISCARD"},
   {RSTP_PRT_STATE_DESIGNATED_PORT,    "DESIGNATED_PORT"},
   {RSTP_PRT_STATE_ALTERNATE_PROPOSED, "ALTERNATE_PROPOSED"},
   {RSTP_PRT_STATE_ALTERNATE_AGREED,   "ALTERNATE_AGREED"},
   {RSTP_PRT_STATE_BLOCK_PORT,         "BLOCK_PORT"},
   {RSTP_PRT_STATE_BACKUP_PORT,        "BACKUP_PORT"},
   {RSTP_PRT_STATE_ALTERNATE_PORT,     "ALTERNATE_PORT"}
};


/**
 * @brief PRT state machine initialization
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPrtInit(RstpBridgePort *port)
{
   //Enter initial state
   rstpPrtDisabledPortChangeState(port, RSTP_PRT_STATE_INIT_PORT);
}


/**
 * @brief PRT state machine implementation
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPrtFsm(RstpBridgePort *port)
{
   //The selected port role is updated by Port Role Selection state machine
   if(port->role != port->selectedRole)
   {
      //Check the newly computed role for the port
      switch(port->selectedRole)
      {
      case STP_PORT_ROLE_DISABLED:
         //Switch to Disabled port role
         rstpPrtDisabledPortChangeState(port, RSTP_PRT_STATE_DISABLE_PORT);
         break;

      case STP_PORT_ROLE_ROOT:
         //Switch to Root port role
         rstpPrtRootPortChangeState(port, RSTP_PRT_STATE_ROOT_PORT);
         break;

      case STP_PORT_ROLE_DESIGNATED:
         //Switch to Designated port role
         rstpPrtDesignatedPortChangeState(port, RSTP_PRT_STATE_DESIGNATED_PORT);
         break;

      case STP_PORT_ROLE_ALTERNATE:
      case STP_PORT_ROLE_BACKUP:
         //Switch to Alternate or Backup port role
         rstpPrtAlternatePortChangeState(port, RSTP_PRT_STATE_BLOCK_PORT);
         break;

      default:
         //Just for sanity
         rstpFsmError(port->context);
         break;
      }
   }
   else
   {
      //Check current port role
      switch(port->role)
      {
      case STP_PORT_ROLE_DISABLED:
         //Process the states associated with the Disabled port role
         rstpPrtDisabledPortFsm(port);
         break;

      case STP_PORT_ROLE_ROOT:
         //Process the states associated with the Root port role
         rstpPrtRootPortFsm(port);
         break;

      case STP_PORT_ROLE_DESIGNATED:
         //Process the states associated with the Designated port role
         rstpPrtDesignatedPortFsm(port);
         break;

      case STP_PORT_ROLE_ALTERNATE:
      case STP_PORT_ROLE_BACKUP:
         //Process the states associated with the Alternate or Backup port role
         rstpPrtAlternatePortFsm(port);
         break;

      default:
         //Just for sanity
         rstpFsmError(port->context);
         break;
      }
   }
}


/**
 * @brief PRT state machine implementation (Disabled port role)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPrtDisabledPortFsm(RstpBridgePort *port)
{
   //All conditions for the current state are evaluated continuously until one
   //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->prtState)
   {
   //INIT_PORT state?
   case RSTP_PRT_STATE_INIT_PORT:
      //Unconditional transition (UCT) to DISABLE_PORT state
      rstpPrtDisabledPortChangeState(port, RSTP_PRT_STATE_DISABLE_PORT);
      break;

   //DISABLE_PORT state?
   case RSTP_PRT_STATE_DISABLE_PORT:
      //All transitions, except UCT, are qualified by the following condition
      if(port->selected && !port->updtInfo)
      {
         //Check the learning and forwarding flags
         if(!port->learning && !port->forwarding)
         {
            //Switch to DISABLED_PORT state
            rstpPrtDisabledPortChangeState(port, RSTP_PRT_STATE_DISABLED_PORT);
         }
      }

      break;

   //DISABLED_PORT state?
   case RSTP_PRT_STATE_DISABLED_PORT:
      //All transitions, except UCT, are qualified by the following condition
      if(port->selected && !port->updtInfo)
      {
         //Evaluate conditions for the current state
         if(port->fdWhile != rstpMaxAge(port) || port->sync || port->reRoot ||
            !port->synced)
         {
            //Switch to DISABLED_PORT state
            rstpPrtDisabledPortChangeState(port, RSTP_PRT_STATE_DISABLED_PORT);
         }
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
 * @brief Update PRT state machine state (Disabled port role)
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpPrtDisabledPortChangeState(RstpBridgePort *port, RstpPrtState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": PRT state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->prtState, rstpPrtStates, arraysize(rstpPrtStates)),
      rstpGetParamName(newState, rstpPrtStates, arraysize(rstpPrtStates)));

   //Switch to the new state
   port->prtState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->prtState)
   {
   //INIT_PORT state?
   case RSTP_PRT_STATE_INIT_PORT:
      //Initialize variables
      port->role = STP_PORT_ROLE_DISABLED;
      port->learn = FALSE;
      port->forward = FALSE;
      port->synced = FALSE;
      port->sync = TRUE;
      port->reRoot = TRUE;
      port->rrWhile = rstpFwdDelay(port);
      port->fdWhile = rstpMaxAge(port);
      port->rbWhile = 0;
      break;

   //DISABLE_PORT state?
   case RSTP_PRT_STATE_DISABLE_PORT:
      //Update port role
      port->role = port->selectedRole;
      port->learn = FALSE;
      port->forward = FALSE;
      break;

   //DISABLED_PORT state?
   case RSTP_PRT_STATE_DISABLED_PORT:
      //Reload the Forward Delay timer
      port->fdWhile = rstpMaxAge(port);
      port->synced = TRUE;
      port->rrWhile = 0;
      port->sync = FALSE;
      port->reRoot = FALSE;
      break;

   //Invalid state?
   default:
      //Just for sanity
      break;
   }

   //The RSTP state machine is busy
   port->context->busy = TRUE;
}


/**
 * @brief PRT state machine implementation (Root port role)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPrtRootPortFsm(RstpBridgePort *port)
{
   //All conditions for the current state are evaluated continuously until one
   //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->prtState)
   {
   //ROOT_PROPOSED, ROOT_AGREED, REROOT, ROOT_FORWARD, ROOT_LEARN or REROOTED
   //state?
   case RSTP_PRT_STATE_ROOT_PROPOSED:
   case RSTP_PRT_STATE_ROOT_AGREED:
   case RSTP_PRT_STATE_REROOT:
   case RSTP_PRT_STATE_ROOT_FORWARD:
   case RSTP_PRT_STATE_ROOT_LEARN:
   case RSTP_PRT_STATE_REROOTED:
      //Unconditional transition (UCT) to ROOT_PORT state
      rstpPrtRootPortChangeState(port, RSTP_PRT_STATE_ROOT_PORT);
      break;

   //ROOT_PORT state?
   case RSTP_PRT_STATE_ROOT_PORT:
      //All transitions, except UCT, are qualified by the following condition
      if(port->selected && !port->updtInfo)
      {
         //Evaluate conditions for the current state
         if(port->proposed && !port->agree)
         {
            //Switch to ROOT_PROPOSED state
            rstpPrtRootPortChangeState(port, RSTP_PRT_STATE_ROOT_PROPOSED);
         }
         else if((rstpAllSynced(port->context) && !port->agree) ||
            (port->proposed && port->agree))
         {
            //Switch to ROOT_AGREED state
            rstpPrtRootPortChangeState(port, RSTP_PRT_STATE_ROOT_AGREED);
         }
         else if(!port->forward && !port->reRoot)
         {
            //Switch to REROOT state
            rstpPrtRootPortChangeState(port, RSTP_PRT_STATE_REROOT);
         }
         else if(port->rrWhile != rstpFwdDelay(port))
         {
            //Switch to ROOT_PORT state
            rstpPrtRootPortChangeState(port, RSTP_PRT_STATE_ROOT_PORT);
         }
         else if(port->reRoot && port->forward)
         {
            //Switch to REROOTED state
            rstpPrtRootPortChangeState(port, RSTP_PRT_STATE_REROOTED);
         }
         else if(port->fdWhile == 0 || (rstpReRooted(port) &&
            port->rbWhile == 0 && rstpVersion(port->context)))
         {
            //The Root port can transition to Learning and to Forwarding
            if(!port->learn)
            {
               //Switch to ROOT_LEARN state
               rstpPrtRootPortChangeState(port, RSTP_PRT_STATE_ROOT_LEARN);
            }
            else if(port->learn && !port->forward)
            {
               //Switch to ROOT_FORWARD state
               rstpPrtRootPortChangeState(port, RSTP_PRT_STATE_ROOT_FORWARD);
            }
            else
            {
               //Just for sanity
            }
         }
         else
         {
            //Just for sanity
         }
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
 * @brief Update PRT state machine state (Root port role)
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpPrtRootPortChangeState(RstpBridgePort *port, RstpPrtState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": PRT state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->prtState, rstpPrtStates, arraysize(rstpPrtStates)),
      rstpGetParamName(newState, rstpPrtStates, arraysize(rstpPrtStates)));

   //Switch to the new state
   port->prtState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->prtState)
   {
   //ROOT_PROPOSED state?
   case RSTP_PRT_STATE_ROOT_PROPOSED:
      //Proposal
      rstpSetSyncTree(port->context);
      port->proposed = FALSE;
      break;

   //ROOT_AGREED state?
   case RSTP_PRT_STATE_ROOT_AGREED:
      //Agreement
      port->proposed = FALSE;
      port->sync = FALSE;
      port->agree = TRUE;
      port->newInfo = TRUE;
      break;

   //REROOT state?
   case RSTP_PRT_STATE_REROOT:
      //Set reRoot for all bridge ports
      rstpSetReRootTree(port->context);
      break;

   //ROOT_FORWARD state?
   case RSTP_PRT_STATE_ROOT_FORWARD:
      //The forward variable is used by this state machine to request the
      //Port State Transitions machine to change the port state
      port->fdWhile = 0;
      port->forward = TRUE;
      break;

   //ROOT_LEARN state?
   case RSTP_PRT_STATE_ROOT_LEARN:
      //The learn variable is used by this state machine to request the
      //Port State Transitions machine to change the port state
      port->fdWhile= rstpForwardDelay(port);
      port->learn = TRUE;
      break;

   //REROOTED state?
   case RSTP_PRT_STATE_REROOTED:
      //Clear the reRoot variable
      port->reRoot = FALSE;
      break;

   //ROOT_PORT state?
   case RSTP_PRT_STATE_ROOT_PORT:
      //Update port role
      port->role = STP_PORT_ROLE_ROOT;
      port->rrWhile = rstpFwdDelay(port);
      break;

   //Invalid state?
   default:
      //Just for sanity
      break;
   }

   //The RSTP state machine is busy
   port->context->busy = TRUE;
}


/**
 * @brief PRT state machine implementation (Designated port role)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPrtDesignatedPortFsm(RstpBridgePort *port)
{
   //All conditions for the current state are evaluated continuously until one
   //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->prtState)
   {
   //DESIGNATED_PROPOSE, DESIGNATED_SYNCED, DESIGNATED_RETIRED,
   //DESIGNATED_FORWARD, DESIGNATED_LEARN or DESIGNATED_DISCARD state?
   case RSTP_PRT_STATE_DESIGNATED_PROPOSE:
   case RSTP_PRT_STATE_DESIGNATED_SYNCED:
   case RSTP_PRT_STATE_DESIGNATED_RETIRED:
   case RSTP_PRT_STATE_DESIGNATED_FORWARD:
   case RSTP_PRT_STATE_DESIGNATED_LEARN:
   case RSTP_PRT_STATE_DESIGNATED_DISCARD:
      //Unconditional transition (UCT) to DESIGNATED_PORT state
      rstpPrtDesignatedPortChangeState(port, RSTP_PRT_STATE_DESIGNATED_PORT);
      break;

   //DESIGNATED_PORT state?
   case RSTP_PRT_STATE_DESIGNATED_PORT:
      //All transitions, except UCT, are qualified by the following condition
      if(port->selected && !port->updtInfo)
      {
         //Evaluate conditions for the current state
         if(!port->forward && !port->agreed && !port->proposing &&
            !port->operEdge)
         {
            //Switch to DESIGNATED_PROPOSE state
            rstpPrtDesignatedPortChangeState(port, RSTP_PRT_STATE_DESIGNATED_PROPOSE);
         }
         else if((!port->learning && !port->forwarding && !port->synced) ||
            (port->agreed && !port->synced) || (port->operEdge && !port->synced) ||
            (port->sync && port->synced))
         {
            //Switch to DESIGNATED_SYNCED state
            rstpPrtDesignatedPortChangeState(port, RSTP_PRT_STATE_DESIGNATED_SYNCED);
         }
         else if(port->rrWhile == 0 && port->reRoot)
         {
            //Switch to DESIGNATED_RETIRED state
            rstpPrtDesignatedPortChangeState(port, RSTP_PRT_STATE_DESIGNATED_RETIRED);
         }
         else if(((port->sync && !port->synced) || (port->reRoot && port->rrWhile != 0) ||
            port->disputed) && !port->operEdge && (port->learn || port->forward))
         {
            //Switch to DESIGNATED_DISCARD state
            rstpPrtDesignatedPortChangeState(port, RSTP_PRT_STATE_DESIGNATED_DISCARD);
         }
         else if((port->fdWhile == 0 || port->agreed || port->operEdge) &&
            (port->rrWhile == 0 || !port->reRoot) && !port->sync)
         {
            //The Designated port can transition to Learning and to Forwarding
            if(!port->learn)
            {
               //Switch to DESIGNATED_LEARN state
               rstpPrtDesignatedPortChangeState(port, RSTP_PRT_STATE_DESIGNATED_LEARN);
            }
            else if(port->learn && !port->forward)
            {
               //Switch to DESIGNATED_FORWARD state
               rstpPrtDesignatedPortChangeState(port, RSTP_PRT_STATE_DESIGNATED_FORWARD);
            }
            else
            {
               //Just for sanity
            }
         }
         else
         {
            //Just for sanity
         }
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
 * @brief Update PRT state machine state (Designated port role)
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpPrtDesignatedPortChangeState(RstpBridgePort *port, RstpPrtState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": PRT state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->prtState, rstpPrtStates, arraysize(rstpPrtStates)),
      rstpGetParamName(newState, rstpPrtStates, arraysize(rstpPrtStates)));

   //Switch to the new state
   port->prtState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->prtState)
   {
   //DESIGNATED_PROPOSE state?
   case RSTP_PRT_STATE_DESIGNATED_PROPOSE:
      //When a Designated port is in a Discarding or Learning state (and only
      //in this case), it sets the proposal bit on the BPDUs it sends out
      port->proposing = TRUE;
      port->edgeDelayWhile = rstpEdgeDelay(port);
      port->newInfo = TRUE;
      break;

   //DESIGNATED_SYNCED state?
   case RSTP_PRT_STATE_DESIGNATED_SYNCED:
      //Synchronize the port state with spanning tree information
      port->rrWhile = 0;
      port->synced = TRUE;
      port->sync = FALSE;
      break;

   //DESIGNATED_RETIRED state?
   case RSTP_PRT_STATE_DESIGNATED_RETIRED:
      //Clear the reRoot variable
      port->reRoot = FALSE;
      break;

   //DESIGNATED_FORWARD state?
   case RSTP_PRT_STATE_DESIGNATED_FORWARD:
      //The forward variable is used by this state machine to request the
      //Port State Transitions machine to change the port state
      port->forward = TRUE;
      port->fdWhile = 0;
      port->agreed = port->sendRstp;
      break;

   //DESIGNATED_LEARN state?
   case RSTP_PRT_STATE_DESIGNATED_LEARN:
      //The learn variable is used by this state machine to request the
      //Port State Transitions machine to change the port state
      port->learn = TRUE;
      port->fdWhile= rstpForwardDelay(port);
      break;

   //DESIGNATED_DISCARD state?
   case RSTP_PRT_STATE_DESIGNATED_DISCARD:
      //Transition the Designated port to Discarding
      port->learn = FALSE;
      port->forward = FALSE;
      port->disputed = FALSE;
      port->fdWhile = rstpForwardDelay(port);
      break;

   //DESIGNATED_PORT state?
   case RSTP_PRT_STATE_DESIGNATED_PORT:
      //Update port role
      port->role = STP_PORT_ROLE_DESIGNATED;
      break;

   //Invalid state?
   default:
      //Just for sanity
      break;
   }

   //The RSTP state machine is busy
   port->context->busy = TRUE;
}


/**
 * @brief PRT state machine implementation (Alternate or Backup port role)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPrtAlternatePortFsm(RstpBridgePort *port)
{
   //All conditions for the current state are evaluated continuously until one
   //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->prtState)
   {
   //ALTERNATE_PROPOSED, ALTERNATE_AGREED or BACKUP_PORT state?
   case RSTP_PRT_STATE_ALTERNATE_PROPOSED:
   case RSTP_PRT_STATE_ALTERNATE_AGREED:
   case RSTP_PRT_STATE_BACKUP_PORT:
      //Unconditional transition (UCT) to ALTERNATE_PORT state
      rstpPrtAlternatePortChangeState(port, RSTP_PRT_STATE_ALTERNATE_PORT);
      break;

   //BLOCK_PORT state?
   case RSTP_PRT_STATE_BLOCK_PORT:
      //All transitions, except UCT, are qualified by the following condition
      if(port->selected && !port->updtInfo)
      {
         //Check the learning and forwarding flags
         if(!port->learning && !port->forwarding)
         {
            //Switch to ALTERNATE_PORT state
            rstpPrtAlternatePortChangeState(port, RSTP_PRT_STATE_ALTERNATE_PORT);
         }
      }

      break;

   //ALTERNATE_PORT state?
   case RSTP_PRT_STATE_ALTERNATE_PORT:
      //All transitions, except UCT, are qualified by the following condition
      if(port->selected && !port->updtInfo)
      {
         //Evaluate conditions for the current state
         if(port->proposed && !port->agree)
         {
            //Switch to ALTERNATE_PROPOSED state
            rstpPrtAlternatePortChangeState(port, RSTP_PRT_STATE_ALTERNATE_PROPOSED);
         }
         else if((rstpAllSynced(port->context) && !port->agree) ||
            (port->proposed && port->agree))
         {
            //Switch to ALTERNATE_AGREED state
            rstpPrtAlternatePortChangeState(port, RSTP_PRT_STATE_ALTERNATE_AGREED);
         }
         else if(port->rbWhile != (2 * rstpHelloTime(port)) &&
            port->role == STP_PORT_ROLE_BACKUP)
         {
            //Switch to BACKUP_PORT state
            rstpPrtAlternatePortChangeState(port, RSTP_PRT_STATE_BACKUP_PORT);
         }
         else if(port->fdWhile != rstpForwardDelay(port) || port->sync ||
            port->reRoot || !port->synced)
         {
            //Switch to ALTERNATE_PORT state
            rstpPrtAlternatePortChangeState(port, RSTP_PRT_STATE_ALTERNATE_PORT);
         }
         else
         {
            //Just for sanity
         }
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
 * @brief Update PRT state machine state (Alternate or Backup port role)
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpPrtAlternatePortChangeState(RstpBridgePort *port, RstpPrtState newState)
{
   //Dump the state transition
   TRACE_VERBOSE("Port %" PRIu8 ": PRT state machine %s -> %s\r\n",
      port->portIndex,
      rstpGetParamName(port->prtState, rstpPrtStates, arraysize(rstpPrtStates)),
      rstpGetParamName(newState, rstpPrtStates, arraysize(rstpPrtStates)));

   //Switch to the new state
   port->prtState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->prtState)
   {
   //ALTERNATE_PROPOSED state?
   case RSTP_PRT_STATE_ALTERNATE_PROPOSED:
      //Proposal
      rstpSetSyncTree(port->context);
      port->proposed = FALSE;
      break;

   //ALTERNATE_AGREED state?
   case RSTP_PRT_STATE_ALTERNATE_AGREED:
      //Agreement
      port->proposed = FALSE;
      port->agree = TRUE;
      port->newInfo = TRUE;
      break;

   //BLOCK_PORT state?
   case RSTP_PRT_STATE_BLOCK_PORT:
      //Update port role
      port->role = port->selectedRole;
      port->learn = FALSE;
      port->forward = FALSE;
      break;

   //BACKUP_PORT state?
   case RSTP_PRT_STATE_BACKUP_PORT:
      //The Recent Backup timer is maintained at its initial value, twice
      //HelloTime, while the port is a Backup port
      port->rbWhile = 2 * rstpHelloTime(port);
      break;

   //ALTERNATE_PORT state?
   case RSTP_PRT_STATE_ALTERNATE_PORT:
      //Errata (refer to IEEE Std 802.1Q-2018, section 13.37)
      port->fdWhile = rstpForwardDelay(port);

      port->synced = TRUE;
      port->rrWhile = 0;
      port->sync = FALSE;
      port->reRoot = FALSE;
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

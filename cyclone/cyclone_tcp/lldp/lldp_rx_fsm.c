/**
 * @file lldp_rx_fsm.c
 * @brief LLDP receive state machine
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

//Switch to the appropriate trace level
#define TRACE_LEVEL LLDP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"
#include "lldp/lldp_fsm.h"
#include "lldp/lldp_rx_fsm.h"
#include "lldp/lldp_procedures.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED && LLDP_RX_MODE_SUPPORT == ENABLED)

//LLDP receive states
const LldpParamName lldpRxStates[] =
{
   {LLDP_STATE_LLDP_WAIT_PORT_OPERATIONAL, "LLDP_WAIT_PORT_OPERATIONAL"},
   {LLDP_STATE_DELETE_AGED_INFO,           "DELETE_AGED_INFO"},
   {LLDP_STATE_RX_LLDP_INITIALIZE,         "RX_LLDP_INITIALIZE"},
   {LLDP_STATE_RX_WAIT_FOR_FRAME,          "RX_WAIT_FOR_FRAME"},
   {LLDP_STATE_RX_FRAME,                   "RX_FRAME"},
   {LLDP_STATE_DELETE_INFO,                "DELETE_INFO"},
   {LLDP_STATE_UPDATE_INFO,                "UPDATE_INFO"}
};


/**
 * @brief LLDP receive state machine initialization
 * @param[in] port Pointer to the port context
 **/

void lldpInitRxFsm(LldpPortEntry *port)
{
   //Enter initial state
   lldpChangeRxState(port, LLDP_STATE_LLDP_WAIT_PORT_OPERATIONAL);
}


/**
 * @brief LLDP receive state machine implementation
 * @param[in] port Pointer to the port context
 **/

void lldpRxFsm(LldpPortEntry *port)
{
   LldpAgentContext *context;

   //Point to the LLDP agent context
   context = port->context;

   //A global transition can occur from any of the possible states
   if(!port->rxInfoAge && !port->portEnabled)
   {
      //When the condition associated with a global transition is met, it
      //supersedes all other exit conditions
      lldpChangeRxState(port, LLDP_STATE_LLDP_WAIT_PORT_OPERATIONAL);
   }
   else
   {
      //All exit conditions for the state are evaluated continuously until one
      //of the conditions is met (refer to IEEE Std 802.1AB-2005, section 10.4)
      switch(port->rxState)
      {
      //LLDP_WAIT_PORT_OPERATIONAL state?
      case LLDP_STATE_LLDP_WAIT_PORT_OPERATIONAL:
         //Evaluate conditions for the current state
         if(port->rxInfoAge)
         {
            //Switch to the DELETE_AGED_INFO state
            lldpChangeRxState(port, LLDP_STATE_DELETE_AGED_INFO);
         }
         else if(port->portEnabled)
         {
            //Switch to the RX_LLDP_INITIALIZE state
            lldpChangeRxState(port, LLDP_STATE_RX_LLDP_INITIALIZE);
         }
         else
         {
            //Just for sanity
         }

         break;

      //DELETE_AGED_INFO state?
      case LLDP_STATE_DELETE_AGED_INFO:
         //Unconditional transition (UCT) to LLDP_WAIT_PORT_OPERATIONAL state
         lldpChangeRxState(port, LLDP_STATE_LLDP_WAIT_PORT_OPERATIONAL);
         break;

      //RX_LLDP_INITIALIZE state?
      case LLDP_STATE_RX_LLDP_INITIALIZE:
         //LLDP receive initialization shall be halted until the value of
         //adminStatus is either enabledTxRx or enabledRxOnly
         if(port->adminStatus == LLDP_ADMIN_STATUS_ENABLED_TX_RX ||
            port->adminStatus == LLDP_ADMIN_STATUS_ENABLED_RX_ONLY)
         {
            //Switch to the RX_WAIT_FOR_FRAME state
            lldpChangeRxState(port, LLDP_STATE_RX_WAIT_FOR_FRAME);
         }
         break;

      //RX_WAIT_FOR_FRAME state?
      case LLDP_STATE_RX_WAIT_FOR_FRAME:
         //Evaluate conditions for the current state
         if(port->rxInfoAge)
         {
            //Switch to the DELETE_INFO state
            lldpChangeRxState(port, LLDP_STATE_DELETE_INFO);
         }
         else if(port->rcvFrame)
         {
            //Switch to the RX_FRAME state
            lldpChangeRxState(port, LLDP_STATE_RX_FRAME);
         }
         else if(port->adminStatus == LLDP_ADMIN_STATUS_DISABLED ||
            port->adminStatus == LLDP_ADMIN_STATUS_ENABLED_TX_ONLY)
         {
            //Switch to the RX_LLDP_INITIALIZE state
            lldpChangeRxState(port, LLDP_STATE_RX_LLDP_INITIALIZE);
         }
         else
         {
            //Just for sanity
         }

         break;

      //RX_FRAME state?
      case LLDP_STATE_RX_FRAME:
         //Evaluate conditions for the current state
         if(context->badFrame)
         {
            //Switch to the RX_WAIT_FOR_FRAME state
            lldpChangeRxState(port, LLDP_STATE_RX_WAIT_FOR_FRAME);
         }
         else if(context->rxTTL == 0)
         {
            //Switch to the DELETE_INFO state
            lldpChangeRxState(port, LLDP_STATE_DELETE_INFO);
         }
         else if(context->rxChanges)
         {
            //Switch to the UPDATE_INFO state
            lldpChangeRxState(port, LLDP_STATE_UPDATE_INFO);
         }
         else
         {
            //Switch to the RX_WAIT_FOR_FRAME state
            lldpChangeRxState(port, LLDP_STATE_RX_WAIT_FOR_FRAME);
         }

         break;

      //DELETE_INFO state?
      case LLDP_STATE_DELETE_INFO:
         //Unconditional transition (UCT) to RX_WAIT_FOR_FRAME state
         lldpChangeRxState(port, LLDP_STATE_RX_WAIT_FOR_FRAME);
         break;

      //UPDATE_INFO state?
      case LLDP_STATE_UPDATE_INFO:
         //Unconditional transition (UCT) to RX_WAIT_FOR_FRAME state
         lldpChangeRxState(port, LLDP_STATE_RX_WAIT_FOR_FRAME);
         break;

      //Invalid state?
      default:
         //Just for sanity
         lldpFsmError(port->context);
         break;
      }
   }
}


/**
 * @brief Update LLDP receive state
 * @param[in] port Pointer to the port context
 * @param[in] newState New state to switch to
 **/

void lldpChangeRxState(LldpPortEntry *port, LldpRxState newState)
{
   LldpAgentContext *context;

   //Point to the LLDP agent context
   context = port->context;

   //Any state change?
   if(port->rxState != newState)
   {
      //Dump the state transition
      TRACE_DEBUG("Port %" PRIu8 ": RX state machine %s -> %s\r\n",
         port->portIndex,
         lldpGetParamName(port->rxState, lldpRxStates, arraysize(lldpRxStates)),
         lldpGetParamName(newState, lldpRxStates, arraysize(lldpRxStates)));
   }

   //Switch to the new state
   port->rxState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1AB-2005, section 10.4)
   switch(port->rxState)
   {
   //LLDP_WAIT_PORT_OPERATIONAL state?
   case LLDP_STATE_LLDP_WAIT_PORT_OPERATIONAL:
      //No action
      break;

   //DELETE_AGED_INFO state?
   case LLDP_STATE_DELETE_AGED_INFO:
      //To avoid a race condition, the flag variable somethingChangedRemote is
      //not set to TRUE until after the information in the LLDP remote systems
      //MIB has been updated
      context->somethingChangedRemote = FALSE;
      lldpMibDeleteObjects(port);
      port->rxInfoAge = FALSE;
      context->somethingChangedRemote = TRUE;
      break;

   //RX_LLDP_INITIALIZE state?
   case LLDP_STATE_RX_LLDP_INITIALIZE:
      //Initialize the LLDP receive module
      lldpRxInitializeLLDP(port);
      port->rcvFrame = FALSE;
      break;

   //RX_WAIT_FOR_FRAME state?
   case LLDP_STATE_RX_WAIT_FOR_FRAME:
      //Reset flags
      context->badFrame = FALSE;
      port->rxInfoAge = FALSE;
      context->somethingChangedRemote = FALSE;
      break;

   //RX_FRAME state?
   case LLDP_STATE_RX_FRAME:
      //Reset flags
      context->rxChanges = FALSE;
      port->rcvFrame = FALSE;
      //Process incoming frame
      lldpRxProcessFrame(port);
      break;

   //DELETE_INFO state?
   case LLDP_STATE_DELETE_INFO:
      //Delete all information in the LLDP remote systems MIB associated with
      //the MSAP identifier if an LLDPDU is received with an rxTTL value of
      //zero or the timing counter rxInfoTTL expires
      lldpMibDeleteObjects(port);
      context->somethingChangedRemote = TRUE;
      break;

   //UPDATE_INFO state?
   case LLDP_STATE_UPDATE_INFO:
      //Update the MIB objects corresponding to the TLVs contained in the
      //received LLDPDU
      lldpMibUpdateObjects(port);
      context->somethingChangedRemote = TRUE;
      break;

   //Invalid state?
   default:
      //Just for sanity
      break;
   }

   //Check whether the port is enabled
   if(port->portEnabled)
   {
      //The LLDP state machine is busy
      port->context->busy = TRUE;
   }
}

#endif

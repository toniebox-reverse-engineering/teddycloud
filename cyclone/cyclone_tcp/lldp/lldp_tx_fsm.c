/**
 * @file lldp_tx_fsm.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL LLDP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"
#include "lldp/lldp_fsm.h"
#include "lldp/lldp_tx_fsm.h"
#include "lldp/lldp_procedures.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED && LLDP_TX_MODE_SUPPORT == ENABLED)

//LLDP transmit states
const LldpParamName lldpTxStates[] =
{
   {LLDP_STATE_TX_LLDP_INITIALIZE, "TX_LLDP_INITIALIZE"},
   {LLDP_STATE_TX_IDLE,            "TX_IDLE"},
   {LLDP_STATE_TX_SHUTDOWN_FRAME,  "TX_SHUTDOWN_FRAME"},
   {LLDP_STATE_TX_INFO_FRAME,      "TX_INFO_FRAME"}
};


/**
 * @brief LLDP transmit state machine initialization
 * @param[in] port Pointer to the port context
 **/

void lldpInitTxFsm(LldpPortEntry *port)
{
   //Enter initial state
   lldpChangeTxState(port, LLDP_STATE_TX_LLDP_INITIALIZE);
}


/**
 * @brief LLDP transmit state machine implementation
 * @param[in] port Pointer to the port context
 **/

void lldpTxFsm(LldpPortEntry *port)
{
   //A global transition can occur from any of the possible states
   if(!port->portEnabled)
   {
      //When the condition associated with a global transition is met, it
      //supersedes all other exit conditions
      lldpChangeTxState(port, LLDP_STATE_TX_LLDP_INITIALIZE);
   }
   else
   {
      //All exit conditions for the state are evaluated continuously until one
      //of the conditions is met (refer to IEEE Std 802.1AB-2005, section 10.4)
      switch(port->txState)
      {
      //TX_LLDP_INITIALIZE state?
      case LLDP_STATE_TX_LLDP_INITIALIZE:
         //LLDP transmit module initialization shall be halted until the variable
         //portEnabled is equal to TRUE and the value of adminStatus is either
         //enabledTxRx or enabledTxOnly
         if(port->adminStatus == LLDP_ADMIN_STATUS_ENABLED_TX_RX ||
            port->adminStatus == LLDP_ADMIN_STATUS_ENABLED_TX_ONLY)
         {
            //Switch to the TX_IDLE state
            lldpChangeTxState(port, LLDP_STATE_TX_IDLE);
         }

         break;

      //TX_IDLE state?
      case LLDP_STATE_TX_IDLE:
         //Monitoring both somethingChangedLocal and txTTR to determine when a
         //new transmission cycle is required
         if(port->adminStatus == LLDP_ADMIN_STATUS_DISABLED ||
            port->adminStatus == LLDP_ADMIN_STATUS_ENABLED_RX_ONLY)
         {
            //Switch to the TX_SHUTDOWN_FRAME state
            lldpChangeTxState(port, LLDP_STATE_TX_SHUTDOWN_FRAME);
         }
         else if(port->txDelayWhile == 0 && (port->txTTR == 0 ||
            port->somethingChangedLocal))
         {
            //Switch to the TX_INFO_FRAME state
            lldpChangeTxState(port, LLDP_STATE_TX_INFO_FRAME);
         }
         else
         {
            //Just for sanity
         }

         break;

      //TX_SHUTDOWN_FRAME state?
      case LLDP_STATE_TX_SHUTDOWN_FRAME:
         //The txShutdownWhile timer indicates the number of seconds remaining
         //until LLDP re-initialization can occur
         if(port->txShutdownWhile == 0)
         {
            //Switch to the TX_LLDP_INITIALIZE state
            lldpChangeTxState(port, LLDP_STATE_TX_LLDP_INITIALIZE);
         }

         break;

      //TX_INFO_FRAME state?
      case LLDP_STATE_TX_INFO_FRAME:
         //Unconditional transition (UCT) to TX_IDLE state
         lldpChangeTxState(port, LLDP_STATE_TX_IDLE);
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
 * @brief Update LLDP transmit state
 * @param[in] port Pointer to the port context
 * @param[in] newState New state to switch to
 **/

void lldpChangeTxState(LldpPortEntry *port, LldpTxState newState)
{
   LldpAgentContext *context;

   //Point to the LLDP agent context
   context = port->context;

   //Any state change?
   if(port->txState != newState)
   {
      //Dump the state transition
      TRACE_DEBUG("Port %" PRIu8 ": TX state machine %s -> %s\r\n",
         port->portIndex,
         lldpGetParamName(port->txState, lldpTxStates, arraysize(lldpTxStates)),
         lldpGetParamName(newState, lldpTxStates, arraysize(lldpTxStates)));
   }

   //Switch to the new state
   port->txState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1AB-2005, section 10.4)
   switch(port->txState)
   {
   //TX_LLDP_INITIALIZE state?
   case LLDP_STATE_TX_LLDP_INITIALIZE:
      //Initialize the LLDP transmit module
      lldpTxInitializeLLDP(port);
      break;

   //TX_IDLE state?
   case LLDP_STATE_TX_IDLE:
      //The txTTL variable indicates the time remaining before information in
      //the outgoing LLDPDU will no longer be valid
      port->txTTL = MIN(65535, context->msgTxInterval * context->msgTxHold);

      //When the LLDPDU is complete, the MIB manager shall re-initialize the
      //txTTR timing counter in the LLDP local system MIB
      port->txTTR = context->msgTxInterval;

      //The somethingChangedLocal variable indicates that the status/value of
      //one or more of the selected objects in the LLDP local system MIB has
      //changed
      port->somethingChangedLocal = FALSE;

      //The txDelayWhile timer introduces a minimum delay between transmission
      //of successive LLDP frames
      port->txDelayWhile = context->txDelay;
      break;

   //TX_SHUTDOWN_FRAME state?
   case LLDP_STATE_TX_SHUTDOWN_FRAME:
      //Construct a shutdown LLDPDU
      lldpMibConstrShutdownLldpdu(port);
      //Send the LLDPDU to the MAC for transmission
      lldpTxFrame(port);

      //The txShutdownWhile timer indicates the number of seconds remaining
      //until LLDP re-initialization can occur
      port->txShutdownWhile = context->reinitDelay;
      break;

   //TX_INFO_FRAME state?
   case LLDP_STATE_TX_INFO_FRAME:
      //Construct an information LLDPDU
      lldpMibConstrInfoLldpdu(port);
      //Send the LLDPDU to the MAC for transmission
      lldpTxFrame(port);
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

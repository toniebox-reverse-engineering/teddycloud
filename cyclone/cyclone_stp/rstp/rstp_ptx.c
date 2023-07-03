/**
 * @file rstp_ptx.c
 * @brief Port Transmit state machine (PTX)
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
#include "rstp/rstp_ptx.h"
#include "rstp/rstp_procedures.h"
#include "rstp/rstp_conditions.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//PTX state machine's states
const RstpParamName rstpPtxStates[] =
{
   {RSTP_PTX_STATE_TRANSMIT_INIT,     "TRANSMIT_INIT"},
   {RSTP_PTX_STATE_TRANSMIT_PERIODIC, "TRANSMIT_PERIODIC"},
   {RSTP_PTX_STATE_TRANSMIT_CONFIG,   "TRANSMIT_CONFIG"},
   {RSTP_PTX_STATE_TRANSMIT_TCN,      "TRANSMIT_TCN"},
   {RSTP_PTX_STATE_TRANSMIT_RSTP,     "TRANSMIT_RSTP"},
   {RSTP_PTX_STATE_IDLE,              "IDLE"}
};


/**
 * @brief PTX state machine initialization
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPtxInit(RstpBridgePort *port)
{
   //Enter initial state
   rstpPtxChangeState(port, RSTP_PTX_STATE_TRANSMIT_INIT);
}


/**
 * @brief PTX state machine implementation
 * @param[in] port Pointer to the bridge port context
 **/

void rstpPtxFsm(RstpBridgePort *port)
{
   RstpBridgeContext *context;

   //Point to the RSTP bridge context
   context = port->context;

   //A global transition can occur from any of the possible states
   if(!port->portEnabled)
   {
      //When the condition associated with a global transition is met, it
      //supersedes all other exit conditions
      rstpPtxChangeState(port, RSTP_PTX_STATE_TRANSMIT_INIT);
   }
   else
   {
      //All conditions for the current state are evaluated continuously until one
      //of the conditions is met (refer to IEEE Std 802.1D-2004, section 17.16)
      switch(port->ptxState)
      {
      //TRANSMIT_INIT, TRANSMIT_PERIODIC, TRANSMIT_CONFIG, TRANSMIT_TCN or
      //TRANSMIT_RSTP state?
      case RSTP_PTX_STATE_TRANSMIT_INIT:
      case RSTP_PTX_STATE_TRANSMIT_PERIODIC:
      case RSTP_PTX_STATE_TRANSMIT_CONFIG:
      case RSTP_PTX_STATE_TRANSMIT_TCN:
      case RSTP_PTX_STATE_TRANSMIT_RSTP:
         //Unconditional transition (UCT) to IDLE state
         rstpPtxChangeState(port, RSTP_PTX_STATE_IDLE);
         break;

      //IDLE state?
      case RSTP_PTX_STATE_IDLE:
         //All transitions, except UCT, are qualified by the following condition
         if(port->selected && !port->updtInfo)
         {
            //The state machine transmits BPDUs at regular intervals and when
            //newInfo is set
            if(port->helloWhen == 0)
            {
               //Switch to the TRANSMIT_PERIODIC state
               rstpPtxChangeState(port, RSTP_PTX_STATE_TRANSMIT_PERIODIC);
            }
            else
            {
               //The newInfo flag is set if a BPDU is to be transmitted
               if(port->newInfo)
               {
                  //The TxHoldCount is used to limit transmission rate
                  if(port->txCount < rstpTxHoldCount(context))
                  {
                     //The sendRSTP determines the type of the BPDU to send
                     if(port->sendRstp)
                     {
                        //Transmit an RST BPDU
                        rstpPtxChangeState(port, RSTP_PTX_STATE_TRANSMIT_RSTP);
                     }
                     else
                     {
                        //Check port role
                        if(port->role == STP_PORT_ROLE_ROOT)
                        {
                           //Transmit a TCN BPDU
                           rstpPtxChangeState(port, RSTP_PTX_STATE_TRANSMIT_TCN);
                        }
                        else if(port->role == STP_PORT_ROLE_DESIGNATED)
                        {
                           //Transmit a Configuration BPDU
                           rstpPtxChangeState(port, RSTP_PTX_STATE_TRANSMIT_CONFIG);
                        }
                        else
                        {
                           //Just for sanity
                        }
                     }
                  }
               }
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
}


/**
 * @brief Update PTX state machine state
 * @param[in] port Pointer to the bridge port context
 * @param[in] newState New state to switch to
 **/

void rstpPtxChangeState(RstpBridgePort *port, RstpPtxState newState)
{
   //Any state change?
   if(port->ptxState != newState)
   {
      //Dump the state transition
      TRACE_VERBOSE("Port %" PRIu8 ": PTX state machine %s -> %s\r\n",
         port->portIndex,
         rstpGetParamName(port->ptxState, rstpPtxStates, arraysize(rstpPtxStates)),
         rstpGetParamName(newState, rstpPtxStates, arraysize(rstpPtxStates)));
   }

   //Switch to the new state
   port->ptxState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1D-2004, section 17.16)
   switch(port->ptxState)
   {
   //TRANSMIT_INIT state?
   case RSTP_PTX_STATE_TRANSMIT_INIT:
      //Initialize variables
      port->newInfo = TRUE;
      port->txCount = 0;
      break;

   //TRANSMIT_PERIODIC state?
   case RSTP_PTX_STATE_TRANSMIT_PERIODIC:
      //Check port role
      if(port->role == STP_PORT_ROLE_DESIGNATED)
      {
         //Transmit a Configuration BPDU
         port->newInfo = TRUE;
      }
      else if(port->role == STP_PORT_ROLE_ROOT)
      {
         //Check whether the Topology Change timer is running
         if(port->tcWhile != 0)
         {
            //Transmit a TCN BPDU
            port->newInfo = TRUE;
         }
      }
      else
      {
         //Just for sanity
      }

      break;

   //TRANSMIT_CONFIG state?
   case RSTP_PTX_STATE_TRANSMIT_CONFIG:
      //Send a Configuration BPDU
      port->newInfo = FALSE;
      rstpTxConfig(port);
      port->txCount++;
      port->tcAck = FALSE;
      break;

   //TRANSMIT_TCN state?
   case RSTP_PTX_STATE_TRANSMIT_TCN:
      //Send a TCN BPDU
      port->newInfo = FALSE;
      rstpTxTcn(port);
      port->txCount++;
      break;

   //TRANSMIT_RSTP state?
   case RSTP_PTX_STATE_TRANSMIT_RSTP:
      //Send an RSTP BPDU
      port->newInfo = FALSE;
      rstpTxRstp(port);
      port->txCount++;
      port->tcAck = FALSE;
      break;

   //IDLE state?
   case RSTP_PTX_STATE_IDLE:
      //Reload the Hello timer
      port->helloWhen = rstpHelloTime(port);
      break;

   //Invalid state?
   default:
      //Just for sanity
      break;
   }

   //Check whether the port is enabled
   if(port->portEnabled)
   {
      //The RSTP state machine is busy
      port->context->busy = TRUE;
   }
}

#endif

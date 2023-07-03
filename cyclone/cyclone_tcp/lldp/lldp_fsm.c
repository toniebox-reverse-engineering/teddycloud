/**
 * @file lldp_fsm.c
 * @brief LLDP state machine
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
#include "lldp/lldp_tx_fsm.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED)


/**
 * @brief LLDP state machine initialization
 * @param[in] context Pointer to the LLDP agent context
 **/

void lldpInitFsm(LldpAgentContext *context)
{
   uint_t i;
   LldpPortEntry *port;

   //Loop through the ports
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current port
      port = &context->ports[i];

#if (LLDP_RX_MODE_SUPPORT == ENABLED)
      //Initialize LLDP receive state machine
      lldpInitRxFsm(port);
#endif

#if (LLDP_TX_MODE_SUPPORT == ENABLED)
      //Initialize LLDP transmit state machine
      lldpInitTxFsm(port);
#endif
   }

   //Update LLDP state machines
   lldpFsm(context);
}


/**
 * @brief LLDP state machine implementation
 * @param[in] context Pointer to the LLDP agent context
 **/

void lldpFsm(LldpAgentContext *context)
{
   uint_t i;

   //The operation of the LLDP protocol can be represented with two simple
   //state machines
   do
   {
      //Clear the busy flag
      context->busy = FALSE;

#if (LLDP_RX_MODE_SUPPORT == ENABLED)
      //Loop through the ports
      for(i = 0; i < context->numPorts; i++)
      {
         //Update the LLDP receive state machine
         lldpRxFsm(&context->ports[i]);
      }
#endif

#if (LLDP_TX_MODE_SUPPORT == ENABLED)
      //Check whether the RSTP state machine is idle
      if(!context->busy)
      {
         //Loop through the ports
         for(i = 0; i < context->numPorts; i++)
         {
            //Update the LLDP transmit state machine
            lldpTxFsm(&context->ports[i]);
         }
      }
#endif

      //Transition conditions are evaluated continuously as long as the LLDP
      //state machine is busy
   } while(context->busy);
}


/**
 * @brief LLDP state machine error handler
 * @param[in] context Pointer to the LLDP agent context
 **/

void lldpFsmError(LldpAgentContext *context)
{
   //Debug message
   TRACE_ERROR("LLDP finite state machine error!\r\n");
}

#endif

/**
 * @file stp_conditions.c
 * @brief STP algorithm conditions
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
#define TRACE_LEVEL STP_TRACE_LEVEL

//Dependencies
#include "stp/stp.h"
#include "stp/stp_conditions.h"
#include "stp/stp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (STP_SUPPORT == ENABLED)


/**
 * @brief Test whether the bridge is the Root bridge
 * @param[in] context Pointer to the STP bridge context
 * @return TRUE if the bridge has been selected as the Root, else FALSE
 **/

bool_t stpRootBridge(StpBridgeContext *context)
{
   bool_t res;

   //Check if the Designated Root and Bridge Identifier parameters held for
   //the bridge are the same
   if(stpCompareBridgeId(&context->designatedRoot, &context->bridgeId) == 0)
   {
      res = TRUE;
   }
   else
   {
      res = FALSE;
   }

   //Return TRUE if the bridge has been selected as the Root
   return res;
}


/**
 * @brief Test whether the bridge is the Designated bridge for at least one LAN
 * @param[in] context Pointer to the STP bridge context
 * @return TRUE if the bridge is the Designated bridge for at least one of the
 *   LANs, else FALSE
 **/

bool_t stpDesignatedBridge(StpBridgeContext *context)
{
   uint_t i;
   bool_t res;
   StpBridgePort *port;

   //Initialize boolean
   res = FALSE;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //Check if the bridge is the Designated bridge for the LAN to which the
      //port is attached
      if(stpCompareBridgeId(&port->designatedBridge, &context->bridgeId) == 0)
      {
         res = TRUE;
      }
   }

   //Return TRUE if the bridge is the Designated bridge for at least one of
   //the LANs
   return res;
}


/**
 * @brief Test whether a given port is the Root port for the bridge
 * @param[in] port Pointer to the bridge port context
 * @return TRUE if the port is the Root port for the bridge, else FALSE
 **/

bool_t stpRootPort(StpBridgePort *port)
{
   bool_t res;

   //Root port?
   if(stpComparePortNum(port->portId, port->context->rootPort) == 0)
   {
      res = TRUE;
   }
   else
   {
      res = FALSE;
   }

   //Return TRUE if the port is the Root port for the bridge
   return res;
}


/**
 * @brief Test whether a given port is a Designated port
 * @param[in] port Pointer to the bridge port context
 * @return TRUE if the port is the Designated port for the LAN to which it is
 *   attached, else FALSE
 **/

bool_t stpDesignatedPort(StpBridgePort *port)
{
   bool_t res;
   StpBridgeContext *context;

   //Point to the STP bridge context
   context = port->context;

   //Check whether the value of the Designated Bridge and Designated Port
   //parameters held for the port are the same as that of the Bridge Identifier
   //and the Port Identifier for that port, respectively
   if(stpCompareBridgeId(&port->designatedBridge, &context->bridgeId) == 0 &&
      port->designatedPort == port->portId)
   {
      res = TRUE;
   }
   else
   {
      res = FALSE;
   }

   //Return TRUE if the port is the Designated port for the LAN to which it is
   //attached
   return res;
}


/**
 * @brief Check whether the protocol information supersedes that already held
 *   for a port
 * @param[in] port Pointer to the bridge port context
 * @param[in] bpdu Pointer to the received Configuration BPDU
 * @return TRUE if the Configuration BPDU conveys protocol information that
 *   supersedes that already held, else FALSE
 **/

bool_t stpSupersedesPortInfo(StpBridgePort *port, const StpBpdu *bpdu)
{
   bool_t res;
   StpBridgeId rootId;
   StpBridgeId bridgeId;
   StpBridgeContext *context;

   //Point to the STP bridge context
   context = port->context;

   //Extract the Root Identifier and the Bridge Identifier from the received
   //Configuration PBDU
   rootId.priority = ntohs(bpdu->rootId.priority);
   rootId.addr = bpdu->rootId.addr;
   bridgeId.priority = ntohs(bpdu->bridgeId.priority);
   bridgeId.addr = bpdu->bridgeId.addr;

   //Initialize boolean
   res = FALSE;

   //Check whether the Configuration BPDU conveys protocol information that
   //supersedes that already held
   if(stpCompareBridgeId(&rootId, &port->designatedRoot) < 0)
   {
      //Case 1. The Root Identifier denotes a bridge of higher priority than
      //that recorded as the Designated Root
      res = TRUE;
   }
   else if(stpCompareBridgeId(&rootId, &port->designatedRoot) > 0)
   {
   }
   else if(ntohl(bpdu->rootPathCost) < port->designatedCost)
   {
      //Case 2. The Root Identifier is the same as the Designated Root, and
      //the Root Path Cost is lower than that recorded as the Designated Cost
      //for the port
      res = TRUE;
   }
   else if(ntohl(bpdu->rootPathCost) > port->designatedCost)
   {
   }
   else if(stpCompareBridgeId(&bridgeId, &port->designatedBridge) < 0)
   {
      //Case 3. The Root Identifier and Root Path Cost are as recorded for the
      //port, and the Bridge Identifier denotes a bridge of higher priority than
      //that recorded as the Designated Bridge for the port
      res = TRUE;
   }
   else if(stpCompareBridgeId(&bridgeId, &port->designatedBridge) > 0)
   {
   }
   else
   {
      //Case 4. The Root Identifier and Root Path Cost are as recorded for the
      //port, and the Bridge Identifier is the same as that recorded as the
      //Designated Bridge for the Port
      if(stpCompareBridgeId(&bridgeId, &context->bridgeId) != 0)
      {
         //The Bridge receiving the BPDU is not the Designated Bridge for the
         //port
         res = TRUE;
      }
      else if(ntohs(bpdu->portId) <= port->designatedPort)
      {
         //The Port Identifier denotes a port of priority not less than that
         //recorded as the Designated Port
         res = TRUE;
      }
      else
      {
      }
   }

   //Return boolean value
   return res;
}

#endif

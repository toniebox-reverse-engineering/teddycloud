/**
 * @file rstp_conditions.c
 * @brief RSTP state machine conditions
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
#include "rstp/rstp_conditions.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)


/**
 * @brief AdminEdge variable evaluation (17.20.1)
 * @param[in] port Pointer to the bridge port context
 * @return AdminEdgePort parameter for the port
 **/

uint_t rstpAdminEdge(RstpBridgePort *port)
{
   //The function returns the AdminEdgePort parameter for the port
   return port->params.adminEdgePort;
}


/**
 * @brief AutoEdge variable evaluation (17.20.2)
 * @param[in] port Pointer to the bridge port context
 * @return AutoEdgePort parameter for the port
 **/

uint_t rstpAutoEdge(RstpBridgePort *port)
{
   //The function returns the AutoEdgePort parameter for the port
   return port->params.autoEdgePort;
}


/**
 * @brief allSynced condition (17.20.3)
 * @param[in] context Pointer to the RSTP bridge context
 * @return Boolean
 **/

bool_t rstpAllSynced(RstpBridgeContext *context)
{
   uint_t i;
   bool_t res;
   RstpBridgePort *port;

   //Initialize boolean
   res = TRUE;

   //The condition allSynced is TRUE if and only if, for all ports for the
   //given tree, selected is TRUE and the port's role is the same as its
   //selectedRole, updtInfo is FALSE (refer to IEEE Std 802.1D-2004 errata)
   //and either: synced is TRUE or the port is the Root port
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //Evaluate the condition for the current port
      if(!port->selected)
      {
         res = FALSE;
      }
      else if(port->role != port->selectedRole)
      {
         res = FALSE;
      }
      else if(port->updtInfo)
      {
         res = FALSE;
      }
      else if(!port->synced && port->role != STP_PORT_ROLE_ROOT)
      {
         res = FALSE;
      }
      else
      {
         //Just for sanity
      }
   }

   //Return TRUE if the condition is met for all the ports
   return res;
}


/**
 * @brief EdgeDelay variable evaluation (17.20.4)
 * @param[in] port Pointer to the bridge port context
 * @return MigrateTime if operPointToPointMAC is TRUE, else MaxAge
 **/

uint_t rstpEdgeDelay(RstpBridgePort *port)
{
   uint_t value;

   //The function returns the value of MigrateTime if operPointToPointMAC is
   //TRUE, and the value of MaxAge otherwise
   if(port->operPointToPointMac)
   {
      value = rstpMigrateTime(port->context);
   }
   else
   {
      value = rstpMaxAge(port);
   }

   //Return the relevant value
   return value;
}


/**
 * @brief forwardDelay variable evaluation (17.20.5)
 * @param[in] port Pointer to the bridge port context
 * @return HelloTime if sendRSTP is TRUE, else FwdDelay
 **/

uint_t rstpForwardDelay(RstpBridgePort *port)
{
   uint_t value;

   //The function returns the value of HelloTime if sendRSTP is TRUE, and the
   //value of FwdDelay otherwise
   if(port->sendRstp)
   {
      value = rstpHelloTime(port);
   }
   else
   {
      value = rstpFwdDelay(port);
   }

   //Return the relevant value
   return value;
}


/**
 * @brief FwdDelay variable evaluation (17.20.6)
 * @param[in] port Pointer to the bridge port context
 * @return Forward Delay component of designatedTimes
 **/

uint_t rstpFwdDelay(RstpBridgePort *port)
{
   //The function returns the Forward Delay component of designatedTimes
   return port->designatedTimes.forwardDelay;
}


/**
 * @brief HelloTime variable evaluation (17.20.7)
 * @param[in] port Pointer to the bridge port context
 * @return Hello Time component of designatedTimes
 **/

uint_t rstpHelloTime(RstpBridgePort *port)
{
   //The function returns the Hello Time component of designatedTimes
   return port->designatedTimes.helloTime;
}


/**
 * @brief MaxAge variable evaluation (17.20.8)
 * @param[in] port Pointer to the bridge port context
 * @return Max Age component of designatedTimes
 **/

uint_t rstpMaxAge(RstpBridgePort *port)
{
   //The function returns the Max Age component of designatedTimes
   return port->designatedTimes.maxAge;
}


/**
 * @brief MigrateTime variable evaluation (17.20.9)
 * @param[in] context Pointer to the RSTP bridge context
 * @return Migrate Time parameter
 **/

uint_t rstpMigrateTime(RstpBridgeContext *context)
{
   //The function returns the Migrate Time parameter
   return context->params.migrateTime;
}


/**
 * @brief reRooted condition (17.20.10)
 * @param[in] port Pointer to the bridge port context
 * @return Boolean
 **/

bool_t rstpReRooted(RstpBridgePort *port)
{
   uint_t i;
   bool_t res;
   RstpBridgeContext *context;

   //Initialize boolean
   res = TRUE;

   //Point to the RSTP bridge context
   context = port->context;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Check the value of the rrWhile timer
      if(&context->ports[i] != port && context->ports[i].rrWhile != 0)
      {
         res = FALSE;
      }
   }

   //Return TRUE if the rrWhile timer is zero for all ports other than the
   //given port
   return res;
}


/**
 * @brief rstpVersion condition (17.20.11)
 * @param[in] context Pointer to the RSTP bridge context
 * @return Boolean
 **/

bool_t rstpVersion(RstpBridgeContext *context)
{
   bool_t res;

   //Check protocol version
   if(context->params.forceProtocolVersion >= RSTP_PROTOCOL_VERSION)
   {
      //Normal operation
      res = TRUE;
   }
   else
   {
      //STP compatibility mode
      res = FALSE;
   }

   //Return TRUE if Force Protocol Version is greater than or equal to 2
   return res;
}


/**
 * @brief stpVersion condition (17.20.12)
 * @param[in] context Pointer to the RSTP bridge context
 * @return Boolean
 **/

bool_t stpVersion(RstpBridgeContext *context)
{
   //Return TRUE if Force Protocol Version is less than 2
   return !rstpVersion(context);
}


/**
 * @brief TxHoldCount variable evaluation (17.20.13)
 * @param[in] context Pointer to the RSTP bridge context
 * @return Transmit Hold Count parameter
 **/

uint_t rstpTxHoldCount(RstpBridgeContext *context)
{
   //The function returns the Transmit Hold Count parameter
   return context->params.transmitHoldCount;
}

#endif

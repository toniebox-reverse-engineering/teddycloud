/**
 * @file bridge_mib_impl.c
 * @brief Bridge MIB module implementation
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
#define TRACE_LEVEL SNMP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "mibs/mib_common.h"
#include "mibs/bridge_mib_module.h"
#include "mibs/bridge_mib_impl.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "stp/stp.h"
#include "stp/stp_mgmt.h"
#include "stp/stp_misc.h"
#include "rstp/rstp.h"
#include "rstp/rstp_mgmt.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (BRIDGE_MIB_SUPPORT == ENABLED)


/**
 * @brief Bridge MIB module initialization
 * @return Error code
 **/

error_t bridgeMibInit(void)
{
   //Debug message
   TRACE_INFO("Initializing Bridge MIB base...\r\n");

   //Clear Bridge MIB base
   memset(&bridgeMibBase, 0, sizeof(bridgeMibBase));

   //Type of bridging this bridge can perform
   bridgeMibBase.dot1dBaseType = BRIDGE_MIB_BASE_TYPE_TRANSPARENT_ONLY;
   //Version of the Spanning Tree Protocol
   bridgeMibBase.dot1dStpProtocolSpecification = BRIDGE_MIB_PROTOCOL_SPEC_IEEE802_1D;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Attach STP bridge context
 * @param[in] context Pointer to the STP bridge context
 * @return Error code
 **/

error_t bridgeMibSetStpBridgeContext(StpBridgeContext *context)
{
#if (STP_SUPPORT == ENABLED)
   //Make sure the STP bridge context is valid
   if(context != NULL)
   {
      bridgeMibBase.stpBridgeContext = context;
      bridgeMibBase.interface = context->interface;
   }
   else
   {
      bridgeMibBase.stpBridgeContext = NULL;
      bridgeMibBase.interface = NULL;
   }

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Attach RSTP bridge context
 * @param[in] context Pointer to the RSTP bridge context
 * @return Error code
 **/

error_t bridgeMibSetRstpBridgeContext(RstpBridgeContext *context)
{
#if (RSTP_SUPPORT == ENABLED)
   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      bridgeMibBase.rstpBridgeContext = context;
      bridgeMibBase.interface = context->interface;
   }
   else
   {
      bridgeMibBase.rstpBridgeContext = NULL;
      bridgeMibBase.interface = NULL;
   }

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Get the number of ports
 * @return Number of ports
 **/

uint_t bridgeMibGetNumPorts(void)
{
   uint_t numPorts;

   //Initialize value
   numPorts = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      numPorts = bridgeMibBase.stpBridgeContext->numPorts;
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      numPorts = bridgeMibBase.rstpBridgeContext->numPorts;
   }
   else
#endif
   //Invalid bridge context?
   {
      //Just for sanity
   }

   //Return the number of ports
   return numPorts;
}


/**
 * @brief Get the port index that matches the specified port number
 * @param[in] portNum Port number
 * @return Port index
 **/

uint_t bridgeMibGetPortIndex(uint16_t portNum)
{
   uint_t portIndex;

   //Initialize value
   portIndex = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      StpBridgePort *port;

      //Retrieve the port that matches the specified port number
      port = stpGetBridgePort(bridgeMibBase.stpBridgeContext, portNum);

      //Valid port number?
      if(port != NULL)
      {
         //Get the port index
         portIndex = port->portIndex;
      }
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      RstpBridgePort *port;

      //Retrieve the port that matches the specified port number
      port = rstpGetBridgePort(bridgeMibBase.rstpBridgeContext, portNum);

      //Valid port number?
      if(port != NULL)
      {
         //Get the port index
         portIndex = port->portIndex;
      }
   }
   else
#endif
   //Invalid bridge context?
   {
      //Just for sanity
   }

   //Return the port index
   return portIndex;
}


/**
 * @brief Get the port number that matches the specified port index
 * @param[in] portIndex Port index
 * @return Port number
 **/

uint16_t bridgeMibGetPortNum(uint16_t portIndex)
{
   uint_t portNum;

   //Initialize value
   portNum = 0;

#if (STP_SUPPORT == ENABLED)
   //Valid STP bridge context?
   if(bridgeMibBase.stpBridgeContext != NULL)
   {
      //Valid port index?
      if(portIndex >= 1 && portIndex <= bridgeMibBase.stpBridgeContext->numPorts)
      {
         StpBridgePort *port;

         //Point to the port that matches the specified port index
         port = &bridgeMibBase.stpBridgeContext->ports[portIndex - 1];
         //Get the port number
         portNum = port->portId & STP_PORT_NUM_MASK;
      }
   }
   else
#endif
#if (RSTP_SUPPORT == ENABLED)
   //Valid RSTP bridge context?
   if(bridgeMibBase.rstpBridgeContext != NULL)
   {
      //Valid port index?
      if(portIndex >= 1 && portIndex <= bridgeMibBase.rstpBridgeContext->numPorts)
      {
         RstpBridgePort *port;

         //Point to the port that matches the specified port index
         port = &bridgeMibBase.rstpBridgeContext->ports[portIndex - 1];
         //Get the port number
         portNum = port->portId & RSTP_PORT_NUM_MASK;
      }
   }
   else
#endif
   //Invalid bridge context?
   {
      //Just for sanity
   }

   //Return the port number
   return portNum;
}

#endif

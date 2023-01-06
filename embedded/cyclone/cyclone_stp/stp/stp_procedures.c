/**
 * @file stp_procedures.c
 * @brief Elements of procedures
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
#include "stp/stp_procedures.h"
#include "stp/stp_conditions.h"
#include "stp/stp_bpdu.h"
#include "stp/stp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (STP_SUPPORT == ENABLED)


/**
 * @brief Initialization procedure
 * @param[in] context Pointer to the STP bridge context
 **/

void stpInitProc(StpBridgeContext *context)
{
   uint_t i;
   StpBridgePort *port;

   //The Designated Root parameter held for the bridge is set equal to the
   //value of the Bridge Identifier, and the values of the Root Path Cost and
   //Root Port parameter held for the Bridge are set to zero
   context->designatedRoot = context->bridgeId;
   context->rootPathCost = 0;
   context->rootPort = 0;

   //The Max Age, Hello Time, and Forward Delay parameters held by the bridge
   //are set to the values of the Bridge Max Age, Bridge Hello Time, and Bridge
   //Forward Delay parameters
   context->maxAge = context->bridgeMaxAge;
   context->helloTime = context->bridgeHelloTime;
   context->forwardDelay = context->bridgeForwardDelay;

   //The Topology Change Detected and Topology Change flag parameters for the
   //bridge are reset, and the Topology Change Notification Timer and Topology
   //Change Timer are stopped, if running
   context->topologyChangeDetected = FALSE;
   context->topologyChange = FALSE;
   stpStopTimer(&context->tcnTimer);
   stpStopTimer(&context->topologyChangeTimer);

   //Stop the rapid ageing timer
   stpStopTimer(&context->rapidAgeingTimer);
   //Restore default ageing time
   stpUpdateAgeingTime(context, context->ageingTime);

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //The Become Designated Port procedure is used to assign values to the
      //Designated Root, Designated Cost, Designated Bridge, and Designated
      //Port parameters for the port
      stpBecomeDesignatedPort(port);

      //The Port State is set to Blocking if the port is to be enabled following
      //initialization. Alternatively, the Port State is set to Disabled
      if(port->state != STP_PORT_STATE_DISABLED)
      {
         stpUpdatePortState(port, STP_PORT_STATE_BLOCKING);
      }
      else
      {
         stpUpdatePortState(port, STP_PORT_STATE_DISABLED);
      }

      //The Topology Change Acknowledge flag parameter is reset
      port->topologyChangeAck = FALSE;
      //The Configuration Pending flag parameter is reset
      port->configPending = FALSE;
      //The Message Age Timer is stopped, if running
      stpStopTimer(&port->messageAgeTimer);
      //The Forward Delay Timer is stopped, if running
      stpStopTimer(&port->forwardDelayTimer);
      //The Hold Timer is stopped, if running
      stpStopTimer(&port->holdTimer);
      //The Change Detection Enabled flag is set
      port->changeDetectionEnabled = TRUE;
   }

   //The Port State Selection procedure is used to select the state of each of
   //the bridge's ports
   stpPortStateSelection(context);

   //The Configuration BPDU Generation procedure is invoked and the Hello Timer
   //is started
   stpConfigBpduGeneration(context);
   stpStartTimer(&context->helloTimer, 0);
}


/**
 * @brief Transmit Configuration BPDU (8.6.1)
 * @param[in] port Pointer to the bridge port context
 **/

void stpTransmitConfigBpdu(StpBridgePort *port)
{
   uint_t messageAge;
   StpBpdu bpdu;
   StpBridgeContext *context;
   StpBridgePort *rootPort;

   //Point to the STP bridge context
   context = port->context;

   //Check whether the Hold Timer is active
   if(port->holdTimer.active)
   {
      //If the Hold Timer for the port is active then the Configuration Pending
      //flag parameter for the Port shall be set. This completes the procedure
      port->configPending = TRUE;
   }
   else
   {
      //If the Hold Timer for the Port is not active, a Configuration BPDU is
      //prepared for transmission
      bpdu.protocolId = HTONS(STP_PROTOCOL_ID);
      bpdu.protocolVersionId = STP_PROTOCOL_VERSION;
      bpdu.bpduType = STP_BPDU_TYPE_CONFIG;
      bpdu.flags = 0;

      //The Root Identifier shall be set to the value of the Designated Root
      //parameter held by the Bridge
      bpdu.rootId.priority = htons(context->designatedRoot.priority);
      bpdu.rootId.addr = context->designatedRoot.addr;

      //The Root Path Cost shall be set to the value of the Root Path Cost
      //parameter held by the bridge
      bpdu.rootPathCost = htonl(context->rootPathCost);

      //The Bridge Identifier shall be set to the value of the Bridge Identifier
      //parameter held by the Bridge
      bpdu.bridgeId.priority = htons(context->bridgeId.priority);
      bpdu.bridgeId.addr = context->bridgeId.addr;

      //The Port Identifier shall be set to the value of the Port Identifier
      //parameter held for the bridge port through which the Configuration
      //BPDU is transmitted
      bpdu.portId = htons(port->portId);

      //Check if the bridge has been selected as the Root
      if(stpRootBridge(context))
      {
         //If the Bridge has been selected as the Root, the Message Age shall
         //be set to zero
         messageAge = 0;
      }
      else
      {
         //Point to the Root port
         rootPort = stpGetBridgePort(context, context->rootPort);

         //The value of the Message Age shall be set such that the transmitted
         //Configuration BPDU does not convey an underestimate of the age of
         //the Protocol Message received on the Root port
         messageAge = (rootPort != NULL) ? rootPort->messageAgeTimer.value : 0;

         //The value of the parameter shall not exceed its true value by more
         //than the maximum Message Age increment overestimate
         messageAge += STP_MESSAGE_AGE_INCREMENT;
      }

      //The Max Age, Hello Time, and Forward Delay shall be set to the values
      //of the Max Age, Hello Time, and Forward Delay parameters held for the
      //bridge
      bpdu.maxAge = htons(context->maxAge * 256);
      bpdu.helloTime = htons(context->helloTime * 256);
      bpdu.forwardDelay = htons(context->forwardDelay * 256);

      //The Topology Change Acknowledgment flag shall be set to the value of the
      //Topology Change Acknowledge flag parameter for the port
      if(port->topologyChangeAck)
      {
         bpdu.flags |= STP_BPDU_FLAG_TC_ACK;
      }

      //The Topology Change flag shall be set to the value of the Topology
      //Change flag parameter for the bridge
      if(context->topologyChange)
      {
         bpdu.flags |= STP_BPDU_FLAG_TC;
      }

      //Check if the value of the Message Age parameter in the Configuration
      //BPDU is less than that of the Max Age parameter
      if(messageAge < context->maxAge)
      {
         //Set the Message Age
         bpdu.messageAge = htons(messageAge * 256);

         //The Topology Change Acknowledge flag parameter for the port is reset
         port->topologyChangeAck = FALSE;
         //The Configuration Pending flag parameter for the port is reset
         port->configPending = FALSE;

         //The BPDU shall be transmitted through the port within a time maximum
         //BPDU transmission delay
         stpSendBpdu(port, &bpdu, STP_CONFIG_BPDU_SIZE);

         //The Hold Timer for the port is started
         stpStartTimer(&port->holdTimer, 0);
      }
   }
}


/**
 * @brief Record configuration information (8.6.2)
 * @param[in] port Pointer to the bridge port context
 * @param[in] bpdu Pointer to the received Configuration BPDU
 **/

void stpRecordConfigInfo(StpBridgePort *port, const StpBpdu *bpdu)
{
   //The Designated Root, Designated Cost, Designated Bridge, and Designated
   //Port parameters held for the port are set to the values of the Root
   //Identifier, Root Path Cost, Bridge Identifier, and Port Identifier
   //parameters conveyed in the received Configuration BPDU
   port->designatedRoot.priority = ntohs(bpdu->rootId.priority);
   port->designatedRoot.addr = bpdu->rootId.addr;
   port->designatedCost = ntohl(bpdu->rootPathCost);
   port->designatedBridge.priority = ntohs(bpdu->bridgeId.priority);
   port->designatedBridge.addr = bpdu->bridgeId.addr;
   port->designatedPort = ntohs(bpdu->portId);

   //The Message Age Timer for the Port is started, to run from the value of
   //the Message Age parameter conveyed in the received Configuration BPDU
   stpStartTimer(&port->messageAgeTimer, ntohs(bpdu->messageAge) / 256);
}


/**
 * @brief Record configuration timeout values (8.6.3)
 * @param[in] context Pointer to the STP bridge context
 * @param[in] bpdu Pointer to the received Configuration BPDU
 **/

void stpRecordConfigTimeoutValues(StpBridgeContext *context, const StpBpdu *bpdu)
{
   //The Max Age, Hello Time and Forward Delay parameters held by the bridge
   //are set to the values conveyed in the received Configuration BPDU
   context->maxAge = ntohs(bpdu->maxAge) / 256;
   context->helloTime = ntohs(bpdu->helloTime) / 256;
   context->forwardDelay = ntohs(bpdu->forwardDelay) / 256;

   //The Topology Change parameter held by the bridge is set to the value of
   //the Topology Change flag conveyed in the received Configuration BPDU
   if((bpdu->flags & STP_BPDU_FLAG_TC) != 0)
   {
      //The Topology Change flag parameter held for the bridge is set
      stpUpdateTopologyChange(context, TRUE);
   }
   else
   {
      //The Topology Change flag parameter held for the bridge is reset
      stpUpdateTopologyChange(context, FALSE);
   }
}


/**
 * @brief Configuration BPDU generation (8.6.4)
 * @param[in] context Pointer to the STP bridge context
 **/

void stpConfigBpduGeneration(StpBridgeContext *context)
{
   uint_t i;
   StpBridgePort *port;

   //For each port that is the Designated port for the LAN to which it is
   //attached, the Transmit Configuration BPDU procedure is used
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //Check port state
      if(port->state != STP_PORT_STATE_DISABLED && port->macOperState)
      {
         //Check whether the value of the Designated Bridge and Designated Port
         //parameters held for the port are the same as that of the Bridge
         //Identifier and the Port Identifier for that port, respectively
         if(stpDesignatedPort(port))
         {
            //Send a Configuration BPDU
            stpTransmitConfigBpdu(port);
         }
      }
   }
}


/**
 * @brief Reply to Configuration BPDU (8.6.5)
 * @param[in] port Pointer to the bridge port context
 **/

void stpReplyToConfigBpdu(StpBridgePort *port)
{
   //The Transmit Configuration BPDU procedure is used for the port on which
   //the Configuration BPDU was received
   stpTransmitConfigBpdu(port);
}


/**
 * @brief Transmit Topology Change Notification BPDU (8.6.6)
 * @param[in] context Pointer to the STP bridge context
 **/

void stpTransmitTcnBpdu(StpBridgeContext *context)
{
   StpBpdu bpdu;
   StpBridgePort *rootPort;

   //Point to the Root port
   rootPort = stpGetBridgePort(context, context->rootPort);

   //Sanity check
   if(rootPort != NULL)
   {
      //Format Topology Change Notification BPDU
      bpdu.protocolId = HTONS(STP_PROTOCOL_ID);
      bpdu.protocolVersionId = STP_PROTOCOL_VERSION;
      bpdu.bpduType = STP_BPDU_TYPE_TCN;

      //The Topology Change Notification BPDU shall be transmitted through the
      //Root port within a time of maximum BPDU transmission delay
      stpSendBpdu(rootPort, &bpdu, STP_TCN_BPDU_SIZE);
   }
}


/**
 * @brief Configuration update (8.6.7)
 * @param[in] context Pointer to the STP bridge context
 **/

void stpConfigUpdate(StpBridgeContext *context)
{
   //The procedure for Root Selection shall be used to select the Designated
   //Root and the Root port, and to calculate the Root Path Cost for this bridge
   stpRootSelection(context);

   //The procedure for Designated Port Selection shall be used to determine for
   //each port whether the port should become the Designated port for the LAN
   //to which it is attached
   stpDesignatedPortSelection(context);
}


/**
 * @brief Root selection (8.6.8)
 * @param[in] context Pointer to the STP bridge context
 **/

void stpRootSelection(StpBridgeContext *context)
{
   uint_t i;
   StpBridgePort *port;
   StpBridgePort *rootPort;

   //Initialize root port
   rootPort = NULL;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //Make sure the port is not the Designated port for the LAN to which it
      //is attached, is not Disabled, and has a Designated Root parameter of
      //higher priority than the bridge's Bridge Identifier
      if(port->state != STP_PORT_STATE_DISABLED && !stpDesignatedPort(port) &&
         stpCompareBridgeId(&port->designatedRoot, &context->bridgeId) < 0)
      {
         //Select the root port
         if(rootPort == NULL)
         {
            rootPort = port;
         }
         else if(stpCompareBridgeId(&port->designatedRoot,
            &rootPort->designatedRoot) < 0)
         {
            //This port has the highest priority Root
            rootPort = port;
         }
         else if(stpCompareBridgeId(&port->designatedRoot,
            &rootPort->designatedRoot) > 0)
         {
         }
         else if((port->designatedCost + port->pathCost) <
            (rootPort->designatedCost + rootPort->pathCost))
         {
            //This port has the lowest Root Path Cost
            rootPort = port;
         }
         else if((port->designatedCost + port->pathCost) >
            (rootPort->designatedCost + rootPort->pathCost))
         {
         }
         else if(stpCompareBridgeId(&port->designatedBridge,
            &rootPort->designatedBridge) < 0)
         {
            //This port has the highest priority Bridge Identifier recorded as
            //the Designated Bridge for the LAN to which the port is attached
            rootPort = port;
         }
         else if(stpCompareBridgeId(&port->designatedBridge,
            &rootPort->designatedBridge) > 0)
         {
         }
         else if(port->designatedPort < rootPort->designatedPort)
         {
            //This port has the has the highest priority Port Identifier
            //recorded as the Designated port for the LAN to which the port
            //is attached
            rootPort = port;
         }
         else if(port->designatedPort > rootPort->designatedPort)
         {
         }
         else if(port->portId < rootPort->portId)
         {
            //This port has the highest priority Port Identifier
            rootPort = port;
         }
         else
         {
         }
      }
   }

   //Check whether one of the bridge ports has been identified as the Root port
   if(rootPort == NULL)
   {
      //If there is no such port, the value of the Root Port parameter is set
      //to zero
      context->rootPort = 0;

      //The Designated Root parameter held by the bridge is set to the Bridge
      //Identifier parameter held for the bridge
      context->designatedRoot = context->bridgeId;

      //The value of the Root Path Cost parameter held by the bridge is set to
      //zero
      context->rootPathCost = 0;
   }
   else
   {
      //Save the Port Identifier of the port that offers the lowest cost path
      //to the Root
      context->rootPort = rootPort->portId;

      //The Designated Root parameter held by the bridge is set to the
      //Designated Root parameter held for the Root port
      context->designatedRoot = rootPort->designatedRoot;

      //The value of the Root Path Cost parameter held by the bridge is set to
      //the value of the Root Path Cost parameter associated with the Root port
      context->rootPathCost = rootPort->designatedCost + rootPort->pathCost;
   }
}


/**
 * @brief Designated port selection (8.6.9)
 * @param[in] context Pointer to the STP bridge context
 **/

void stpDesignatedPortSelection(StpBridgeContext *context)
{
   uint_t i;
   StpBridgePort *port;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //The procedure to Become Designated Port shall be invoked for each port
      //that meet the following conditions
      if(stpDesignatedPort(port))
      {
         //The port has already been selected as the Designated port for the
         //LAN to which it is attached
         stpBecomeDesignatedPort(port);
      }
      else if(stpCompareBridgeId(&context->designatedRoot,
         &port->designatedRoot) != 0)
      {
         //The Designated Root parameter recorded for the bridge differs from
         //that recorded for the port
         stpBecomeDesignatedPort(port);
      }
      else if(context->rootPathCost < port->designatedCost)
      {
         //The bridge offers a Path of lower cost to the Root for the LAN to
         //which the port is attached
         stpBecomeDesignatedPort(port);
      }
      else if(context->rootPathCost == port->designatedCost &&
         stpCompareBridgeId(&context->bridgeId, &port->designatedBridge) < 0)
      {
         //The bridge offers a Path of equal cost to the Root, and the bridge's
         //Bridge Identifier denotes a bridge of higher priority than that
         //recorded as the Designated Bridge for that port
         stpBecomeDesignatedPort(port);
      }
      else if(context->rootPathCost == port->designatedCost &&
         stpCompareBridgeId(&context->bridgeId, &port->designatedBridge) == 0 &&
         port->portId < port->designatedPort)
      {
         //The bridge offers a Path of equal cost to the Root, and the bridge
         //is the Designated Bridge for the LAN to which the port is attached,
         //and the Port Identifier of the port is of higher priority than that
         //recorded as the Designated Port
         stpBecomeDesignatedPort(port);
      }
      else
      {
         //Just for sanity
      }
   }
}


/**
 * @brief Become Designated port (8.6.10)
 * @param[in] port Pointer to the bridge port context
 **/

void stpBecomeDesignatedPort(StpBridgePort *port)
{
   StpBridgeContext *context;

   //Point to the STP bridge context
   context = port->context;

   //The Designated Root parameter held for the port is set to the value of the
   //Designated Root parameter held by the bridge
   port->designatedRoot = context->designatedRoot;

   //The Designated Cost parameter held for the port is set to the value of the
   //Root Path Cost held by the bridge
   port->designatedCost = context->rootPathCost;

   //The Designated Bridge parameter held for the port is set to the Bridge
   //Identifier of the bridge
   port->designatedBridge = context->bridgeId;

   //The Designated Port parameter held for the port is set to the Port Identifier
   //of the port
   port->designatedPort = port->portId;
}


/**
 * @brief Port state selection (8.6.11)
 * @param[in] context Pointer to the STP bridge context
 **/

void stpPortStateSelection(StpBridgeContext *context)
{
   uint_t i;
   StpBridgePort *port;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //Root, Designated or Alternate port?
      if(stpRootPort(port))
      {
         //The Configuration Pending flag parameter and Topology Change
         //Acknowledge flag parameter for the port are reset
         port->configPending = FALSE;
         port->topologyChangeAck = FALSE;

         //The Make Forwarding procedure is used for the port
         stpMakeForwarding(port);
      }
      else if(stpDesignatedPort(port))
      {
         //The Message Age Timer for the port is stopped, if running
         stpStopTimer(&port->messageAgeTimer);

         //The Make Forwarding procedure is used for the port
         stpMakeForwarding(port);
      }
      else
      {
         //The Configuration Pending flag parameter and Topology Change
         //Acknowledge flag parameter for the port are reset
         port->configPending = FALSE;
         port->topologyChangeAck = FALSE;

         //The Make Blocking procedure is used for the port
         stpMakeBlocking(port);
      }
   }
}


/**
 * @brief Make forwarding (8.6.12)
 * @param[in] port Pointer to the bridge port context
 **/

void stpMakeForwarding(StpBridgePort *port)
{
   //Check whether the port state is Blocking
   if(port->state == STP_PORT_STATE_BLOCKING)
   {
      //The port state is set to Listening
      stpUpdatePortState(port, STP_PORT_STATE_LISTENING);
      //The Forward Delay Timer for the port is started
      stpStartTimer(&port->forwardDelayTimer, 0);
   }
}


/**
 * @brief Make blocking (8.6.13)
 * @param[in] port Pointer to the bridge port context
 **/

void stpMakeBlocking(StpBridgePort *port)
{
   //Check whether the port is not in the Disabled or the Blocking state
   if(port->state != STP_PORT_STATE_DISABLED &&
      port->state != STP_PORT_STATE_BLOCKING)
   {
      //If the port is in the Forwarding or Learning State and the Change
      //Detection Enabled parameter for the port is set, the Topology Change
      //Detection procedure is invoked
      if(port->state == STP_PORT_STATE_FORWARDING ||
         port->state == STP_PORT_STATE_LEARNING)
      {
         if(port->changeDetectionEnabled)
         {
            stpTopologyChangeDetection(port->context);
         }
      }

      //The port state is set to Blocking
      stpUpdatePortState(port, STP_PORT_STATE_BLOCKING);
      //The Forward Delay Timer for the port is stopped
      stpStopTimer(&port->forwardDelayTimer);
   }
}


/**
 * @brief Topology change detection (8.6.14)
 * @param[in] context Pointer to the STP bridge context
 **/

void stpTopologyChangeDetection(StpBridgeContext *context)
{
   //Check if the bridge has been selected as the Root
   if(stpRootBridge(context))
   {
      //The Topology Change flag parameter held for the bridge is set
      stpUpdateTopologyChange(context, TRUE);
      //The Topology Change Timer for the bridge is started
      stpStartTimer(&context->topologyChangeTimer, 0);
   }
   else
   {
      //Topology Change Detected flag parameter not already set?
      if(!context->topologyChangeDetected)
      {
         //The Transmit Topology Change Notification BPDU procedure is invoked
         stpTransmitTcnBpdu(context);
         //The Topology Change Notification Timer is started
         stpStartTimer(&context->tcnTimer, 0);
      }
   }

   //The Topology Change Detected flag parameter for the bridge is set
   context->topologyChangeDetected = TRUE;
}


/**
 * @brief Topology change acknowledged (8.6.15)
 * @param[in] context Pointer to the STP bridge context
 **/

void stpTopologyChangeAcked(StpBridgeContext *context)
{
   //The Topology Change Detected flag parameter held for the bridge is reset
   context->topologyChangeDetected = FALSE;
   //The Topology Change Notification Timer is stopped
   stpStopTimer(&context->tcnTimer);
}


/**
 * @brief Acknowledge topology change (8.6.16)
 * @param[in] port Pointer to the bridge port context
 **/

void stpAckTopologyChange(StpBridgePort *port)
{
   //The Topology Change Acknowledge flag parameter for the port is set
   port->topologyChangeAck = TRUE;
   //The Transmit Configuration BPDU procedure is used for the port
   stpTransmitConfigBpdu(port);
}

#endif

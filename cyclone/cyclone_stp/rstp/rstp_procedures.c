/**
 * @file rstp_procedures.c
 * @brief RSTP state machine procedures
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
#include "rstp/rstp_procedures.h"
#include "rstp/rstp_conditions.h"
#include "rstp/rstp_bpdu.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//Port roles
const RstpParamName rstpPortRoles[] =
{
   {STP_PORT_ROLE_DISABLED,   "Disabled"},
   {STP_PORT_ROLE_ROOT,       "Root"},
   {STP_PORT_ROLE_DESIGNATED, "Designated"},
   {STP_PORT_ROLE_ALTERNATE,  "Alternate"},
   {STP_PORT_ROLE_BACKUP,     "Backup"}
};


/**
 * @brief Compare Spanning Tree information (17.21.1)
 * @param[in] port Pointer to the bridge port context
 * @param[in] newInfoIs Procedure's parameter
 * @return Boolean
 **/

bool_t rstpBetterOrSameInfo(RstpBridgePort *port, RstpInfoIs newInfoIs)
{
   bool_t res;

   //Check the source of the Spanning Tree information
   if(newInfoIs == RSTP_INFO_IS_RECEIVED &&
      port->infoIs == RSTP_INFO_IS_RECEIVED &&
      rstpComparePriority(&port->msgPriority, &port->portPriority) >= 0)
   {
      //The function returns TRUE if the procedure's parameter newInfoIs is
      //Received, and infoIs is Received and the msgPriority vector is better
      //than or the same as the portPriority vector
      res = TRUE;
   }
   else if(newInfoIs == RSTP_INFO_IS_MINE &&
      port->infoIs == RSTP_INFO_IS_MINE &&
      rstpComparePriority(&port->designatedPriority, &port->portPriority) >= 0)
   {
      //The function returns TRUE if The procedure's parameter newInfoIs is
      //Mine, and infoIs is Mine and the designatedPriority vector is better
      //than or the same as the portPriority vector
      res = TRUE;
   }
   else
   {
      //The function returns FALSE otherwise
      res = FALSE;
   }

   //Return boolean value
   return res;
}


/**
 * @brief Clear reselect for all ports of the bridge (17.21.2)
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpClearReselectTree(RstpBridgeContext *context)
{
   uint_t i;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Clear the reselect variable
      context->ports[i].reselect = FALSE;
   }
}


/**
 * @brief Stop forwarding frames through the port (17.21.3)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpDisableForwarding(RstpBridgePort *port)
{
   //Debug message
   TRACE_INFO("Port %" PRIu8 ": Disable forwarding...\r\n", port->portIndex);
}


/**
 * @brief Stop learning from frames received on the port (17.21.4)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpDisableLearning(RstpBridgePort *port)
{
   //Debug message
   TRACE_INFO("Port %" PRIu8 ": Disable learning...\r\n", port->portIndex);

   //Update the state of the port
   rstpUpdatePortState(port, SWITCH_PORT_STATE_BLOCKING);
}


/**
 * @brief Start forwarding frames through the port (17.21.5)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpEnableForwarding(RstpBridgePort *port)
{
   //Debug message
   TRACE_INFO("Port %" PRIu8 ": Enable forwarding...\r\n", port->portIndex);

   //Update the state of the port
   rstpUpdatePortState(port, SWITCH_PORT_STATE_FORWARDING);

   //Increment the number of times the port has transitioned from the Learning
   //state to the Forwarding state
   port->forwardTransitions++;
}


/**
 * @brief Start learning from frames received on the port (17.21.6)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpEnableLearning(RstpBridgePort *port)
{
   //Debug message
   TRACE_INFO("Port %" PRIu8 ": Enable learning...\r\n", port->portIndex);

   //Update the state of the port
   rstpUpdatePortState(port, SWITCH_PORT_STATE_LEARNING);
}


/**
 * @brief Update the value of tcWhile (17.21.7)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpNewTcWhile(RstpBridgePort *port)
{
   //Check whether the value of tcWhile is zero
   if(port->tcWhile == 0)
   {
      //Update the number of topology changes
      rstpUpdateTopologyChangeCount(port->context);

      //Check whether sendRSTP is set
      if(port->sendRstp)
      {
         //If the value of tcWhile is zero and sendRSTP is TRUE, this procedure
         //sets the value of tcWhile to HelloTime plus one second and sets
         //newInfo TRUE
         port->tcWhile = rstpHelloTime(port) + 1;
         port->newInfo = TRUE;
      }
      else
      {
         //If the value of tcWhile is zero and sendRSTP is FALSE, this procedure
         //sets the value of tcWhile to the sum of the Max Age and Forward Delay
         //components of rootTimes and does not change the value of newInfo
         port->tcWhile = port->context->rootTimes.maxAge +
            port->context->rootTimes.forwardDelay;
      }
   }
   else
   {
      //Otherwise the procedure takes no action
   }
}


/**
 * @brief Decode message priority and timer values from the received BPDU (17.21.8)
 * @param[in] port Pointer to the bridge port context
 * @return State of the received Spanning Tree information
 **/

RstpRcvdInfo rstpRcvInfo(RstpBridgePort *port)
{
   int_t res;
   uint8_t role;
   RstpRcvdInfo portInfo;
   const RstpBpdu *bpdu;

   //Point to the received BPDU
   bpdu = &port->context->bpdu;

   //Errata (refer to IEEE Std 802.1Q-2018, section 13.29.13)
   if(bpdu->bpduType == RSTP_BPDU_TYPE_TCN)
   {
      //Set rcvdTcn if a TCN BPDU has been received
      port->rcvdTcn = TRUE;
   }

   //Extract the message priority values from the received BPDU storing them in
   //the msgPriority variable
   port->msgPriority.rootBridgeId.priority = ntohs(bpdu->rootId.priority);
   port->msgPriority.rootBridgeId.addr = bpdu->rootId.addr;
   port->msgPriority.rootPathCost = ntohl(bpdu->rootPathCost);
   port->msgPriority.designatedBridgeId.priority = ntohs(bpdu->bridgeId.priority);
   port->msgPriority.designatedBridgeId.addr = bpdu->bridgeId.addr;
   port->msgPriority.designatedPortId = ntohs(bpdu->portId);

   //The fifth component of the message priority vector value is the port
   //identifier of the port through which the message was received
   port->msgPriority.bridgePortId = port->portId;

   //Extract the timer values from the received BPDU storing them in the msgTimes
   //variable
   port->msgTimes.messageAge = ntohs(bpdu->messageAge) / 256;
   port->msgTimes.maxAge = ntohs(bpdu->maxAge) / 256;
   port->msgTimes.forwardDelay = ntohs(bpdu->forwardDelay) / 256;
   port->msgTimes.helloTime = ntohs(bpdu->helloTime) / 256;

   //Check BPDU type
   if(bpdu->bpduType == RSTP_BPDU_TYPE_RST)
   {
      //Decode port role
      role = bpdu->flags & RSTP_BPDU_FLAG_PORT_ROLE;
   }
   else if(bpdu->bpduType == RSTP_BPDU_TYPE_CONFIG)
   {
      //A Configuration BPDU explicitly conveys a Designated port role
      role = RSTP_BPDU_FLAG_PORT_ROLE_DESIGNATED;
   }
   else
   {
      //Unknown port role
      role = RSTP_BPDU_FLAG_PORT_ROLE_UNKNOWN;
   }

   //Check port role
   if(role == RSTP_BPDU_FLAG_PORT_ROLE_DESIGNATED)
   {
      //Compare message priority and port priority vectors
      res = rstpComparePriority(&port->msgPriority, &port->portPriority);

      //A message priority vector is superior to the port priority vector if,
      //and only if, the message priority vector is better than the port
      //priority vector, or the Designated Bridge Identifier Bridge Address and
      //Designated Port Identifier Port Number components are the same
      if(res < 0)
      {
         //Compare Designated Bridge Identifier Bridge Address and Designated
         //Port Identifier Port Number components
         if(rstpCompareBridgeAddr(&port->msgPriority.designatedBridgeId.addr,
            &port->portPriority.designatedBridgeId.addr) == 0 &&
            rstpComparePortNum(port->msgPriority.designatedPortId,
            port->portPriority.designatedPortId) == 0)
         {
            //The message has been transmitted from the same Designated port as
            //a previously received superior message
            res = 1;
         }
      }

      //Check comparison result
      if(res > 0)
      {
         //Return SuperiorDesignatedInfo if the message priority is superior to
         //the port priority vector
         portInfo = RSTP_RCVD_INFO_SUPERIOR_DESIGNATED;
      }
      else if(res == 0)
      {
         //Check whether any of the received timer parameter values (msgTimes)
         //differ from those already held for the port (portTimes)
         if(rstpCompareTimes(&port->msgTimes, &port->portTimes) != 0)
         {
            //Return SuperiorDesignatedInfo
            portInfo = RSTP_RCVD_INFO_SUPERIOR_DESIGNATED;
         }
         else
         {
            //Return RepeatedDesignatedInfo
            portInfo = RSTP_RCVD_INFO_REPEATED_DESIGNATED;
         }
      }
      else
      {
         //Returns InferiorDesignatedInfo if the message priority vector is
         //worse than the Port's port priority vector
         portInfo = RSTP_RCVD_INFO_INFERIOR_DESIGNATED;
      }
   }
   else if(role == RSTP_BPDU_FLAG_PORT_ROLE_ROOT ||
      role == RSTP_BPDU_FLAG_PORT_ROLE_ALT_BACKUP)
   {
      //Compare message priority and port priority vectors
      res = rstpComparePriority(&port->msgPriority, &port->portPriority);

      //Check comparison result
      if(res <= 0)
      {
         //Return InferiorRootAlternateInfo if the received message conveys a
         //Root Port, Alternate Port, or Backup Port Role and a message priority
         //that is the same as or worse than the port priority vector
         portInfo = RSTP_RCVD_INFO_INFERIOR_ROOT_ALTERNATE;
      }
      else
      {
         //Return OtherInfo
         portInfo = RSTP_RCVD_INFO_OTHER;
      }
   }
   else
   {
      //Otherwise, return OtherInfo
      portInfo = RSTP_RCVD_INFO_OTHER;
   }

   //Return the state of the received Spanning Tree information
   return portInfo;
}


/**
 * @brief Record agreement (17.21.9)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpRecordAgreement(RstpBridgePort *port)
{
   const RstpBpdu *bpdu;

   //Point to the received BPDU
   bpdu = &port->context->bpdu;

   //If rstpVersion is TRUE, operPointToPointMAC is TRUE, and the received
   //Configuration Message has the Agreement flag set, the agreed flag is set
   //and the proposing flag is cleared. Otherwise, the agreed flag is cleared
   if(rstpVersion(port->context) && port->operPointToPointMac &&
      (bpdu->flags & RSTP_BPDU_FLAG_AGREEMENT) != 0)
   {
      port->agreed = TRUE;
      port->proposing = FALSE;
   }
   else
   {
      port->agreed = FALSE;
   }
}


/**
 * @brief Record dispute (17.21.10)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpRecordDispute(RstpBridgePort *port)
{
   const RstpBpdu *bpdu;

   //Point to the received BPDU
   bpdu = &port->context->bpdu;

   //If an RST BPDU with the learning flag set has been received, the
   //disputed variable is set and the agreed variable is cleared (refer
   //to IEEE Std 802.1D-2004 errata)
   if((bpdu->flags & RSTP_BPDU_FLAG_LEARNING) != 0)
   {
      port->disputed = TRUE;
      port->agreed = FALSE;
   }
}


/**
 * @brief Record proposal (17.21.11)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpRecordProposal(RstpBridgePort *port)
{
   uint8_t role;
   const RstpBpdu *bpdu;

   //Point to the received BPDU
   bpdu = &port->context->bpdu;

   //Decode port role
   role = bpdu->flags & RSTP_BPDU_FLAG_PORT_ROLE;

   //If the received Configuration Message conveys a Designated Port Role,
   //and has the Proposal flag is set, the proposed flag is set. Otherwise,
   //the proposed flag is not changed
   if(role == RSTP_BPDU_FLAG_PORT_ROLE_DESIGNATED)
   {
      if((bpdu->flags & RSTP_BPDU_FLAG_PROPOSAL) != 0)
      {
         port->proposed = TRUE;
      }
   }
}


/**
 * @brief Record priority (17.21.12)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpRecordPriority(RstpBridgePort *port)
{
   //Set the components of the portPriority variable to the values of the
   //corresponding msgPriority components
   port->portPriority = port->msgPriority;
}


/**
 * @brief Set portTimes variable (17.21.13)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpRecordTimes(RstpBridgePort *port)
{
   //Set portTimes' Message Age, Max Age, and Forward Delay to the received
   //values held in the messageTimes parameter
   port->portTimes.messageAge = port->msgTimes.messageAge;
   port->portTimes.maxAge = port->msgTimes.maxAge;
   port->portTimes.forwardDelay = port->msgTimes.forwardDelay;

   //Set portTimes' Hello Time to msgTimes' Hello Time if that is greater
   //than the minimum specified value, and to that minimum otherwise
   if(port->msgTimes.helloTime > RSTP_MIN_BRIDGE_HELLO_TIME)
   {
      port->portTimes.helloTime = port->msgTimes.helloTime;
   }
   else
   {
      port->portTimes.helloTime = RSTP_MIN_BRIDGE_HELLO_TIME;
   }
}


/**
 * @brief Set sync for all ports of the bridge (17.21.14)
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpSetSyncTree(RstpBridgeContext *context)
{
   uint_t i;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Set the sync variable
      context->ports[i].sync = TRUE;
   }
}


/**
 * @brief Set reRoot for all ports of the bridge (17.21.15)
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpSetReRootTree(RstpBridgeContext *context)
{
   uint_t i;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Set the reRoot variable
      context->ports[i].reRoot = TRUE;
   }
}


/**
 * @brief Set the selected variable for all ports of the bridge (17.21.16)
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpSetSelectedTree(RstpBridgeContext *context)
{
   uint_t i;
   bool_t reselect;

   //Check whether the reselect variable is TRUE for any port
   for(reselect = FALSE, i = 0; i < context->numPorts; i++)
   {
      reselect |= context->ports[i].reselect;
   }

   //Set the selected variable TRUE for all ports of the bridge if reselect
   //is FALSE for all ports. If reselect is TRUE for any port, this procedure
   //takes no action
   if(!reselect)
   {
      //Loop through the ports of the bridge
      for(i = 0; i < context->numPorts; i++)
      {
         //Set the selected variable
         context->ports[i].selected = TRUE;
      }
   }
}


/**
 * @brief Update rcvdTc, rcvdTcAck and rcvdTcn flags (17.21.17)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpSetTcFlags(RstpBridgePort *port)
{
   const RstpBpdu *bpdu;

   //Point to the received BPDU
   bpdu = &port->context->bpdu;

   //Check BPDU type
   if(bpdu->bpduType == RSTP_BPDU_TYPE_CONFIG ||
      bpdu->bpduType == RSTP_BPDU_TYPE_RST)
   {
      //Sets rcvdTc and/or rcvdTcAck if the Topology Change and/or Topology
      //Change Acknowledgment flags, respectively, are set in a Configuration
      //BPDU or RST BPDU
      if((bpdu->flags & RSTP_BPDU_FLAG_TC) != 0)
      {
         port->rcvdTc = TRUE;
      }

      if((bpdu->flags & RSTP_BPDU_FLAG_TC_ACK) != 0)
      {
         port->rcvdTcAck = TRUE;
      }
   }
   else if(bpdu->bpduType == RSTP_BPDU_TYPE_TCN)
   {
      //Set rcvdTcn TRUE if the BPDU is a TCN BPDU
      port->rcvdTcn = TRUE;
   }
   else
   {
      //Just for sanity
   }
}


/**
 * @brief Set tcProp for all ports except the port that called the procedure (17.21.18)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpSetTcPropTree(RstpBridgePort *port)
{
   uint_t i;
   RstpBridgeContext *context;

   //Point to the RSTP bridge context
   context = port->context;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Set tcProp for all ports except the port that called the procedure
      if(&context->ports[i] != port)
      {
         context->ports[i].tcProp = TRUE;
      }
   }
}


/**
 * @brief Transmit a Configuration BPDU (17.21.19)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpTxConfig(RstpBridgePort *port)
{
   RstpBpdu bpdu;

   //Format Configuration BPDU
   bpdu.protocolId = HTONS(STP_PROTOCOL_ID);
   bpdu.protocolVersionId = STP_PROTOCOL_VERSION;
   bpdu.bpduType = RSTP_BPDU_TYPE_CONFIG;
   bpdu.flags = 0;

   //The Topology Change flag is set if tcWhile is non-zero for the port
   if(port->tcWhile != 0)
   {
      bpdu.flags |= RSTP_BPDU_FLAG_TC;
   }

   //The Topology Change Acknowledgement flag is set to the value of tcAck
   //for the port
   if(port->tcAck)
   {
      bpdu.flags |= RSTP_BPDU_FLAG_TC_ACK;
   }

   //The components of the message priority vector conveyed in the BPDU are set
   //to the value of designatedPriority for this port
   bpdu.rootId.priority = htons(port->designatedPriority.rootBridgeId.priority);
   bpdu.rootId.addr = port->designatedPriority.rootBridgeId.addr;
   bpdu.rootPathCost = htonl(port->designatedPriority.rootPathCost);
   bpdu.bridgeId.priority = htons(port->designatedPriority.designatedBridgeId.priority);
   bpdu.bridgeId.addr = port->designatedPriority.designatedBridgeId.addr;
   bpdu.portId = htons(port->designatedPriority.designatedPortId);

   //The value of the Message Age, Max Age, Fwd Delay, and Hello Time parameters
   //conveyed in the BPDU are set to the values held in designatedTimes for the
   //port
   bpdu.messageAge = htons(port->designatedTimes.messageAge * 256);
   bpdu.maxAge = htons(port->designatedTimes.maxAge * 256);
   bpdu.helloTime = htons(port->designatedTimes.helloTime * 256);
   bpdu.forwardDelay = htons(port->designatedTimes.forwardDelay * 256);

   //Send BPDU
   rstpSendBpdu(port, &bpdu, RSTP_CONFIG_BPDU_SIZE);
}


/**
 * @brief Transmit a Rapid Spanning Tree BPDU (17.21.20)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpTxRstp(RstpBridgePort *port)
{
   RstpBpdu bpdu;

   //Format Rapid Spanning Tree BPDU
   bpdu.protocolId = HTONS(STP_PROTOCOL_ID);
   bpdu.protocolVersionId = RSTP_PROTOCOL_VERSION;
   bpdu.bpduType = RSTP_BPDU_TYPE_RST;
   bpdu.flags = 0;

   //The Port Role in the BPDU is set to the current value of the role variable
   //for the transmitting port
   if(port->role == STP_PORT_ROLE_ALTERNATE ||
      port->role == STP_PORT_ROLE_BACKUP)
   {
      //Alternate or Backup port role
      bpdu.flags |= RSTP_BPDU_FLAG_PORT_ROLE_ALT_BACKUP;
   }
   else if(port->role == STP_PORT_ROLE_ROOT)
   {
      //Root port role
      bpdu.flags |= RSTP_BPDU_FLAG_PORT_ROLE_ROOT;
   }
   else if(port->role == STP_PORT_ROLE_DESIGNATED)
   {
      //Designated port role
      bpdu.flags |= RSTP_BPDU_FLAG_PORT_ROLE_DESIGNATED;
   }
   else
   {
      //The Unknown value of Port Role cannot be generated by a valid
      //implementation
      bpdu.flags |= RSTP_BPDU_FLAG_PORT_ROLE_UNKNOWN;
   }

   //The Agreement and Proposal flags in the BPDU are set to the values of the
   //agree and proposing variables for the transmitting port, respectively
   if(port->agree)
   {
      bpdu.flags |= RSTP_BPDU_FLAG_AGREEMENT;
   }

   if(port->proposing)
   {
      bpdu.flags |= RSTP_BPDU_FLAG_PROPOSAL;
   }

   //The Topology Change flag is set if tcWhile is non-zero for the port. The
   //topology change acknowledge flag in the BPDU is never used and is set to
   //zero
   if(port->tcWhile != 0)
   {
      bpdu.flags |= RSTP_BPDU_FLAG_TC;
   }

   //The Learning and Forwarding flags in the BPDU are set to the values of the
   //learning and forwarding variables for the transmitting port, respectively
   if(port->learning)
   {
      bpdu.flags |= RSTP_BPDU_FLAG_LEARNING;
   }

   if(port->forwarding)
   {
      bpdu.flags |= RSTP_BPDU_FLAG_FORWARDING;
   }

   //The components of the message priority vector conveyed in the BPDU are set
   //to the value of designatedPriority for this port
   bpdu.rootId.priority = htons(port->designatedPriority.rootBridgeId.priority);
   bpdu.rootId.addr = port->designatedPriority.rootBridgeId.addr;
   bpdu.rootPathCost = htonl(port->designatedPriority.rootPathCost);
   bpdu.bridgeId.priority = htons(port->designatedPriority.designatedBridgeId.priority);
   bpdu.bridgeId.addr = port->designatedPriority.designatedBridgeId.addr;
   bpdu.portId = htons(port->designatedPriority.designatedPortId);

   //The value of the Message Age, Max Age, Fwd Delay, and Hello Time parameters
   //conveyed in the BPDU are set to the values held in designatedTimes for the
   //port
   bpdu.messageAge = htons(port->designatedTimes.messageAge * 256);
   bpdu.maxAge = htons(port->designatedTimes.maxAge * 256);
   bpdu.helloTime = htons(port->designatedTimes.helloTime * 256);
   bpdu.forwardDelay = htons(port->designatedTimes.forwardDelay * 256);

   //The Version 1 Length field takes the value 0, which indicates that there
   //is no Version 1 protocol information present
   bpdu.version1Length = 0;

   //Send BPDU
   rstpSendBpdu(port, &bpdu, RSTP_RST_BPDU_SIZE);
}


/**
 * @brief Transmit a Topology Change Notification BPDU (17.21.21)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpTxTcn(RstpBridgePort *port)
{
   RstpBpdu bpdu;

   //Format Topology Change Notification BPDU
   bpdu.protocolId = HTONS(STP_PROTOCOL_ID);
   bpdu.protocolVersionId = STP_PROTOCOL_VERSION;
   bpdu.bpduType = RSTP_BPDU_TYPE_TCN;

   //Send BPDU
   rstpSendBpdu(port, &bpdu, RSTP_TCN_BPDU_SIZE);
}


/**
 * @brief Update rcvdSTP and rcvdRSTP variables depending on BPDU version (17.21.22)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpUpdtBpduVersion(RstpBridgePort *port)
{
   const RstpBpdu *bpdu;

   //Point to the received BPDU
   bpdu = &port->context->bpdu;

   //Check BPDU type
   if(bpdu->bpduType == RSTP_BPDU_TYPE_TCN ||
      bpdu->bpduType == RSTP_BPDU_TYPE_CONFIG)
   {
      //Sets rcvdSTP TRUE if the BPDU received is a version 0 or version 1 TCN
      //or a Configuration BPDU
      port->rcvdStp = TRUE;
   }
   else if(bpdu->bpduType == RSTP_BPDU_TYPE_RST)
   {
      //Set rcvdRSTP TRUE if the received BPDU is an RST BPDU
      port->rcvdRstp = TRUE;
   }
   else
   {
      //Just for sanity
   }
}


/**
 * @brief Update the Received Info timer (17.21.23)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpUpdtRcvdInfoWhile(RstpBridgePort *port)
{
   //The value assigned to rcvdInfoWhile is the three times the Hello Time,
   //if Message Age, incremented by 1 second and rounded to the nearest whole
   //second, does not exceed Max Age, and is zero otherwise. The values of
   //Message Age, Max Age, and Hello Time used in this calculation are taken
   //from portTimes
   if((port->portTimes.messageAge + 1) <= port->portTimes.maxAge)
   {
      port->rcvdInfoWhile = (3 * port->portTimes.helloTime) + 1;
   }
   else
   {
      port->rcvdInfoWhile = 0;
   }
}


/**
 * @brief Set the selectedRole to DisabledPort for all ports of the bridge (17.21.24)
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpUpdtRoleDisabledTree(RstpBridgeContext *context)
{
   uint_t i;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Set the selectedRole variable to DisabledPort
      context->ports[i].selectedRole = STP_PORT_ROLE_DISABLED;
   }
}


/**
 * @brief Update spanning tree information and port roles (17.21.25)
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpUpdtRolesTree(RstpBridgeContext *context)
{
   uint_t i;
   RstpBridgePort *port;
   RstpBridgePort *rootPort;
   RstpPriority rootPathPriority;

   //Initialize bridge's root priority vector
   context->rootPriority = context->bridgePriority;
   context->rootPortId = context->bridgePriority.bridgePortId;

   //Initialize bridge's rootTimes parameter
   context->rootTimes = context->bridgeTimes;

   //The port the root priority vector is derived from
   rootPort = NULL;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //Calculate the root path priority vector for each port that has a port
      //priority vector (portPriority plus portId) recorded from a received
      //message and not aged out
      if(port->infoIs == RSTP_INFO_IS_RECEIVED)
      {
         //A root path priority vector can be calculated from a received port
         //priority vector, by adding the receiving port's path cost to the
         //Root Path Cost component
         rootPathPriority = port->portPriority;
         rootPathPriority.rootPathCost += port->portPathCost;

         //The bridge's root priority vector (rootPriority plus rootPortId) is
         //chosen as the best of the set of priority vectors comprising the
         //bridge priority vector (BridgePriority) and all the calculated root
         //path priority vectors whose DesignatedBridgeID Bridge Address
         //component is not equal to that component of the Bridge's own bridge
         //priority vector
         if(rstpCompareBridgeAddr(&rootPathPriority.designatedBridgeId.addr,
            &context->bridgePriority.designatedBridgeId.addr) != 0)
         {
            //Calculate the best priority vector
            if(rstpComparePriority(&rootPathPriority, &context->rootPriority) > 0)
            {
               //Save current root path priority vector
               context->rootPriority = rootPathPriority;
               context->rootPortId = rootPathPriority.bridgePortId;

               //Save the port the root priority vector is now derived from
               rootPort = port;

               //Set the bridge's rootTimes parameter to portTimes for the port
               //associated with the selected root priority vector, with the
               //Message Age component incremented by 1 second and rounded to
               //the nearest whole second
               context->rootTimes = port->portTimes;
               context->rootTimes.messageAge++;
            }
         }
      }
   }

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //The designated priority vector is the root priority vector with the
      //Bridge Identifier substituted for the DesignatedBridgeID and the
      //Port Identifier substituted for the DesignatedPortID and BridgePortID
      //components
      port->designatedPriority.rootBridgeId = context->rootPriority.rootBridgeId;
      port->designatedPriority.rootPathCost = context->rootPriority.rootPathCost;
      port->designatedPriority.designatedBridgeId = context->bridgeId;
      port->designatedPriority.designatedPortId = port->portId;
      port->designatedPriority.bridgePortId = port->portId;

      //The designatedTimes for each port is set equal to the value of rootTimes
      //except for the Hello Time component, which is set equal to BridgeTimes'
      //Hello Time
      port->designatedTimes = context->rootTimes;
      port->designatedTimes.helloTime = context->bridgeTimes.helloTime;
   }

   //The port role for each port is assigned, and its port priority vector and
   //Spanning Tree timer information are updated
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //The port role for each port is assigned
      if(port->infoIs == RSTP_INFO_IS_DISABLED)
      {
         //If the Port is Disabled, selectedRole is set to DisabledPort
         port->selectedRole = STP_PORT_ROLE_DISABLED;
      }
      else if(port->infoIs == RSTP_INFO_IS_AGED)
      {
         //If the port priority vector information was aged, updtInfo is set
         //and selectedRole is set to DesignatedPort
         port->selectedRole = STP_PORT_ROLE_DESIGNATED;
         port->updtInfo = TRUE;
      }
      else if(port->infoIs == RSTP_INFO_IS_MINE)
      {
         //If the port priority vector was derived from another port on the
         //bridge or from the bridge itself as the Root bridge, selectedRole
         //is set to DesignatedPort
         port->selectedRole = STP_PORT_ROLE_DESIGNATED;

         //Additionally, updtInfo is set if the port priority vector differs
         //from the designated priority vector or the port's associated timer
         //parameters differ from those for the Root port
         if(rstpComparePriority(&port->portPriority, &port->designatedPriority) != 0 ||
            rstpCompareTimes(&port->portTimes, &context->rootTimes) != 0)
         {
            port->updtInfo = TRUE;
         }
      }
      else if(port->infoIs == RSTP_INFO_IS_RECEIVED)
      {
         //Check whether the root priority vector is derived from port priority
         //vector
         if(port == rootPort)
         {
            //If the port priority vector was received in a Configuration
            //message and is not aged, and the root priority vector is now
            //derived from it, selectedRole is set to RootPort and updtInfo
            //is reset
            port->selectedRole = STP_PORT_ROLE_ROOT;
            port->updtInfo = FALSE;
         }
         else
         {
            //Check whether the designated priority vector is better than the
            //port priority vector
            if(rstpComparePriority(&port->designatedPriority, &port->portPriority) > 0)
            {
               //selectedRole is set to DesignatedPort and updtInfo is set
               port->selectedRole = STP_PORT_ROLE_DESIGNATED;
               port->updtInfo = TRUE;
            }
            else
            {
               MacAddr *addr;
               uint16_t portId;

               //Retrieve the designated bridge and designated port components
               //of the port priority vector
               addr = &port->portPriority.designatedBridgeId.addr;
               portId = port->portPriority.designatedPortId;

               //Check whether the designated bridge and designated port
               //components of the port priority vector reflect another port
               //on this bridge
               if(rstpCompareBridgeAddr(addr, &context->bridgeId.addr) == 0 &&
                  rstpGetBridgePort(context, portId) != NULL)
               {
                  //selectedRole is set to BackupPort and updtInfo is reset
                  port->selectedRole = STP_PORT_ROLE_BACKUP;
                  port->updtInfo = FALSE;
               }
               else
               {
                  //selectedRole is set to AlternatePort and updtInfo is reset
                  port->selectedRole = STP_PORT_ROLE_ALTERNATE;
                  port->updtInfo = FALSE;
               }
            }
         }
      }
      else
      {
         //Just for sanity
      }
   }

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current bridge port
      port = &context->ports[i];

      //Display selected port role
      TRACE_DEBUG("Port %" PRIu8 ": Selected role is %s\r\n", port->portIndex,
         rstpGetParamName(port->selectedRole, rstpPortRoles, arraysize(rstpPortRoles)));
   }
}

#endif

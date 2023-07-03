/**
 * @file stp_bpdu.c
 * @brief BPDU processing
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
#include "stp/stp_operation.h"
#include "stp/stp_bpdu.h"
#include "stp/stp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (STP_SUPPORT == ENABLED)

//Bridge group address (refer to IEEE Std 802.1D-1998, section 7.12.3)
const MacAddr STP_BRIDGE_GROUP_ADDR = {{{0x01, 0x80, 0xC2, 0x00, 0x00, 0x00}}};

//Protocol versions
const StpParamName stpProtocolVersions[] =
{
   {STP_PROTOCOL_VERSION, "STP"}
};

//BPDU types
const StpParamName stpBpduTypes[] =
{
   {STP_BPDU_TYPE_CONFIG, "CONFIG"},
   {STP_BPDU_TYPE_TCN,    "TCN"}
};


/**
 * @brief Process incoming LLC frame
 * @param[in] interface Underlying network interface
 * @param[in] ethHeader Pointer to the Ethernet header
 * @param[in] data Pointer to the LLC frame
 * @param[in] length Length of the LLC frame, in bytes
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @param[in] param Pointer to the STP bridge context
 **/

void stpProcessLlcFrame(NetInterface *interface, EthHeader *ethHeader,
   const uint8_t *data, size_t length, NetRxAncillary *ancillary, void *param)
{
   const LlcHeader *llcHeader;
   const StpBpdu *bpdu;
   StpBridgeContext *context;
   StpBridgePort *port;

   //Point to the STP bridge context
   context = (StpBridgeContext *) param;

   //A MAC frame conveying a BPDU carries the Bridge Group Address in the
   //destination address field (refer to IEEE Std 802.1D-1998, section 8.3.2)
   if(!macCompAddr(&ethHeader->destAddr, &STP_BRIDGE_GROUP_ADDR))
      return;

   //Check the length of the LLC frame
   if(length < sizeof(LlcHeader))
      return;

   //Point to the LLC header
   llcHeader = (LlcHeader *) data;

   //The DSAP and SSAP fields must use the standard LLC address assigned to
   //the Bridge Spanning Tree Protocol (refer to IEEE Std 802.1D-1998, section
   //7.12.3)
   if(llcHeader->dsap != STP_LLC_DSAP || llcHeader->ssap != STP_LLC_SSAP ||
      llcHeader->control != STP_LLC_CTRL)
   {
      return;
   }

   //Invalid port number?
   if(ancillary->port < 1 || ancillary->port > context->numPorts)
      return;

   //Retrieve the port that matches the specified port number
   port = &context->ports[ancillary->port - 1];

   //BPDUs are encapsulated using 802.2 LLC header
   bpdu = (StpBpdu *) (data + sizeof(LlcHeader));

   //Retrieve the length of the BPDU
   length -= sizeof(LlcHeader);

   //Process incoming BPDU
   stpProcessBpdu(port, bpdu, length);
}


/**
 * @brief Process incoming bridge protocol data unit
 * @param[in] port Pointer to the bridge port context
 * @param[in] bpdu Pointer to the received BPDU
 * @param[in] length Length of the BPDU, in bytes
 * @return Error code
 **/

error_t stpProcessBpdu(StpBridgePort *port, const StpBpdu *bpdu,
   size_t length)
{
   //Debug message
   TRACE_INFO("Port %" PRIu8 ": BPDU received (%" PRIuSIZE " bytes)...\r\n",
      port->portIndex, length);

   //Dump BPDU for debugging purpose
   stpDumpBpdu(bpdu, length);

   //The BPDU must contain at least four octets
   if(length < STP_MIN_BPDU_SIZE)
      return ERROR_INVALID_LENGTH;

   //The Protocol Identifier must have the value specified for BPDUs
   if(ntohs(bpdu->protocolId) != STP_PROTOCOL_ID)
      return ERROR_INVALID_LENGTH;

   //Check BPDU type
   if(bpdu->bpduType == STP_BPDU_TYPE_CONFIG)
   {
      //A Configuration BPDU must contain at least 35 octets
      if(length < STP_CONFIG_BPDU_SIZE)
         return ERROR_INVALID_LENGTH;

      //The BPDU's Message Age must be less than its Max Age parameter
      if(ntohs(bpdu->messageAge) >= ntohs(bpdu->maxAge))
         return ERROR_INVALID_PACKET;

      //The Received Configuration BPDU procedure is invoked
      stpReceivedConfigBpdu(port, bpdu);
   }
   else if(bpdu->bpduType == STP_BPDU_TYPE_TCN)
   {
      //The Received Topology Change Notification BPDU procedure is invoked
      stpReceivedTcnBpdu(port, bpdu);
   }
   else
   {
      //Invalid BPDU received
      return ERROR_INVALID_TYPE;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Send bridge protocol data unit
 * @param[in] port Pointer to the bridge port context
 * @param[in] bpdu Pointer to the BPDU to be transmitted
 * @param[in] length Length of the BPDU, in bytes
 * @return Error code
 **/

error_t stpSendBpdu(StpBridgePort *port, const StpBpdu *bpdu,
   size_t length)
{
   error_t error;
   size_t offset;
   LlcHeader *llcHeader;
   NetBuffer *buffer;
   NetTxAncillary ancillary;
   StpBridgeContext *context;

   //Debug message
   TRACE_INFO("Port %" PRIu8 ": Sending BPDU (%" PRIuSIZE " bytes)...\r\n",
      port->portIndex, length);

   //Dump BPDU for debugging purpose
   stpDumpBpdu(bpdu, length);

   //Point to the STP bridge context
   context = port->context;

   //Allocate a buffer to hold the 802.2 LLC header
   buffer = ethAllocBuffer(sizeof(LlcHeader), &offset);

   //Successful memory allocation?
   if(buffer != NULL)
   {
      //Point to the LLC header
      llcHeader = netBufferAt(buffer, offset);

      //The DSAP and SSAP fields must use the standard LLC address assigned
      //to the Bridge Spanning Tree Protocol (refer to IEEE Std 802.1D-1998,
      //section 7.12.3)
      llcHeader->dsap = STP_LLC_DSAP;
      llcHeader->ssap = STP_LLC_SSAP;
      llcHeader->control = STP_LLC_CTRL;

      //BPDUs are encapsulated using 802.2 LLC header
      error = netBufferAppend(buffer, bpdu, length);

      //Check status code
      if(!error)
      {
         //Calculate the length of the LLC frame
         length += sizeof(LlcHeader);

         //Additional options can be passed to the stack along with the packet
         ancillary = NET_DEFAULT_TX_ANCILLARY;
         //Specify the source MAC address
         ancillary.srcMacAddr = port->macAddr;
         //Specify the destination port
         ancillary.port = port->portIndex;
         //BPDUs are transmitted regardless of the port state
         ancillary.override = TRUE;

         //The Bridge Group Address is used as destination MAC address to carry
         //BPDUs between STP entities
         error = ethSendFrame(context->interface, &STP_BRIDGE_GROUP_ADDR,
            length, buffer, offset, &ancillary);
      }

      //Free previously allocated memory
      netBufferFree(buffer);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Dump BPDU for debugging purpose
 * @param[in] bpdu Pointer to the BPDU to dump
 * @param[in] length Length of the BPDU, in bytes
 * @return Error code
 **/

error_t stpDumpBpdu(const StpBpdu *bpdu, size_t length)
{
#if (STP_TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   uint32_t t;

   //The BPDU must contain at least four octets
   if(length < STP_MIN_BPDU_SIZE)
      return ERROR_INVALID_LENGTH;

   //Dump Protocol Identifier
   TRACE_DEBUG("  Protocol Identifier = %" PRIu16 "\r\n",
      ntohs(bpdu->protocolId));

   //Dump Protocol Version Identifier
   TRACE_DEBUG("  Protocol Version Identifier = %" PRIu8 " (%s)\r\n",
      bpdu->protocolVersionId, stpGetParamName(bpdu->protocolVersionId,
      stpProtocolVersions, arraysize(stpProtocolVersions)));

   //Dump BPDU Type
   TRACE_DEBUG("  BPDU Type = 0x%02" PRIX8 " (%s)\r\n", bpdu->bpduType,
      stpGetParamName(bpdu->bpduType, stpBpduTypes, arraysize(stpBpduTypes)));

   //Check the length of the BPDU
   if(length >= STP_CONFIG_BPDU_SIZE)
   {
      //Dump Flags
      stpDumpFlags(bpdu->flags);

      //Dump Root Identifier
      TRACE_DEBUG("  Root Identifier = %" PRIu16 " / %s\r\n",
         ntohs(bpdu->rootId.priority), macAddrToString(&bpdu->rootId.addr, NULL));

      //Dump Root Path Cost
      TRACE_DEBUG("  Root Path Cost = %" PRIu32 "\r\n", ntohl(bpdu->rootPathCost));

      //Dump Bridge Identifier
      TRACE_DEBUG("  Bridge Identifier = %" PRIu16 " / %s\r\n",
         ntohs(bpdu->bridgeId.priority), macAddrToString(&bpdu->bridgeId.addr, NULL));

      //Dump Port Identifier
      TRACE_DEBUG("  Port Identifier = 0x%04" PRIX16 "\r\n", ntohs(bpdu->portId));

      //Dump Message Age
      t = ntohs(bpdu->messageAge) * 1000 / 256;
      TRACE_DEBUG("  Message Age = %" PRIu32 ".%03" PRIu32 "\r\n", t / 1000, t % 1000);

      //Dump Max Age
      t = ntohs(bpdu->maxAge) * 1000 / 256;
      TRACE_DEBUG("  Max Age = %" PRIu32 ".%03" PRIu32 "\r\n", t / 1000, t % 1000);

      //Dump Hello Time
      t = ntohs(bpdu->helloTime) * 1000 / 256;
      TRACE_DEBUG("  Hello Time = %" PRIu32 ".%03" PRIu32 "\r\n", t / 1000, t % 1000);

      //Dump Forward Delay
      t = ntohs(bpdu->forwardDelay) * 1000 / 256;
      TRACE_DEBUG("  Forward Delay = %" PRIu32 ".%03" PRIu32 "\r\n", t / 1000, t % 1000);
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Dump Flags field for debugging purpose
 * @param[in] flags Value of the Flags field
 **/

void stpDumpFlags(uint8_t flags)
{
   //Dump Flags field
   TRACE_DEBUG("  Flags = 0x%02" PRIX8, flags);

   //Check whether any flag is set
   if(flags != 0)
   {
      //Debug message
      TRACE_DEBUG(" (");

      //Decode flags
      while(flags != 0)
      {
         if((flags & STP_BPDU_FLAG_TC_ACK) != 0)
         {
            //The Topology Change Acknowledgment flag is set
            TRACE_DEBUG("TcAck");
            //Clear flag
            flags &= ~STP_BPDU_FLAG_TC_ACK;
         }
         else if((flags & STP_BPDU_FLAG_TC) != 0)
         {
            //The Topology Change flag is set
            TRACE_DEBUG("Tc");
            //Clear flag
            flags &= ~STP_BPDU_FLAG_TC;
         }

         //Any other flag set?
         if(flags != 0)
         {
            TRACE_DEBUG(", ");
         }
      }

      //Debug message
      TRACE_DEBUG(")");
   }

   //Terminate with a line feed
   TRACE_DEBUG("\r\n");
}

#endif

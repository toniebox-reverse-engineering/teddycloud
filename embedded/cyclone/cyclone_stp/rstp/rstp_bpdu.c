/**
 * @file rstp_bpdu.c
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
#define TRACE_LEVEL RSTP_TRACE_LEVEL

//Dependencies
#include "rstp/rstp.h"
#include "rstp/rstp_fsm.h"
#include "rstp/rstp_bpdu.h"
#include "rstp/rstp_conditions.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)

//Bridge group address (refer to IEEE Std 802.1D-2004, section 7.12.3)
const MacAddr RSTP_BRIDGE_GROUP_ADDR = {{{0x01, 0x80, 0xC2, 0x00, 0x00, 0x00}}};

//Protocol versions
const RstpParamName rstpProtocolVersions[] =
{
   {STP_PROTOCOL_VERSION,  "STP"},
   {RSTP_PROTOCOL_VERSION, "RSTP"}
};

//BPDU types
const RstpParamName rstpBpduTypes[] =
{
   {RSTP_BPDU_TYPE_CONFIG, "CONFIG"},
   {RSTP_BPDU_TYPE_TCN,    "TCN"},
   {RSTP_BPDU_TYPE_RST,    "RST"}
};


/**
 * @brief Process incoming LLC frame
 * @param[in] interface Underlying network interface
 * @param[in] ethHeader Pointer to the Ethernet header
 * @param[in] data Pointer to the LLC frame
 * @param[in] length Length of the LLC frame, in bytes
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @param[in] param Pointer to the RSTP bridge context
 **/

void rstpProcessLlcFrame(NetInterface *interface, EthHeader *ethHeader,
   const uint8_t *data, size_t length, NetRxAncillary *ancillary, void *param)
{
   const LlcHeader *llcHeader;
   const RstpBpdu *bpdu;
   RstpBridgeContext *context;
   RstpBridgePort *port;

   //Point to the RSTP bridge context
   context = (RstpBridgeContext *) param;

   //The Bridge Group Address shall be used in the destination address field
   //of all MAC frames conveying BPDUs (refer to IEEE Std 802.1D-2004, section
   //7.12.3)
   if(!macCompAddr(&ethHeader->destAddr, &RSTP_BRIDGE_GROUP_ADDR))
      return;

   //Check the length of the LLC frame
   if(length < sizeof(LlcHeader))
      return;

   //Point to the LLC header
   llcHeader = (LlcHeader *) data;

   //The DSAP and SSAP fields must use the standard LLC address assigned to
   //the Bridge Spanning Tree Protocol (refer to IEEE Std 802.1D-2004, section
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
   bpdu = (RstpBpdu *) (data + sizeof(LlcHeader));

   //Retrieve the length of the BPDU
   length -= sizeof(LlcHeader);

   //Process incoming BPDU
   rstpProcessBpdu(port, bpdu, length);
}


/**
 * @brief Process incoming bridge protocol data unit
 * @param[in] port Pointer to the bridge port context
 * @param[in] bpdu Pointer to the received BPDU
 * @param[in] length Length of the BPDU, in bytes
 * @return Error code
 **/

error_t rstpProcessBpdu(RstpBridgePort *port, const RstpBpdu *bpdu,
   size_t length)
{
   error_t error;
   uint8_t bpduType;
   RstpBridgeContext *context;

   //Debug message
   TRACE_INFO("Port %" PRIu8 ": BPDU received (%" PRIuSIZE " bytes)...\r\n",
      port->portIndex, length);

   //Dump BPDU for debugging purpose
   rstpDumpBpdu(bpdu, length);

   //Point to the RSTP bridge context
   context = port->context;

   //The BPDU must contain at least four octets
   if(length < STP_MIN_BPDU_SIZE)
      return ERROR_INVALID_LENGTH;

   //The Protocol Identifier must have the value specified for BPDUs
   if(ntohs(bpdu->protocolId) != STP_PROTOCOL_ID)
      return ERROR_INVALID_LENGTH;

   //The type of the BPDU is encoded as a single octet
   bpduType = bpdu->bpduType;

   //Check BPDU type
   if(bpduType == RSTP_BPDU_TYPE_CONFIG)
   {
      //Validate the received Configuration BPDU according to 9.3.4 rules
      error = rstpValidateConfigBpdu(port, bpdu, length);
      //Invalid Configuration BPDU?
      if(error)
         return error;

      //All octets that appear in the BPDU beyond the largest numbered octet
      //defined for a given BPDU type shall be ignored
      length = RSTP_CONFIG_BPDU_SIZE;
   }
   else if(bpduType == RSTP_BPDU_TYPE_TCN)
   {
      //All octets that appear in the BPDU beyond the largest numbered octet
      //defined for a given BPDU type shall be ignored
      length = RSTP_TCN_BPDU_SIZE;
   }
   else if(bpduType == RSTP_BPDU_TYPE_RST)
   {
      //RST BPDUs are not recognized by STP bridges (refer IEEE Std 802.1D-2004,
      //section 17.4)
      if(stpVersion(context))
         return ERROR_INVALID_VERSION;

      //A Rapid Spanning Tree BPDU must contain at least 36 octets
      if(length < RSTP_RST_BPDU_SIZE)
         return ERROR_INVALID_LENGTH;

      //All octets that appear in the BPDU beyond the largest numbered octet
      //defined for a given BPDU type shall be ignored
      length = RSTP_RST_BPDU_SIZE;

      //Unknown port role?
      if((bpdu->flags & RSTP_BPDU_FLAG_PORT_ROLE) ==
         RSTP_BPDU_FLAG_PORT_ROLE_UNKNOWN)
      {
         //If the Unknown value of the Port Role parameter is received, the
         //state machine will effectively treat the RST BPDU as if it were a
         //Configuration BPDU (refer to IEEE Std 802.1D-2004, section 9.2.9)
         bpduType = RSTP_BPDU_TYPE_CONFIG;

         //Validate the received Configuration BPDU according to 9.3.4 rules
         error = rstpValidateConfigBpdu(port, bpdu, length);
         //Invalid Configuration BPDU?
         if(error)
            return error;

         //All octets that appear in the BPDU beyond the largest numbered octet
         //defined for a given BPDU type shall be ignored
         length = RSTP_CONFIG_BPDU_SIZE;
      }
   }
   else
   {
      //Invalid BPDU received
      return ERROR_INVALID_TYPE;
   }

   //The received BPDU is valid
   osMemcpy(&context->bpdu, bpdu, length);

   //Fix the BPDU type
   context->bpdu.bpduType = bpduType;

   //All flags that are undefined for a given BPDU type shall be ignored (refer
   //to IEEE Std 802.1D-2004, section 9.3.4)
   if(bpduType == RSTP_BPDU_TYPE_CONFIG)
   {
      //The Topology Change Acknowledgment flag is encoded in bit 8. The
      //Topology Change flag is encoded in bit 1. The remaining flags, bits 2
      //through 7, are unused and take the value 0
      context->bpdu.flags &= RSTP_BPDU_FLAG_TC_ACK | RSTP_BPDU_FLAG_TC;
   }
   else if(bpduType == RSTP_BPDU_TYPE_RST)
   {
      //The Topology Change Acknowledgment flag is encoded in bit 8 as zero
      context->bpdu.flags &= ~RSTP_BPDU_FLAG_TC_ACK;
   }
   else
   {
      //A Topology Change Notification BPDU does not contain any flags
      context->bpdu.flags = 0;
   }

   //The rcvdBPDU variable notifies the Port Receive state machine when a valid
   //Configuration, TCN, or RST BPDU is received on the port
   port->rcvdBpdu = TRUE;

   //Process incoming BPDU
   rstpFsm(context);

   //Clear BPDU
   osMemset(&context->bpdu, 0, sizeof(RstpBpdu));

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Validate Configuration BPDU
 * @param[in] port Pointer to the bridge port context
 * @param[in] bpdu Pointer to the received Configuration BPDU
 * @param[in] length Length of the Configuration BPDU, in bytes
 * @return Error code
 **/

error_t rstpValidateConfigBpdu(RstpBridgePort *port, const RstpBpdu *bpdu,
   size_t length)
{
   RstpBridgeContext *context;

   //Point to the RSTP bridge context
   context = port->context;

   //A Configuration BPDU must contain at least 35 octets
   if(length < RSTP_CONFIG_BPDU_SIZE)
      return ERROR_INVALID_LENGTH;

   //The BPDU's Message Age must be less than its Max Age parameter
   if(ntohs(bpdu->messageAge) >= ntohs(bpdu->maxAge))
      return ERROR_INVALID_PACKET;

   //The Bridge Identifier and Port Identifier parameters from the received BPDU
   //must not match the values that would be transmitted in a BPDU from this port
   if(rstpCompareBridgeAddr(&bpdu->bridgeId.addr, &context->bridgeId.addr) == 0 &&
      rstpComparePortNum(ntohs(bpdu->portId), port->portId) == 0)
   {
      return ERROR_WRONG_IDENTIFIER;
   }

   //The received Configuration BPDU is valid
   return NO_ERROR;
}


/**
 * @brief Send bridge protocol data unit
 * @param[in] port Pointer to the bridge port context
 * @param[in] bpdu Pointer to the BPDU to be transmitted
 * @param[in] length Length of the BPDU, in bytes
 * @return Error code
 **/

error_t rstpSendBpdu(RstpBridgePort *port, const RstpBpdu *bpdu,
   size_t length)
{
   error_t error;
   size_t offset;
   LlcHeader *llcHeader;
   NetBuffer *buffer;
   NetTxAncillary ancillary;
   RstpBridgeContext *context;

   //Debug message
   TRACE_INFO("Port %" PRIu8 ": Sending BPDU (%" PRIuSIZE " bytes)...\r\n",
      port->portIndex, length);

   //Dump BPDU for debugging purpose
   rstpDumpBpdu(bpdu, length);

   //Point to the RSTP bridge context
   context = port->context;

   //Allocate a buffer to hold the 802.2 LLC header
   buffer = ethAllocBuffer(sizeof(LlcHeader), &offset);

   //Successful memory allocation?
   if(buffer != NULL)
   {
      //Point to the LLC header
      llcHeader = netBufferAt(buffer, offset);

      //The DSAP and SSAP fields must use the standard LLC address assigned
      //to the Bridge Spanning Tree Protocol (refer to IEEE Std 802.1D-2004,
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
         error = ethSendFrame(context->interface, &RSTP_BRIDGE_GROUP_ADDR,
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

error_t rstpDumpBpdu(const RstpBpdu *bpdu, size_t length)
{
#if (RSTP_TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   uint32_t t;

   //The BPDU must contain at least four octets
   if(length < STP_MIN_BPDU_SIZE)
      return ERROR_INVALID_LENGTH;

   //Dump Protocol Identifier
   TRACE_DEBUG("  Protocol Identifier = %" PRIu16 "\r\n",
      ntohs(bpdu->protocolId));

   //Dump Protocol Version Identifier
   TRACE_DEBUG("  Protocol Version Identifier = %" PRIu8 " (%s)\r\n",
      bpdu->protocolVersionId, rstpGetParamName(bpdu->protocolVersionId,
      rstpProtocolVersions, arraysize(rstpProtocolVersions)));

   //Dump BPDU Type
   TRACE_DEBUG("  BPDU Type = 0x%02" PRIX8 " (%s)\r\n", bpdu->bpduType,
      rstpGetParamName(bpdu->bpduType, rstpBpduTypes, arraysize(rstpBpduTypes)));

   //Check the length of the BPDU
   if(length >= RSTP_CONFIG_BPDU_SIZE)
   {
      //Dump Flags
      rstpDumpFlags(bpdu->flags);

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

   //Check the length of the BPDU
   if(length >= RSTP_RST_BPDU_SIZE)
   {
      //Dump Version 1 Length
      TRACE_DEBUG("  Version 1 Length = %" PRIu8 "\r\n", bpdu->version1Length);
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Dump Flags field for debugging purpose
 * @param[in] flags Value of the Flags field
 **/

void rstpDumpFlags(uint8_t flags)
{
   uint8_t role;

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
         if((flags & RSTP_BPDU_FLAG_TC_ACK) != 0)
         {
            //The Topology Change Acknowledgment flag is set
            TRACE_DEBUG("TcAck");
            //Clear flag
            flags &= ~RSTP_BPDU_FLAG_TC_ACK;
         }
         else if((flags & RSTP_BPDU_FLAG_AGREEMENT) != 0)
         {
            //The Agreement flag is set
            TRACE_DEBUG("Agreement");
            //Clear flag
            flags &= ~RSTP_BPDU_FLAG_AGREEMENT;
         }
         else if((flags & RSTP_BPDU_FLAG_FORWARDING) != 0)
         {
            //The Forwarding flag is set
            TRACE_DEBUG("Forwarding");
            //Clear flag
            flags &= ~RSTP_BPDU_FLAG_FORWARDING;
         }
         else if((flags & RSTP_BPDU_FLAG_LEARNING) != 0)
         {
            //The Learning flag is set
            TRACE_DEBUG("Learning");
            //Clear flag
            flags &= ~RSTP_BPDU_FLAG_LEARNING;
         }
         else if((flags & RSTP_BPDU_FLAG_PORT_ROLE) != 0)
         {
            //Decode port role
            role = flags & RSTP_BPDU_FLAG_PORT_ROLE;

            //Check port role
            if(role == RSTP_BPDU_FLAG_PORT_ROLE_ALT_BACKUP)
            {
               TRACE_DEBUG("AltBackupRole");
            }
            else if(role == RSTP_BPDU_FLAG_PORT_ROLE_ROOT)
            {
               TRACE_DEBUG("RootRole");
            }
            else if(role == RSTP_BPDU_FLAG_PORT_ROLE_DESIGNATED)
            {
               TRACE_DEBUG("DesignatedRole");
            }

            //Clear flag
            flags &= ~RSTP_BPDU_FLAG_PORT_ROLE;
         }
         else if((flags & RSTP_BPDU_FLAG_PROPOSAL) != 0)
         {
            //The Proposal flag is set
            TRACE_DEBUG("Proposal");
            //Clear flag
            flags &= ~RSTP_BPDU_FLAG_PROPOSAL;
         }
         else if((flags & RSTP_BPDU_FLAG_TC) != 0)
         {
            //The Topology Change flag is set
            TRACE_DEBUG("Tc");
            //Clear flag
            flags &= ~RSTP_BPDU_FLAG_TC;
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

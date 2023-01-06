/**
 * @file lldp_procedures.c
 * @brief LLDP state machine procedures
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
#include <limits.h>
#include "core/net.h"
#include "lldp/lldp.h"
#include "lldp/lldp_procedures.h"
#include "lldp/lldp_misc.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED)


/**
 * @brief Construct an information LLDPDU (10.5.4.2.1)
 * @param[in] port Pointer to the port context
 **/

void lldpMibConstrInfoLldpdu(LldpPortEntry *port)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   uint_t i;
   uint_t j;
   LldpTlv tlv;
   LldpAgentContext *context;
   uint8_t ttl[2];

   //Point to the LLDP agent context
   context = port->context;

   //Extract the selected information from the local system MIB
   context->lldpdu = context->txInfo;

   //The TTL field shall contain an integer value in the range 0 to 65535
   //seconds and shall be set to the computed value of txTTL at the time
   //the LLDPDU is constructed
   port->txTTL = MIN(65535, context->msgTxInterval * context->msgTxHold);

   //Convert the value to network byte order
   STORE16BE(port->txTTL, ttl);

   //Set the Time To Live TLV with the TTL value set equal to txTTL
   lldpSetTlv(&context->lldpdu, LLDP_TLV_TYPE_TIME_TO_LIVE, 0, ttl,
      sizeof(ttl), TRUE);

   //Check whether the System Name TLV is enabled for transmission
   if((port->basicTlvFilter & LLDP_BASIC_TLV_FILTER_SYS_NAME) == 0)
   {
      //Remove the System Name TLV from the LLDPDU
      lldpDeleteTlv(&context->lldpdu, LLDP_TLV_TYPE_SYS_NAME, 0);
   }

   //Check whether the System Description TLV is enabled for transmission
   if((port->basicTlvFilter & LLDP_BASIC_TLV_FILTER_SYS_DESC) == 0)
   {
      //Remove the System Description TLV from the LLDPDU
      lldpDeleteTlv(&context->lldpdu, LLDP_TLV_TYPE_SYS_DESC, 0);
   }

   //Check whether the System Capabilities TLV is enabled for transmission
   if((port->basicTlvFilter & LLDP_BASIC_TLV_FILTER_SYS_CAP) == 0)
   {
      //Remove the System Capabilities TLV from the LLDPDU
      lldpDeleteTlv(&context->lldpdu, LLDP_TLV_TYPE_SYS_CAP, 0);
   }

   //Loop through the list of management addresses
   for(i = 0, j = 0; i < LLDP_MAX_MGMT_ADDRS; i++)
   {
      //Check whether the current management address is configured
      if((context->mgmtAddrMap & (1U << i)) != 0)
      {
         //An individual LLDPDU may contain more than one Management Address
         //TLV (refer to IEEE 802.1AB-2005, section 9.5.9.9)
         if((port->mgmtAddrFilter & (1U << i)) != 0)
         {
            j++;
         }
         else
         {
            //Remove the current management address
            lldpDeleteTlv(&context->lldpdu, LLDP_TLV_TYPE_MGMT_ADDR, j);
         }
      }
   }

   //Extract the first port-specific TLV
   error = lldpGetFirstTlv(&port->txInfo, &tlv);

   //Copy port-specific TLVs
   while(!error)
   {
      //Check TLV type
      if(tlv.type == LLDP_TLV_TYPE_END_OF_LLDPDU)
      {
         //If the End Of LLDPDU TLV is present, any octets that follow it are
         //discarded
         break;
      }
      else if(tlv.type == LLDP_TLV_TYPE_PORT_DESC)
      {
         //Check whether the Port Description TLV is enabled for transmission
         if((port->basicTlvFilter & LLDP_BASIC_TLV_FILTER_PORT_DESC) != 0)
         {
            //Add the Port Description TLV to the LLDPDU
            lldpSetTlv(&context->lldpdu, LLDP_TLV_TYPE_PORT_DESC, 0, tlv.value,
               tlv.length, TRUE);
         }
      }
      else
      {
         //Add the TLV to the LLDPDU
         lldpSetTlv(&context->lldpdu, tlv.type, UINT_MAX, tlv.value,
            tlv.length, FALSE);
      }

      //Extract the next port-specific TLV
      error = lldpGetNextTlv(&port->txInfo, &tlv);
   }
#endif
}


/**
 * @brief Construct a shutdown LLDPDU (10.5.4.2.2)
 * @param[in] port Pointer to the port context
 **/

void lldpMibConstrShutdownLldpdu(LldpPortEntry *port)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const uint8_t *p;
   uint16_t ttl;
   LldpAgentContext *context;

   //Point to the LLDP agent context
   context = port->context;

   //Flush buffer
   context->lldpdu.length = 0;

   //Extract the Chassis ID TLV from the local system MIB
   error = lldpGetTlv(&context->txInfo, LLDP_TLV_TYPE_CHASSIS_ID, 0, &p, &n);

   //Chassis ID TLV found?
   if(!error)
   {
      //The first TLV must be the Chassis ID TLV
      lldpSetTlv(&context->lldpdu, LLDP_TLV_TYPE_CHASSIS_ID, 0, p, n, TRUE);
   }

   //Extract the Port ID TLV from the local system MIB
   error = lldpGetTlv(&port->txInfo, LLDP_TLV_TYPE_PORT_ID, 0, &p, &n);

   //Port ID TLV found?
   if(!error)
   {
      //The second TLV must be the Port ID TLV
      lldpSetTlv(&context->lldpdu, LLDP_TLV_TYPE_PORT_ID, 0, p, n, TRUE);
   }

   //The TTL field must be set to zero
   ttl = HTONS(0);

   //The third TLV must be the Time To Live TLV
   lldpSetTlv(&context->lldpdu, LLDP_TLV_TYPE_TIME_TO_LIVE, 0,
      (uint8_t *) &ttl, sizeof(uint16_t), TRUE);

   //An End Of LLDPDU TLV is necessary to prevent non-zero pad octets from
   //being interpreted by the receiving LLDP agent as another TLV
   lldpSetTlv(&context->lldpdu, LLDP_TLV_TYPE_END_OF_LLDPDU, 0, NULL, 0, TRUE);
#endif
}


/**
 * @brief Send an LLDPDU to the MAC for transmission (10.5.4.2.3)
 * @param[in] port Pointer to the port context
 **/

void lldpTxFrame(LldpPortEntry *port)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   SocketMsg msg;
   LldpAgentContext *context;

   //Point to the LLDP agent context
   context = port->context;

   //Any registered callback?
   if(context->sendCallback != NULL)
   {
      //Invoke user callback function
      context->sendCallback(port, &context->lldpdu);
   }

   //Debug message
   TRACE_DEBUG("Sending LLDPDU (%" PRIuSIZE " bytes)...\r\n",
      context->lldpdu.length);

   //Dump the contents of the LLDPDU for debugging purpose
   lldpDumpDataUnit(&context->lldpdu);

   //Point to the LLDP data unit
   msg = SOCKET_DEFAULT_MSG;
   msg.data = context->lldpdu.data;
   msg.length = context->lldpdu.length;

   //Prepend the source and destinations addresses and the LLDP Ethertype
   //to each LLDPDU
   msg.srcMacAddr = port->macAddr;
   msg.destMacAddr = LLDP_MULTICAST_ADDR;
   msg.ethType = ETH_TYPE_LLDP;

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
   //Specify the destination port
   msg.switchPort = port->portIndex;
#endif

   //Debug message
   TRACE_INFO("Sending LLDP frame on port %u (%" PRIuSIZE " bytes)...\r\n",
      port->portIndex, context->lldpdu.length);

   //Send the LLDP frame to the MAC for transmission
   socketSendMsg(context->socket, &msg, 0);

   //Increment the count of all LLDP frames transmitted through the port
   port->statsFramesOutTotal++;
#endif
}


/**
 * @brief Initialize the LLDP transmit module (10.5.4.2.3)
 * @param[in] port Pointer to the port context
 **/

void lldpTxInitializeLLDP(LldpPortEntry *port)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //The variable somethingChangedLocal shall be set to FALSE
   port->somethingChangedLocal = FALSE;
#endif
}


/**
 * @brief Delete aged entries from the remote systems MIB (10.5.5.2.1)
 * @param[in] port Pointer to the port context
 **/

void lldpMibDeleteObjects(LldpPortEntry *port)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   uint_t i;
   LldpAgentContext *context;
   LldpNeighborEntry *entry;

   //Point to the LLDP agent context
   context = port->context;

   //Loop through the remote systems MIB
   for(i = 0; i < context->numNeighbors; i++)
   {
      //Point to the current entry
      entry = &context->neighbors[i];

      //Check whether the entry is valid
      if(entry->rxInfo.length > 0)
      {
         //Matching port index?
         if(entry->portIndex == port->portIndex)
         {
            //Check whether the TTL has expired
            if(entry->rxInfoTTL == 0)
            {
               //Invalidate the current entry
               lldpDeleteNeighborEntry(entry);

               //Save the time at which an entry was created, modified, or
               //deleted
               context->statsRemTablesLastChangeTime = osGetSystemTime64() / 10;

               //Number of times the complete set of information advertised by
               //a particular MSAP has been deleted from tables
               context->statsRemTablesDeletes++;

               //Number of times the complete set of information advertised by
               //a particular MSAP has been deleted from tables because the
               //information timeliness interval has expired
               if(port->rxInfoAge)
               {
                  context->statsRemTablesAgeouts++;
               }
            }
         }
      }
   }
#endif
}


/**
 * @brief Update MIB objects with TLVs contained in the received LLDPDU (10.5.5.2.2)
 * @param[in] port Pointer to the port context
 **/

void lldpMibUpdateObjects(LldpPortEntry *port)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   LldpAgentContext *context;
   LldpNeighborEntry *entry;

   //Point to the LLDP agent context
   context = port->context;

   //Compare the MSAP identifier in the current LLDPDU with the MSAP
   //identifiers in the LLDP remote systems MIB
   entry = lldpFindNeighborEntry(context, &context->lldpdu);

   //Any matching entry?
   if(entry != NULL)
   {
      //If a match is found, replace all current information associated
      //with the MSAP identifier in the LLDP remote systems MIB with the
      //information in the current LLDPDU
      entry->rxInfo = context->lldpdu;

      //Set the timing counter rxInfoTTL associated with the MSAP identifier
      //to rxTTL
      entry->rxInfoTTL = context->rxTTL;

      //This index value is used to identify the port on which the LLDPDU
      //was received
      entry->portIndex = port->portIndex;

      //Each time the entry is updated, the current value of sysUpTime is
      //recorded in the associated timestamp
      entry->timeMark = osGetSystemTime64() / 10;

      //Save the time at which an entry was created, modified, or deleted
      context->statsRemTablesLastChangeTime = entry->timeMark;
   }
   else
   {
      //If no match is found, create a new MIB structure to receive
      //information associated with the new MSAP identifier, and set these
      //MIB objects to the values indicated in their respective TLVs
      entry = lldpCreateNeighborEntry(context);

      //Sufficient space available in the remote systems MIB?
      if(entry != NULL)
      {
         //An agent is encouraged to assign monotonically increasing index
         //values to new entries, starting with one, after each reboot
         context->index++;

         //The index is used by the agent to identify a particular connection
         //instance
         entry->index = context->index;

         //The timestamp is used to implement time-filtered rows
         entry->timeMark = osGetSystemTime64() / 10;

         //Copy the information contained in the received LLDPDU
         entry->rxInfo = context->lldpdu;

         //Number of seconds remaining until the information is no longer valid
         entry->rxInfoTTL = context->rxTTL;

         //This index value is used to identify the port on which the LLDPDU
         //was received
         entry->portIndex = port->portIndex;

         //Save the time at which an entry was created, modified, or deleted
         context->statsRemTablesLastChangeTime = entry->timeMark;

         //Number of times the complete set of information advertised by a
         //particular MSAP has been inserted into tables
         context->statsRemTablesInserts++;
      }
   }
#endif
}


/**
 * @brief Initialize the LLDP receive module (10.5.5.2.3)
 * @param[in] port Pointer to the port context
 **/

void lldpRxInitializeLLDP(LldpPortEntry *port)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   uint_t i;
   LldpAgentContext *context;
   LldpNeighborEntry *entry;

   //Point to the LLDP agent context
   context = port->context;

   //The variable tooManyNeighbors shall be set to FALSE
   context->tooManyNeighbors = FALSE;

   //All information in the remote systems MIB associated with this port
   //shall be deleted
   for(i = 0; i < context->numNeighbors; i++)
   {
      //Point to the current entry
      entry = &context->neighbors[i];

      //Check whether the entry is valid
      if(entry->rxInfo.length > 0)
      {
         //Matching port number?
         if(entry->portIndex == port->portIndex)
         {
            //Invalidate the current entry
            lldpDeleteNeighborEntry(entry);

            //Save the time at which an entry was created, modified, or deleted
            context->statsRemTablesLastChangeTime = osGetSystemTime64() / 10;

            //Number of times the complete set of information advertised by a
            //particular MSAP has been deleted from tables
            context->statsRemTablesDeletes++;
         }
      }
   }
#endif
}


/**
 * @brief Process incoming LLDP frame (10.5.5.2.4)
 * @param[in] port Pointer to the port context
 **/

void lldpRxProcessFrame(LldpPortEntry *port)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   error_t error;
   LldpAgentContext *context;
   LldpNeighborEntry *entry;

   //Point to the LLDP agent context
   context = port->context;

   //Dump the contents of the LLDPDU for debugging purpose
   lldpDumpDataUnit(&context->lldpdu);

   //The statsFramesInTotal counter for the port shall be incremented
   port->statsFramesInTotal++;

   //Perform LLDPDU validation
   error = lldpCheckDataUnit(port, &context->lldpdu);

   //Valid LLDPDU?
   if(!error)
   {
      //Check the TTL value of the received LLDPDU
      if(context->rxTTL > 0)
      {
         //Checking whether or not the current LLDPDU represents a new MSAP
         //identifier
         entry = lldpFindNeighborEntry(context, &context->lldpdu);

         //Matching MSAP identifier found?
         if(entry != NULL)
         {
            //If rxTTL is non-zero and the LLDPDU's MSAP identifier is
            //associated with an existing LLDP remote systems MIB, compare
            //all current information in the LLDP remote systems MIB with
            //the information in the TLVs just received
            if(entry->portIndex == port->portIndex &&
               entry->rxInfo.length == context->lldpdu.length &&
               osMemcmp(entry->rxInfo.data, context->lldpdu.data, context->lldpdu.length) == 0)
            {
               //If no differences are found, set the control variable
               //rxChanges to FALSE, set the timing counter rxInfoTTL
               //associated with the MSAP identifier to rxTTL, and wait
               //for the next LLDPDU
               context->rxChanges = FALSE;
               entry->rxInfoTTL = context->rxTTL;
            }
            else
            {
               //If any differences are found and there is sufficient space
               //in the LLDP remote systems MIB to store the new LLDPDU, set
               //the control variable rxChanges to TRUE and perform the LLDP
               //remote systems MIB update process
               context->rxChanges = TRUE;
            }
         }
         else
         {
            //If rxTTL is non-zero and the LLDPDU's MSAP identifier is not
            //associated with an existing LLDP remote systems MIB, determine
            //if sufficient space exists in the LLDP remote systems MIB to
            //accommodate the current LLDPDU
            entry = lldpCreateNeighborEntry(context);

            //Sufficient space available in the remote systems MIB?
            if(entry != NULL)
            {
               //Perform the LLDP remote systems MIB update procedure
               context->rxChanges = TRUE;
            }
            else
            {
               //Set the flag variable tooManyNeighbors to TRUE
               context->tooManyNeighbors = TRUE;

               //Update value of the tooManyNeighborsTimer
               if(context->rxTTL > context->tooManyNeighborsTimer)
               {
                  context->tooManyNeighborsTimer = context->rxTTL;
               }

               //The received LLDPDU is discarded
               port->statsFramesDiscardedTotal++;

               //Number of times the complete set of information advertised
               //by a particular MSAP could not be entered into tables
               //because of insufficient resources
               context->statsRemTablesDrops++;
            }
         }
      }
      else
      {
         //If rxTTL is zero, delete all information associated with the
         //MSAP identifier from the LLDP remote systems MIB
         entry = lldpFindNeighborEntry(context, &context->lldpdu);

         //Any matching entry found in the remote systems MIB?
         if(entry != NULL)
         {
            //This index value is used to identify the port on which the
            //LLDPDU was received
            entry->portIndex = port->portIndex;

            //Delete the entry
            entry->rxInfoTTL = 0;
         }
      }
   }
#endif
}

#endif

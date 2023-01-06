/**
 * @file lldp_misc.c
 * @brief Helper functions for LLDP
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
#include "lldp/lldp_misc.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED)

//LLDP multicast address (refer to IEEE Std 802.1AB-2005, section 8.1)
const MacAddr LLDP_MULTICAST_ADDR = {{{0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}}};


/**
 * @brief LLDP agent timer handler
 *
 * This routine must be periodically called by the TCP/IP stack to
 * manage LLDP agent operation
 *
 * @param[in] context Pointer to the LLDP agent context
 **/

void lldpTick(LldpAgentContext *context)
{
   uint_t i;
   bool_t linkState;
   LldpPortEntry *port;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->interface;

   //Loop through the ports
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current port
      port = &context->ports[i];

#if (LLDP_TX_MODE_SUPPORT == ENABLED)
      //Timers used for the transmit state machine are decremented once per second
      lldpDecrementTimer(&port->txShutdownWhile);
      lldpDecrementTimer(&port->txDelayWhile);
      lldpDecrementTimer(&port->txTTR);
#endif

      //Poll link state
      linkState = lldpGetLinkState(context, i + 1);

      //Link state change detected?
      if(!port->portEnabled && linkState && interface->linkState)
      {
         //Debug message
         TRACE_INFO("Port %" PRIu8 ": Link is up...\r\n", port->portIndex);

         //The portEnabled variable is externally controlled. Its value reflects
         //the operational state of the MAC service supporting the port
         port->portEnabled = TRUE;

#if (LLDP_TX_MODE_SUPPORT == ENABLED)
         //Update LLDP state machines
         lldpFsm(context);

         //Force the port to transmit an LLDP frame
         port->somethingChangedLocal = TRUE;
#endif
      }
      else if(port->portEnabled && !linkState)
      {
         //Debug message
         TRACE_INFO("Port %" PRIu8 ": Link is down...\r\n", port->portIndex);

         //The portEnabled variable is externally controlled. Its value reflects
         //the operational state of the MAC service supporting the port
         port->portEnabled = FALSE;
      }
      else
      {
         //No link state change
      }
   }

#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //Timers used for the receive state machine are decremented once per second
   lldpDecrementTimer(&context->tooManyNeighborsTimer);

   //Loop through the remote systems MIB
   for(i = 0; i < context->numNeighbors; i++)
   {
      LldpNeighborEntry *entry;

      //Point to the current entry
      entry = &context->neighbors[i];

      //Check whether the entry is valid
      if(entry->rxInfo.length > 0)
      {
         //Decrement the TTL value
         lldpDecrementTimer(&entry->rxInfoTTL);

         //Check whether the TTL has expired
         if(entry->rxInfoTTL == 0)
         {
            //Valid port index?
            if(entry->portIndex >= 1 && entry->portIndex <= context->numPorts)
            {
               //Point to the port that matches the specified port index
               port = &context->ports[entry->portIndex - 1];

               //The rxInfoAge variable indicates that the rxInfoTTL timing
               //counter has expired
               port->rxInfoAge = TRUE;
            }
         }
      }
   }
#endif

   //Update LLDP state machines
   lldpFsm(context);

   //Any registered callback?
   if(context->tickCallback != NULL)
   {
      //Invoke user callback function
      context->tickCallback(context);
   }
}


/**
 * @brief Process incoming LLDP frame
 * @param[in] context Pointer to the LLDP agent context
 **/

void lldpProcessFrame(LldpAgentContext *context)
{
   error_t error;
   uint_t portIndex;
   SocketMsg msg;
   LldpPortEntry *port;

   //Point to the receive buffer
   msg = SOCKET_DEFAULT_MSG;
   msg.data = context->lldpdu.data;
   msg.size = LLDP_MAX_LLDPDU_SIZE;

   //Receive LLDP frame
   error = socketReceiveMsg(context->socket, &msg, 0);

   //Any frame received?
   if(!error)
   {
      //Save the length of the LLDP frame
      context->lldpdu.length = msg.length;

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
      //Save the port number on which the LLDP frame was received
      portIndex = MAX(msg.switchPort, 1);
#else
      //The station has a single port
      portIndex = 1;
#endif

      //Debug message
      TRACE_INFO("LLDP frame received on port %u (%" PRIuSIZE " bytes)...\r\n",
         portIndex, context->lldpdu.length);

      //Sanity check
      if(portIndex <= context->numPorts)
      {
         //The LLDPDU shall be delivered to the LLDP receive module if, and
         //only if, the destination address value is the assigned LLDP multicast
         //address and the Ethertype value is the LLDP Ethertype
         if(macCompAddr(&msg.destMacAddr, &LLDP_MULTICAST_ADDR) &&
            msg.ethType == ETH_TYPE_LLDP)
         {
            //Point to the port that matches the specified port index
            port = &context->ports[portIndex - 1];

            //Any registered callback?
            if(context->receiveCallback != NULL)
            {
               //Invoke user callback function
               context->receiveCallback(port, &context->lldpdu);
            }

#if (LLDP_RX_MODE_SUPPORT == ENABLED)
            //The global variable rcvFrame shall be set to TRUE
            port->rcvFrame = TRUE;

            //The frame shall be sent to the LLDP receive module for validation
            lldpFsm(context);
#endif
         }
      }
   }
}


/**
 * @brief LLDP data unit validation
 * @param[in] port Pointer to the port context
 * @param[in] lldpdu Pointer to the received LLDP data unit
 * @return Error code
 **/

error_t lldpCheckDataUnit(LldpPortEntry *port, LldpDataUnit *lldpdu)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   error_t error;
   uint_t index;
   LldpTlv tlv;
   LldpAgentContext *context;

   //Initialize index value
   index = 0;

   //Point to the LLDP agent context
   context = port->context;
   //Initialize rxTTL value
   context->rxTTL = 0;

   //Extract the first TLV
   error = lldpGetFirstTlv(lldpdu, &tlv);

   //Parse the LLDP data unit
   while(!error)
   {
      //The LLDPDU shall be checked to verify the presence of the three
      //mandatory TLVs at the beginning of the LLDPDU
      if(index == 0)
      {
         //The first TLV must be the Chassis ID TLV
         if(tlv.type != LLDP_TLV_TYPE_CHASSIS_ID)
         {
            error = ERROR_INVALID_FRAME;
            break;
         }

         //Sanity check
         if(tlv.length < sizeof(LldpChassisIdTlv))
         {
            error = ERROR_INVALID_FRAME;
            break;
         }

         //Out of range information string length?
         if((tlv.length - sizeof(LldpChassisIdTlv)) < LLDP_MIN_CHASSIS_ID_LEN ||
            (tlv.length - sizeof(LldpChassisIdTlv)) > LLDP_MAX_CHASSIS_ID_LEN)
         {
            error = ERROR_INVALID_FRAME;
            break;
         }
      }
      else if(index == 1)
      {
         //The second TLV must be the Port ID TLV
         if(tlv.type != LLDP_TLV_TYPE_PORT_ID)
         {
            error = ERROR_INVALID_FRAME;
            break;
         }

         //Sanity check
         if(tlv.length < sizeof(LldpPortIdTlv))
         {
            error = ERROR_INVALID_FRAME;
            break;
         }

         //Out of range information string length?
         if((tlv.length - sizeof(LldpPortIdTlv)) < LLDP_MIN_PORT_ID_LEN ||
            (tlv.length - sizeof(LldpPortIdTlv)) > LLDP_MAX_PORT_ID_LEN)
         {
            error = ERROR_INVALID_FRAME;
            break;
         }
      }
      else if(index == 2)
      {
         //The third TLV must be the Time To Live TLV
         if(tlv.type != LLDP_TLV_TYPE_TIME_TO_LIVE)
         {
            error = ERROR_INVALID_FRAME;
            break;
         }

         //Check the length of the Time To Live TLV
         if(tlv.length < sizeof(LldpTimeToLiveTlv))
         {
            error = ERROR_INVALID_FRAME;
            break;
         }

         //The first two octets of the TLV information string shall be
         //extracted and rxTTL shall be set to this value
         context->rxTTL = LOAD16BE(tlv.value);

         //If rxTTL equals zero, a shutdown frame has been received. The MSAP
         //identifier and rxTTL shall be passed up to the LLDP MIB manager, and
         //further LLDPDU validation shall be terminated
         if(context->rxTTL == 0)
         {
            index++;
            error = NO_ERROR;
            break;
         }
      }
      else
      {
         //Check optional TLVs
         if(tlv.type == LLDP_TLV_TYPE_END_OF_LLDPDU)
         {
            //If the end of the LLDPDU has been reached, the MSAP identifier,
            //rxTTL, and all validated TLVs shall be passed to the LLDP manager
            //for LLDP remote systems MIB updating
            break;
         }
         else if(tlv.type >= LLDP_TLV_TYPE_CHASSIS_ID &&
            tlv.type <= LLDP_TLV_TYPE_TIME_TO_LIVE)
         {
            //If the LLDPDU contains more than one Chassis ID TLV, Port ID TLV,
            //or Time To Live TLV, then the LLDPDU shall be discarded
            error = ERROR_INVALID_FRAME;
            break;
         }
         else if(tlv.type >= LLDP_TLV_TYPE_PORT_DESC &&
            tlv.type <= LLDP_TLV_TYPE_SYS_CAP)
         {
            //An LLDPDU should not contain more than one Port Description TLV,
            //System Name TLV, System Description TLV and System Capabilities TLV
         }
         else if(tlv.type == LLDP_TLV_TYPE_MGMT_ADDR)
         {
            //An LLDPDU may contain more than one Management Address TLV
         }
         else if(tlv.type == LLDP_TLV_TYPE_ORG_DEFINED)
         {
            //If the TLV's OUI and/or organizationally defined subtype are
            //not recognized, the statsTLVsUnrecognizedTotal counter shall be
            //incremented, and the TLV shall be assumed to be validated
         }
         else
         {
            //The TLV is unrecognized and may be a basic TLV from a later
            //LLDP version. The statsTLVsUnrecognizedTotal counter shall be
            //incremented, and the TLV shall be assumed to be validated
            port->statsTLVsUnrecognizedTotal++;
         }
      }

      //Increment index value
      index++;

      //Extract the next TLV
      error = lldpGetNextTlv(lldpdu, &tlv);
   }

   //Mandatory TLVs are required for all LLDPDUs
   if(index < 3)
   {
      error = ERROR_INVALID_FRAME;
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_END_OF_STREAM)
   {
      //Successful parsing
      error = NO_ERROR;
   }
   else if(error == ERROR_INVALID_SYNTAX)
   {
      //If any TLV extends past the physical end of the frame, the TLV shall be
      //discarded. The statsTLVsDiscardedTotal and statsFramesInErrorsTotal
      //counters shall both be incremented
      port->statsTLVsDiscardedTotal++;
      port->statsFramesInErrorsTotal++;

      //All validated TLVs shall be passed to the LLDP manager for LLDP remote
      //systems MIB updating
      error = NO_ERROR;
   }
   else
   {
      //The statsFramesDiscardedTotal and statsFramesInErrorsTotal counters
      //shall both be incremented
      port->statsFramesDiscardedTotal++;
      port->statsFramesInErrorsTotal++;

      //The variable badFrame shall be set to TRUE
      context->badFrame = TRUE;
   }

   //Return status code
   return error;
#else
   //RX mode is not implemented
   return ERROR_INVALID_FRAME;
#endif
}


/**
 * @brief Create a new entry in the remote systems MIB
 * @param[in] context Pointer to the LLDP agent context
 * @return Pointer to the newly created entry
 **/

LldpNeighborEntry *lldpCreateNeighborEntry(LldpAgentContext *context)
{
   uint_t i;
   LldpNeighborEntry *entry;

   //Initialize pointer
   entry = NULL;

   //Loop through the remote systems MIB
   for(i = 0; i < context->numNeighbors; i++)
   {
      //Check whether the current entry is available for use
      if(context->neighbors[i].rxInfo.length == 0)
      {
         //Point to the current entry
         entry = &context->neighbors[i];
         break;
      }
   }

   //Return a pointer to the newly created entry
   return entry;
}


/**
 * @brief Search the remote systems MIB for a matching MSAP identifier
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] lldpdu Pointer to the received LLDP data unit
 * @return Pointer to the matching entry, if any
 **/

LldpNeighborEntry *lldpFindNeighborEntry(LldpAgentContext *context,
   LldpDataUnit *lldpdu)
{
   error_t error;
   uint_t i;
   LldpMsapId msapId1;
   LldpMsapId msapId2;
   LldpNeighborEntry *entry;

   //Initialize pointer
   entry = NULL;

   //Extract the MSAP identifier from the received LLDPDU
   error = lldpGetMsapId(lldpdu, &msapId1);

   //Check status code
   if(!error)
   {
      //Loop through the remote systems MIB
      for(i = 0; i < context->numNeighbors; i++)
      {
         //Valid entry?
         if(context->neighbors[i].rxInfo.length > 0)
         {
            //Extract the MSAP identifier from the current entry
            error = lldpGetMsapId(&context->neighbors[i].rxInfo, &msapId2);

            //Check status code
            if(!error)
            {
               //Compare MSAP identifiers
               if(lldpCompareMsapId(&msapId1, &msapId2))
               {
                  //A matching entry has been found
                  entry = &context->neighbors[i];
                  break;
               }
            }
         }
      }
   }

   //Return a pointer to the matching entry, if any
   return entry;
}


/**
 * @brief Remove an entry from the remote systems MIB
 * @param[in] entry Pointer to a given entry
 **/

void lldpDeleteNeighborEntry(LldpNeighborEntry *entry)
{
   //Invalidate the current entry
   entry->rxInfoTTL = 0;
   entry->rxInfo.length = 0;
   entry->portIndex = 0;
}


/**
 * @brief Get link state
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @return Error code
 **/

bool_t lldpGetLinkState(LldpAgentContext *context, uint_t portIndex)
{
   bool_t linkState;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->interface;

   //Valid switch driver?
   if(context->numPorts > 1 && interface->switchDriver != NULL &&
      interface->switchDriver->getLinkState != NULL)
   {
      //Get exclusive access
      osAcquireMutex(&netMutex);
      //Retrieve the link state of the specified port
      linkState = interface->switchDriver->getLinkState(interface, portIndex);
      //Release exclusive access
      osReleaseMutex(&netMutex);
   }
   else
   {
      //Retrieve the link state of the network interface
      linkState = interface->linkState;
   }

   //Return link state
   return linkState;
}


/**
 * @brief Add the LLDP multicast address to the static MAC table
 * @param[in] context Pointer to the LLDP agent context
 * @return Error code
 **/

error_t lldpAcceptMulticastAddr(LldpAgentContext *context)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   error_t error;
   SwitchFdbEntry entry;
   NetInterface *interface;

   //Initialize status code
   error = NO_ERROR;

   //Point to the underlying network interface
   interface = context->interface;

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->addStaticFdbEntry != NULL)
   {
      //Format forwarding database entry
      entry.macAddr = LLDP_MULTICAST_ADDR;
      entry.srcPort = 0;
      entry.destPorts = SWITCH_CPU_PORT_MASK;
      entry.override = FALSE;

      //Update the static MAC table of the switch
      error = interface->switchDriver->addStaticFdbEntry(interface, &entry);
   }

   //Check status code
   if(!error)
   {
      //Add the LLDP multicast address to the MAC filter table
      error = ethAcceptMacAddr(interface, &LLDP_MULTICAST_ADDR);
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Return status code
   return error;
#else
   //Not implemented
   return NO_ERROR;
#endif
}


/**
 * @brief Remove the LLDP multicast address from the static MAC table
 * @param[in] context Pointer to the LLDP agent context
 * @return Error code
 **/

error_t lldpDropMulticastAddr(LldpAgentContext *context)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   error_t error;
   SwitchFdbEntry entry;
   NetInterface *interface;

   //Initialize status code
   error = NO_ERROR;

   //Point to the underlying network interface
   interface = context->interface;

   //Get exclusive access
   osAcquireMutex(&netMutex);

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->deleteStaticFdbEntry != NULL)
   {
      //Format forwarding database entry
      entry.macAddr = LLDP_MULTICAST_ADDR;
      entry.srcPort = 0;
      entry.destPorts = 0;
      entry.override = FALSE;

      //Update the static MAC table of the switch
      error = interface->switchDriver->deleteStaticFdbEntry(interface, &entry);
   }

   //Check status code
   if(!error)
   {
      //Remove the LLDP multicast address to the MAC filter table
      ethDropMacAddr(interface, &LLDP_MULTICAST_ADDR);
   }

   //Release exclusive access
   osReleaseMutex(&netMutex);

   //Return status code
   return error;
#else
   //Not implemented
   return NO_ERROR;
#endif
}


/**
 * @brief Port's MAC address generation
 * @param[in] port Pointer to the port context
 **/

void lldpGeneratePortAddr(LldpPortEntry *port)
{
   int_t i;
   uint8_t c;
   MacAddr *macAddr;
   LldpAgentContext *context;

   //Point to the LLDP agent context
   context = port->context;

   //Check the number of ports
   if(context->numPorts > 1)
   {
      //Get the MAC address of the underlying network interface
      macAddr = &port->context->interface->macAddr;

      //Retrieve port index
      c = port->portIndex;

      //Generate a unique MAC address for the port
      for(i = 5; i >= 0; i--)
      {
         //Generate current byte
         port->macAddr.b[i] = macAddr->b[i] + c;

         //Propagate the carry if necessary
         if(port->macAddr.b[i] < macAddr->b[i])
         {
            c = 1;
         }
         else
         {
            c = 0;
         }
      }
   }
   else
   {
      //Use the MAC address of the underlying network interface
      port->macAddr = context->interface->macAddr;
   }
}


/**
 * @brief Extract MSAP identifier
 * @param[in] lldpdu Pointer to the LLDP data unit
 * @param[out] msapId MSAP identifier
 * @return Error code
 **/

error_t lldpGetMsapId(LldpDataUnit *lldpdu, LldpMsapId *msapId)
{
   error_t error;

   //Extract chassis identifier
   error = lldpGetTlv(lldpdu, LLDP_TLV_TYPE_CHASSIS_ID, 0,
      &msapId->chassisId, &msapId->chassisIdLen);

   //Check status code
   if(!error)
   {
      //Extract port identifier
      error = lldpGetTlv(lldpdu, LLDP_TLV_TYPE_PORT_ID, 0,
         &msapId->portId, &msapId->portIdLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Compare MSAP identifiers
 * @param[in] msapId1 Pointer to the first MSAP identifier
 * @param[in] msapId2 Pointer to the second MSAP identifier
 * @return TRUE if the MSAP identifiers match, else FALSE
 **/

bool_t lldpCompareMsapId(const LldpMsapId *msapId1, const LldpMsapId *msapId2)
{
   bool_t res;

   //Check whether the MSAP identifiers match
   if(msapId1->chassisIdLen != msapId2->chassisIdLen)
   {
      res = FALSE;
   }
   else if(osMemcmp(msapId1->chassisId, msapId2->chassisId,
      msapId1->chassisIdLen) != 0)
   {
      res = FALSE;
   }
   else if(msapId1->portIdLen != msapId2->portIdLen)
   {
      res = FALSE;
   }
   else if(osMemcmp(msapId1->portId, msapId2->portId,
      msapId1->portIdLen) != 0)
   {
      res = FALSE;
   }
   else
   {
      res = TRUE;
   }

   //Return comparison result
   return res;
}


/**
 * @brief Notify LLDP that an object in the LLDP local system MIB has changed
 * @param[in] context Pointer to the LLDP agent context
 **/

void lldpSomethingChangedLocal(LldpAgentContext *context)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   uint_t i;

   //Loop through the ports
   for(i = 0; i < context->numPorts; i++)
   {
      context->ports[i].somethingChangedLocal = TRUE;
   }
#endif
}


/**
 * @brief Decrement timer value
 * @param[in,out] x Actual timer value
 **/

void lldpDecrementTimer(uint_t *x)
{
   //If the variable has a non-zero value, this procedure decrements the value
   //of the variable by 1
   if(*x > 0)
   {
      *x -= 1;
   }
}

#endif

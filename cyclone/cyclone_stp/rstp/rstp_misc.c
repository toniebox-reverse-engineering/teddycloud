/**
 * @file rstp_misc.c
 * @brief RSTP helper functions
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
#include "rstp/rstp_conditions.h"
#include "rstp/rstp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (RSTP_SUPPORT == ENABLED)


/**
 * @brief Acquire exclusive access to the RSTP bridge context
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpLock(RstpBridgeContext *context)
{
   //Acquire exclusive access
   osAcquireMutex(&netMutex);
}


/**
 * @brief Release exclusive access to the RSTP bridge context
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpUnlock(RstpBridgeContext *context)
{
   //Release exclusive access
   osReleaseMutex(&netMutex);
}


/**
 * @brief RSTP tick handler
 *
 * This routine must be called at one second intervals
 *
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpTick(RstpBridgeContext *context)
{
   uint_t i;
   bool_t macOperState;
   RstpBridgePort *port;
   NetInterface *interface;

   //Make sure the RSTP bridge context is valid
   if(context != NULL)
   {
      //Point to the underlying network interface
      interface = context->interface;

      //Any topology change detected?
      if(context->topologyChangeCount > 0)
      {
         //Increment the count in seconds of the time since the tcWhile timer
         //for any port was non-zero
         context->timeSinceTopologyChange++;
      }

      //Decrement the rapid ageing timer
      rstpDecrementTimer(&context->rapidAgeingWhile);

      //Check whether the value of the timer is zero
      if(context->rapidAgeingWhile == 0)
      {
         //Determine whether the short (Forward Delay) or long (Ageing Time)
         //timeout value is to be used for dynamic entries in the filtering
         //database
         if(context->ageingTime != context->params.ageingTime)
         {
            //Restore long timeout value
            context->ageingTime = context->params.ageingTime;
            //Set ageing time for dynamic filtering entries
            rstpUpdateAgeingTime(context, context->ageingTime);
         }
      }

      //Loop through the ports of the bridge
      for(i = 0; i < context->numPorts; i++)
      {
         //Point to the current bridge port
         port = &context->ports[i];

         //The tick signal is set by an implementation specific system clock
         //function at one second intervals
         port->tick = TRUE;

         //Valid switch driver?
         if(interface->switchDriver != NULL &&
            interface->switchDriver->getLinkState != NULL &&
            interface->switchDriver->getLinkSpeed != NULL &&
            interface->switchDriver->getDuplexMode != NULL)
         {
            //Poll link state
            macOperState = interface->switchDriver->getLinkState(interface, i + 1);

            //Link state change detected?
            if(macOperState && !port->macOperState && interface->linkState)
            {
               //Debug message
               TRACE_INFO("Port %" PRIu8 ": Link is up...\r\n", port->portIndex);

               //The port is up
               port->macOperState = TRUE;

               //Retrieve link speed and duplex mode
               port->linkSpeed = interface->switchDriver->getLinkSpeed(interface, i + 1);
               port->duplexMode = interface->switchDriver->getDuplexMode(interface, i + 1);

               //Recalculate the contribution of the port to the root path cost
               rstpUpdatePortPathCost(port);

               //The MAC is considered to be connected to a point-to-point LAN
               //if the MAC entity is configured for full duplex operation
               rstpUpdateOperPointToPointMac(port);
            }
            else if(!macOperState && port->macOperState)
            {
               //Debug message
               TRACE_INFO("Port %" PRIu8 ": Link is down...\r\n", port->portIndex);

               //The port is down
               port->macOperState = FALSE;
            }
            else
            {
               //No link state change
            }
         }

         //The portEnabled variable is set if the MAC entity can transmit and
         //receive frames to and from the attached LAN
         port->portEnabled = port->macOperState && port->params.adminPortState;
      }

      //Update RSTP state machine
      rstpFsm(context);
   }
}


/**
 * @brief Retrieve the port that matches the specified port number
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] portId Port identifier
 * @return Pointer to the matching port, if any
 **/

RstpBridgePort *rstpGetBridgePort(RstpBridgeContext *context, uint16_t portId)
{
   uint_t i;
   RstpBridgePort *port;

   //Initialize pointer
   port = NULL;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Check port number
      if(rstpComparePortNum(context->ports[i].portId, portId) == 0)
      {
         port = &context->ports[i];
         break;
      }
   }

   //Return a pointer to the matching port, if any
   return port;
}


/**
 * @brief Compare port numbers
 * @param[in] portId1 First port identifier
 * @param[in] portId2 Second port identifier
 * @return The function returns zero if the port numbers are the same and a
 *   non-zero value if the port numbers are different
 **/

int_t rstpComparePortNum(uint16_t portId1, uint16_t portId2)
{
   int_t res;
   uint16_t portNum1;
   uint16_t portNum2;

   //The less significant twelve bits is the port number
   portNum1 = portId1 & RSTP_PORT_NUM_MASK;
   portNum2 = portId2 & RSTP_PORT_NUM_MASK;

   //Compare port numbers
   if(portNum1 < portNum2)
   {
      res = -1;
   }
   else if(portNum1 > portNum2)
   {
      res = 1;
   }
   else
   {
      res = 0;
   }

   //Return comparison result
   return res;
}


/**
 * @brief Compare bridge addresses
 * @param[in] addr1 First bridge address
 * @param[in] addr2 Second bridge address
 * @return The function returns 1 if addr1 is greater than addr2, 0 if addr1
 *   is the same as addr2 and -1 if addr1 is less than addr2
 **/

int_t rstpCompareBridgeAddr(const MacAddr *addr1, const MacAddr *addr2)
{
   //Compare bridge addresses
   return osMemcmp(addr1, addr2, sizeof(MacAddr));
}


/**
 * @brief Compare bridge identifiers
 * @param[in] id1 First bridge identifier
 * @param[in] id2 Second bridge identifier
 * @return The function returns 1 if id1 is greater than id2, 0 if id1
 *   is the same as id2 and -1 if id1 is less than id2
 **/

int_t rstpCompareBridgeId(const StpBridgeId *id1, const StpBridgeId *id2)
{
   int_t res;

   //Compare bridge identifiers
   if(id1->priority < id2->priority)
   {
      res = -1;
   }
   else if(id1->priority > id2->priority)
   {
      res = 1;
   }
   else
   {
      res = rstpCompareBridgeAddr(&id1->addr, &id2->addr);
   }

   //Return comparison result
   return res;
}


/**
 * @brief Compare priority vectors
 * @param[in] p1 First priority vector
 * @param[in] p2 Second priority vector
 * @return The function returns 1 if p1 priority is better than p2, 0 if p1
 *   priority is the same as p2 and -1 if p1 priority is worse than p2
 **/

int_t rstpComparePriority(const RstpPriority *p1, const RstpPriority *p2)
{
   int_t res;

   //Compare priority vectors according to 17.6 rules
   if(rstpCompareBridgeId(&p1->rootBridgeId, &p2->rootBridgeId) < 0)
   {
      res = 1;
   }
   else if(rstpCompareBridgeId(&p1->rootBridgeId, &p2->rootBridgeId) > 0)
   {
      res = -1;
   }
   else if(p1->rootPathCost < p2->rootPathCost)
   {
      res = 1;
   }
   else if(p1->rootPathCost > p2->rootPathCost)
   {
      res = -1;
   }
   else if(rstpCompareBridgeId(&p1->designatedBridgeId,
      &p2->designatedBridgeId) < 0)
   {
      res = 1;
   }
   else if(rstpCompareBridgeId(&p1->designatedBridgeId,
      &p2->designatedBridgeId) > 0)
   {
      res = -1;
   }
   else if(p1->designatedPortId < p2->designatedPortId)
   {
      res = 1;
   }
   else if(p1->designatedPortId > p2->designatedPortId)
   {
      res = -1;
   }
   else if(p1->bridgePortId < p2->bridgePortId)
   {
      res = 1;
   }
   else if(p1->bridgePortId > p2->bridgePortId)
   {
      res = -1;
   }
   else
   {
      res = 0;
   }

   //Return comparison result
   return res;
}


/**
 * @brief Compare timer parameter values
 * @param[in] t1 First set of timer values
 * @param[in] t2 Second set of timer values
 * @return The function returns 1 if t1 differs from t2 and 0 if t1 is the
 *   same as t2
 **/

int_t rstpCompareTimes(const RstpTimes *t1, const RstpTimes *t2)
{
   int_t res = 0;

   //Check whether t1 timer values are the same as t2 timer values
   if(t1->messageAge == t2->messageAge &&
      t1->maxAge == t2->maxAge &&
      t1->forwardDelay == t2->forwardDelay &&
      t1->helloTime == t2->helloTime)
   {
      res = 0;
   }
   else
   {
      res = 1;
   }

   //Return comparison result
   return res;
}


/**
 * @brief Update the number of topology changes
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpUpdateTopologyChangeCount(RstpBridgeContext *context)
{
   uint_t i;
   bool_t flag;

   //Check whether the tcWhile variable is zero for all the ports
   for(flag = TRUE, i = 0; i < context->numPorts; i++)
   {
      //Check the value of the tcWhile timer for the current port
      if(context->ports[i].tcWhile != 0)
      {
         flag = FALSE;
      }
   }

   //Any topology change detected?
   if(flag)
   {
      //Increment the number of topology changes
      context->topologyChangeCount++;
      //Reset the time since the last topology change
      context->timeSinceTopologyChange = 0;
   }
}


/**
 * @brief Update the value of the portPathCost variable
 * @param[in] port Pointer to the bridge port context
 **/

void rstpUpdatePortPathCost(RstpBridgePort *port)
{
   //An administrative value of zero assigns the automatically calculated
   //default Path Cost value to the port
   if(port->params.adminPathCost == 0)
   {
      //The value of the Port Path Cost variable is chosen according to the
      //speed of the attached LAN
      if(port->linkSpeed <= 100000)
      {
         port->portPathCost = 200000000;
      }
      else
      {
         port->portPathCost = 200000000 / (port->linkSpeed / 100000);
      }
   }
   else
   {
      //Update the value of the Port Path Cost
      port->portPathCost = port->params.adminPathCost;
   }
}


/**
 * @brief Update the value of the operPointToPointMac variable
 * @param[in] port Pointer to the bridge port context
 **/

void rstpUpdateOperPointToPointMac(RstpBridgePort *port)
{
   //Check the administrative point-to-point status of the LAN segment attached
   //to this port
   if(port->params.adminPointToPointMac == RSTP_ADMIN_P2P_MAC_AUTO)
   {
      //The MAC is considered to be connected to a point-to-point LAN if the
      //MAC entity is configured for full duplex operation
      if(port->duplexMode == NIC_FULL_DUPLEX_MODE)
      {
         port->operPointToPointMac = TRUE;
      }
      else
      {
         port->operPointToPointMac = FALSE;
      }
   }
   else if(port->params.adminPointToPointMac == RSTP_ADMIN_P2P_MAC_FORCE_TRUE)
   {
      //The administrator requires the MAC to be treated as if it is connected
      //to a point-to-point LAN, regardless of any indications to the contrary
      //that are generated by the MAC entity
      port->operPointToPointMac = TRUE;
   }
   else
   {
      //The administrator requires the MAC to be treated as connected to a
      //non-point-to-point LAN, regardless of any indications to the contrary
      //that are generated by the MAC entity
      port->operPointToPointMac = FALSE;
   }
}


/**
 * @brief Set port state
 * @param[in] port Pointer to the bridge port context
 * @param[in] state Port state (disabled, learning or forwarding)
 **/

void rstpUpdatePortState(RstpBridgePort *port, SwitchPortState state)
{
   NetInterface *interface;
   RstpBridgeContext *context;

   //Point to the RSTP bridge context
   context = port->context;

   //Check RSTP bridge operation state
   if(context->running)
   {
      //Point to the underlying network interface
      interface = context->interface;

      //Valid switch driver?
      if(interface->switchDriver != NULL &&
         interface->switchDriver->setPortState != NULL)
      {
         //Update the state of the specified port
         interface->switchDriver->setPortState(interface, port->portIndex,
            state);
      }
   }
}


/**
 * @brief Set ageing time for dynamic filtering entries
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] ageingTime Aging time, in seconds
 **/

void rstpUpdateAgeingTime(RstpBridgeContext *context, uint32_t ageingTime)
{
   NetInterface *interface;

   //Debug message
   TRACE_INFO("Set ageing time to %" PRIu32 " seconds...\r\n", ageingTime);

   //Check RSTP bridge operation state
   if(context->running)
   {
      //Point to the underlying network interface
      interface = context->interface;

      //Valid switch driver?
      if(interface->switchDriver != NULL &&
         interface->switchDriver->setAgingTime != NULL)
      {
         //Set ageing time for dynamic filtering entries
         interface->switchDriver->setAgingTime(interface, ageingTime);
      }
   }
}


/**
 * @brief Enable reserved multicast table
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] enable Enable or disable reserved group addresses
 **/

void rstpEnableRsvdMcastTable(RstpBridgeContext *context, bool_t enable)
{
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->interface;

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->enableRsvdMcastTable != NULL)
   {
      //Enable or disable reserved group addresses
      interface->switchDriver->enableRsvdMcastTable(interface, enable);
   }
}


/**
 * @brief Add a new entry to the static MAC table
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] macAddr MAC address to be added
 * @param[in] override This flag specifies whether packets received with a
 *   destination address that matches the MAC address will be forwarded
 *   regardless of the port state
 * @return Error code
 **/

error_t rstpAddStaticFdbEntry(RstpBridgeContext *context, const MacAddr *macAddr,
   bool_t override)
{
   error_t error;
   SwitchFdbEntry entry;
   NetInterface *interface;

   //Initialize status code
   error = NO_ERROR;

   //Point to the underlying network interface
   interface = context->interface;

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->addStaticFdbEntry != NULL)
   {
      //Format forwarding database entry
      entry.macAddr = *macAddr;
      entry.srcPort = 0;
      entry.destPorts = SWITCH_CPU_PORT_MASK;
      entry.override = override;

      //Update the static MAC table of the switch
      error = interface->switchDriver->addStaticFdbEntry(interface, &entry);
   }

   //Return status code
   return error;
}


/**
 * @brief Remove an entry from the static MAC table
 * @param[in] context Pointer to the RSTP bridge context
 * @param[in] macAddr MAC address to be removed from the table
 * @return Error code
 **/

error_t rstpDeleteStaticFdbEntry(RstpBridgeContext *context,
   const MacAddr *macAddr)
{
   error_t error;
   SwitchFdbEntry entry;
   NetInterface *interface;

   //Initialize status code
   error = NO_ERROR;

   //Point to the underlying network interface
   interface = context->interface;

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->deleteStaticFdbEntry != NULL)
   {
      //Format forwarding database entry
      entry.macAddr = *macAddr;
      entry.srcPort = 0;
      entry.destPorts = 0;
      entry.override = FALSE;

      //Update the static MAC table of the switch
      error = interface->switchDriver->deleteStaticFdbEntry(interface, &entry);
   }

   //Return status code
   return error;
}


/**
 * @brief Remove filtering database entries (immediately or by rapid ageing)
 * @param[in] port Pointer to the bridge port context
 **/

void rstpRemoveFdbEntries(RstpBridgePort *port)
{
   uint_t value;
   RstpBridgeContext *context;

   //Point to the RSTP bridge context
   context = port->context;

   //Check whether the bridge is operating in STP compatibility mode
   if(stpVersion(context))
   {
      //Save the current value of the ageingTime parameter
      value = context->ageingTime;

      //The value of the ageingTime parameter is changed to FwdDelay for a
      //period of FwdDelay after fdbFlush is set by the topology change state
      //machine if stpVersion is TRUE
      context->ageingTime = rstpFwdDelay(port);
      context->rapidAgeingWhile = rstpFwdDelay(port);

      //Instruct the filtering database to remove all entries for this port
      //by rapid ageing
      if(context->ageingTime != value)
      {
         rstpUpdateAgeingTime(context, context->ageingTime);
      }

      //The fdbFlush flag is reset immediately
      port->fdbFlush = FALSE;
   }
   else
   {
      //Instruct the filtering database to remove all entries for this port
      //immediately if rstpVersion is TRUE
      rstpFlushFdbTable(port);

      //The fdbFlush flag is reset by the filtering database once the entries
      //are removed
      port->fdbFlush = FALSE;
   }

   //The RSTP state machine is busy
   context->busy = TRUE;
}


/**
 * @brief Remove all the filtering database entries for a given port
 * @param[in] port Pointer to the bridge port context
 **/

void rstpFlushFdbTable(RstpBridgePort *port)
{
   NetInterface *interface;
   RstpBridgeContext *context;

   //Point to the RSTP bridge context
   context = port->context;

   //Point to the underlying network interface
   interface = context->interface;

   //Debug message
   TRACE_INFO("Port %" PRIu8 ": Flush filtering database...\r\n",
      port->portIndex);

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->flushDynamicFdbTable != NULL)
   {
      //Flush the filtering database
      interface->switchDriver->flushDynamicFdbTable(interface,
         port->portIndex);
   }
}


/**
 * @brief Configure the permanent database
 * @param[in] context Pointer to the RSTP bridge context
 * @return Error code
 **/

error_t rstpConfigurePermanentDatabase(RstpBridgeContext *context)
{
   uint_t i;
   error_t error;

   //The Bridge Group Address shall be configured in the permanent database in
   //order to confine BPDUs to the individual LAN on which they are transmitted
   //(refer IEEE Std 802.1D-2004, section 7.12.3)
   error = rstpAddStaticFdbEntry(context, &RSTP_BRIDGE_GROUP_ADDR, TRUE);

   //Check status code
   if(!error)
   {
      //Add the bridge's address to the static MAC table of the switch
      error = rstpAddStaticFdbEntry(context, &context->bridgeId.addr, FALSE);
   }

   //Frames addressed to a bridge port as an end station shall be submitted to
   //LLC (refer IEEE Std 802.1D-2004, section 7.5)
   for(i = 0; i < context->numPorts && !error; i++)
   {
      //Add the port's address to the static MAC table of the switch
      error = rstpAddStaticFdbEntry(context, &context->ports[i].macAddr, FALSE);
   }

   //Check status code
   if(!error)
   {
      //Frames containing any of the reserved addresses in their destination
      //address field shall not be relayed by the bridge. They shall be
      //configured in the permanent database (refer IEEE Std 802.1D-2004,
      //section 7.12.6)
      rstpEnableRsvdMcastTable(context, TRUE);
   }

   //Return status code
   return error;
}


/**
 * @brief Unconfigure the permanent database
 * @param[in] context Pointer to the RSTP bridge context
 **/

void rstpUnconfigurePermanentDatabase(RstpBridgeContext *context)
{
   uint_t i;

   //Remove the Bridge Group Address from the static MAC table of the switch
   rstpDeleteStaticFdbEntry(context, &RSTP_BRIDGE_GROUP_ADDR);

   //Remove the bridge's address from the static MAC table of the switch
   rstpDeleteStaticFdbEntry(context, &context->bridgeId.addr);

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Remove the port's address from the static MAC table of the switch
      rstpDeleteStaticFdbEntry(context, &context->ports[i].macAddr);
   }

   //Remove reserved group addresses from the permanent database
   rstpEnableRsvdMcastTable(context, FALSE);
}


/**
 * @brief Port's MAC address generation
 * @param[in] port Pointer to the bridge port context
 **/

void rstpGeneratePortAddr(RstpBridgePort *port)
{
   int_t i;
   uint8_t c;
   MacAddr *bridgeAddr;

   //Get bridge's MAC address
   bridgeAddr = &port->context->bridgeId.addr;

   //Retrieve port index
   c = port->portIndex;

   //Generate a unique MAC address for the port
   for(i = 5; i >= 0; i--)
   {
      //Generate current byte
      port->macAddr.b[i] = bridgeAddr->b[i] + c;

      //Propagate the carry if necessary
      if(port->macAddr.b[i] < bridgeAddr->b[i])
      {
         c = 1;
      }
      else
      {
         c = 0;
      }
   }
}


/**
 * @brief Check bridge parameters
 * @param[in] maxAge Value of the Bridge Max Age parameter
 * @param[in] helloTime Value of the Bridge Hello Time parameter
 * @param[in] forwardDelay Value of the Bridge Forward Delay parameter
 * @return TRUE if the set of parameters is valid, else FALSE
 **/

bool_t rstpCheckBridgeParams(uint_t maxAge, uint_t helloTime,
   uint_t forwardDelay)
{
   bool_t valid;

   //To support interoperability with legacy bridges, a bridge shall enforce the
   //following relationships (refer to IEEE Std 802.1D-2004, section 17.14)
   if(maxAge >= (2 * (helloTime + 1)) && maxAge <= (2 * (forwardDelay - 1)))
   {
      valid = TRUE;
   }
   else
   {
      valid = FALSE;
   }

   //Return TRUE if the set of parameters is valid, else FALSE
   return valid;
}


/**
 * @brief Convert a parameter to string representation
 * @param[in] value Parameter value
 * @param[in] paramList List of acceptable parameters
 * @param[in] paramListLen Number of entries in the list
 * @return NULL-terminated string describing the parameter
 **/

const char_t *rstpGetParamName(uint_t value, const RstpParamName *paramList,
   size_t paramListLen)
{
   uint_t i;

   //Default name for unknown values
   static const char_t defaultName[] = "Unknown";

   //Loop through the list of acceptable parameters
   for(i = 0; i < paramListLen; i++)
   {
      if(paramList[i].value == value)
      {
         return paramList[i].name;
      }
   }

   //Unknown value
   return defaultName;
}


/**
 * @brief Decrement timer value
 * @param[in,out] x Actual timer value
 **/

void rstpDecrementTimer(uint_t *x)
{
   //Non-zero timer value?
   if(*x > 0)
   {
      //Decrement timer value
      *x -= 1;
   }
}

#endif

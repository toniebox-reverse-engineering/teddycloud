/**
 * @file stp_misc.c
 * @brief STP helper functions
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
#include "stp/stp_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (STP_SUPPORT == ENABLED)

//STP port states
const StpParamName stpPortStates[] =
{
   {STP_PORT_STATE_DISABLED,   "Disabled"},
   {STP_PORT_STATE_LISTENING,  "Listening"},
   {STP_PORT_STATE_LEARNING,   "Learning"},
   {STP_PORT_STATE_FORWARDING, "Forwarding"},
   {STP_PORT_STATE_BLOCKING,   "Blocking"}
};


/**
 * @brief Acquire exclusive access to the STP bridge context
 * @param[in] context Pointer to the STP bridge context
 **/

void stpLock(StpBridgeContext *context)
{
   //Acquire exclusive access
   osAcquireMutex(&netMutex);
}


/**
 * @brief Release exclusive access to the STP bridge context
 * @param[in] context Pointer to the STP bridge context
 **/

void stpUnlock(StpBridgeContext *context)
{
   //Release exclusive access
   osReleaseMutex(&netMutex);
}


/**
 * @brief STP tick handler
 *
 * This routine must be called at one second intervals
 *
 * @param[in] context Pointer to the STP bridge context
 **/

void stpTick(StpBridgeContext *context)
{
   uint_t i;
   bool_t macOperState;
   StpBridgePort *port;
   NetInterface *interface;

   //Make sure the STP bridge context is valid
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

      //Loop through the ports of the bridge
      for(i = 0; i < context->numPorts; i++)
      {
         //Point to the current bridge port
         port = &context->ports[i];

         //Valid switch driver?
         if(interface->switchDriver != NULL &&
            interface->switchDriver->getLinkState != NULL)
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
      }

      //Increment the Hello Timer and check for expiration
      if(stpIncrementTimer(&context->helloTimer, context->helloTime))
      {
         stpHelloTimerExpiry(context);
      }

      //Increment the Topology Change Notification Timer and check for
      //expiration
      if(stpIncrementTimer(&context->tcnTimer, context->bridgeHelloTime))
      {
         stpTcnTimerExpiry(context);
      }

      //Increment the Topology Change Timer and check for expiration
      if(stpIncrementTimer(&context->topologyChangeTimer, context->topologyChangeTime))
      {
         stpTopologyChangeTimerExpiry(context);
      }

      //Loop through the ports of the bridge
      for(i = 0; i < context->numPorts; i++)
      {
         //Point to the current bridge port
         port = &context->ports[i];

         //Increment the Message Age Timer and check for expiration
         if(stpIncrementTimer(&port->messageAgeTimer, context->maxAge))
         {
            stpMessageAgeTimerExpiry(port);
         }
      }

      //Loop through the ports of the bridge
      for(i = 0; i < context->numPorts; i++)
      {
         //Point to the current bridge port
         port = &context->ports[i];

         //Increment the Forward Delay Timer and check for expiration
         if(stpIncrementTimer(&port->forwardDelayTimer, context->forwardDelay))
         {
            stpForwardDelayTimerExpiry(port);
         }

         //Increment the Hold Timer and check for expiration
         if(stpIncrementTimer(&port->holdTimer, context->holdTime))
         {
            stpHoldTimerExpiry(port);
         }
      }
   }

   //Increment the rapid ageing timer and check for expiration
   if(stpIncrementTimer(&context->rapidAgeingTimer, context->forwardDelay))
   {
      //Use long ageing time for dynamic filtering entries
      stpUpdateAgeingTime(context, context->ageingTime);
   }
}


/**
 * @brief Retrieve the port that matches the specified port number
 * @param[in] context Pointer to the STP bridge context
 * @param[in] portId Port identifier
 * @return Pointer to the matching port, if any
 **/

StpBridgePort *stpGetBridgePort(StpBridgeContext *context, uint16_t portId)
{
   uint_t i;
   StpBridgePort *port;

   //Initialize pointer
   port = NULL;

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Check port number
      if(stpComparePortNum(context->ports[i].portId, portId) == 0)
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

int_t stpComparePortNum(uint16_t portId1, uint16_t portId2)
{
   int_t res;
   uint16_t portNum1;
   uint16_t portNum2;

   //The less significant twelve bits is the port number
   portNum1 = portId1 & STP_PORT_NUM_MASK;
   portNum2 = portId2 & STP_PORT_NUM_MASK;

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

int_t stpCompareBridgeAddr(const MacAddr *addr1, const MacAddr *addr2)
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

int_t stpCompareBridgeId(const StpBridgeId *id1, const StpBridgeId *id2)
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
      res = stpCompareBridgeAddr(&id1->addr, &id2->addr);
   }

   //Return comparison result
   return res;
}


/**
 * @brief Set the Topology Change flag
 * @param[in] context Pointer to the STP bridge context
 * @param[in] value Value of the Topology Change flag
 **/

void stpUpdateTopologyChange(StpBridgeContext *context, bool_t value)
{
   //The Topology Change Count parameters counts the number of times the
   //Topology Change flag parameter for the bridge has transitioned from FALSE
   //to TRUE since the bridge was powered on or initialized (refer to IEEE Std
   //802.1D-1998, section 14.8.1.1.3)
   if(!context->topologyChange && value)
   {
      //Increment the number of topology changes
      context->topologyChangeCount++;
      //Reset the time since the last topology change
      context->timeSinceTopologyChange = 0;

      //After any topology change, the bridge uses a short value to age out
      //dynamic entries in the filtering database for a period (refer to IEEE
      //Std 802.1D-1998, section 8.3.5)
      stpUpdateAgeingTime(context, context->forwardDelay);

      //Start the rapid ageing timer
      stpStartTimer(&context->rapidAgeingTimer, 0);
   }

   //Update the value of the Topology Change flag
   context->topologyChange = value;
}


/**
 * @brief Set port state
 * @param[in] port Pointer to the bridge port context
 * @param[in] state Port state (disabled, learning or forwarding)
 **/

void stpUpdatePortState(StpBridgePort *port, StpPortState state)
{
   NetInterface *interface;
   StpBridgeContext *context;

   //Point to the STP bridge context
   context = port->context;

   //Debug message
   TRACE_INFO("Port %u: Set port state to %s\r\n", port->portIndex,
      stpGetParamName(state, stpPortStates, arraysize(stpPortStates)));

   //Learning to Forwarding state transition?
   if(port->state == STP_PORT_STATE_LEARNING &&
      state == STP_PORT_STATE_FORWARDING)
   {
      //Increment the number of times the port has transitioned from the
      //Learning state to the Forwarding state
      port->forwardTransitions++;
   }

   //Save the new state of the port
   port->state = state;

   //Check STP bridge operation state
   if(context->running)
   {
      //Point to the underlying network interface
      interface = context->interface;

      //Valid switch driver?
      if(interface->switchDriver != NULL &&
         interface->switchDriver->setPortState != NULL)
      {
         SwitchPortState portState;

         //Translate port state
         if(state == STP_PORT_STATE_BLOCKING ||
            state == STP_PORT_STATE_LISTENING)
         {
            portState = SWITCH_PORT_STATE_BLOCKING;
         }
         else if(state == STP_PORT_STATE_LEARNING)
         {
            portState = SWITCH_PORT_STATE_LEARNING;
         }
         else if(state == STP_PORT_STATE_FORWARDING)
         {
            portState = SWITCH_PORT_STATE_FORWARDING;
         }
         else
         {
            portState = SWITCH_PORT_STATE_DISABLED;
         }

         //Update the state of the specified port
         interface->switchDriver->setPortState(interface, port->portIndex,
            portState);
      }
   }
}


/**
 * @brief Set ageing time for dynamic filtering entries
 * @param[in] context Pointer to the STP bridge context
 * @param[in] ageingTime Aging time, in seconds
 **/

void stpUpdateAgeingTime(StpBridgeContext *context, uint32_t ageingTime)
{
   NetInterface *interface;

   //Debug message
   TRACE_INFO("Set ageing time to %" PRIu32 " seconds...\r\n", ageingTime);

   //Check STP bridge operation state
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
 * @param[in] context Pointer to the STP bridge context
 * @param[in] enable Enable or disable reserved group addresses
 **/

void stpEnableRsvdMcastTable(StpBridgeContext *context, bool_t enable)
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
 * @param[in] context Pointer to the STP bridge context
 * @param[in] macAddr MAC address to be added
 * @param[in] override This flag specifies whether packets received with a
 *   destination address that matches the MAC address will be forwarded
 *   regardless of the port state
 * @return Error code
 **/

error_t stpAddStaticFdbEntry(StpBridgeContext *context, const MacAddr *macAddr,
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
 * @param[in] context Pointer to the STP bridge context
 * @param[in] macAddr MAC address to be removed from the table
 * @return Error code
 **/

error_t stpDeleteStaticFdbEntry(StpBridgeContext *context,
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
 * @brief Configure the permanent database
 * @param[in] context Pointer to the STP bridge context
 * @return Error code
 **/

error_t stpConfigurePermanentDatabase(StpBridgeContext *context)
{
   uint_t i;
   error_t error;

   //The Bridge Group Address shall be configured in the permanent database in
   //order to confine BPDUs to the individual LAN on which they are transmitted
   //(refer IEEE Std 802.1D-1998, section 7.12.3)
   error = stpAddStaticFdbEntry(context, &STP_BRIDGE_GROUP_ADDR, TRUE);

   //Check status code
   if(!error)
   {
      //Add the bridge's address to the static MAC table of the switch
      error = stpAddStaticFdbEntry(context, &context->bridgeId.addr, FALSE);
   }

   //Frames addressed to a bridge port as an end station shall be submitted to
   //LLC (refer IEEE Std 802.1D-1998, section 7.5)
   for(i = 0; i < context->numPorts && !error; i++)
   {
      //Add the port's address to the static MAC table of the switch
      error = stpAddStaticFdbEntry(context, &context->ports[i].macAddr, FALSE);
   }

   //Check status code
   if(!error)
   {
      //Frames containing any of the reserved addresses in their destination
      //address field shall not be relayed by the bridge. They shall be
      //configured in the permanent database (refer IEEE Std 802.1D-1998,
      //section 7.12.6)
      stpEnableRsvdMcastTable(context, TRUE);
   }

   //Return status code
   return error;
}


/**
 * @brief Unconfigure the permanent database
 * @param[in] context Pointer to the STP bridge context
 **/

void stpUnconfigurePermanentDatabase(StpBridgeContext *context)
{
   uint_t i;

   //Remove the Bridge Group Address from the static MAC table of the switch
   stpDeleteStaticFdbEntry(context, &STP_BRIDGE_GROUP_ADDR);

   //Remove the bridge's address from the static MAC table of the switch
   stpDeleteStaticFdbEntry(context, &context->bridgeId.addr);

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Remove the port's address from the static MAC table of the switch
      stpDeleteStaticFdbEntry(context, &context->ports[i].macAddr);
   }

   //Remove reserved group addresses from the permanent database
   stpEnableRsvdMcastTable(context, FALSE);
}


/**
 * @brief Port's MAC address generation
 * @param[in] port Pointer to the bridge port context
 **/

void stpGeneratePortAddr(StpBridgePort *port)
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

bool_t stpCheckBridgeParams(uint_t maxAge, uint_t helloTime,
   uint_t forwardDelay)
{
   bool_t valid;

   //A bridge shall enforce the following relationships (refer to IEEE Std
   //802.1D-1998, section 8.10.2)
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

const char_t *stpGetParamName(uint_t value, const StpParamName *paramList,
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
 * @brief Start timer
 * @param[in] timer Pointer the timer to start (or restart)
 * @param[in] value Initial value of the timer
 **/

void stpStartTimer(StpTimer *timer, uint_t value)
{
   //Set the initial value of the timer
   timer->value = value;
   //Start the timer
   timer->active = TRUE;
}


/**
 * @brief Stop timer
 * @param[in] timer Pointer the timer to stop
 **/

void stpStopTimer(StpTimer *timer)
{
   //Stop the timer
   timer->active = FALSE;
}


/**
 * @brief Increment the timer and check for expiration
 * @param[in] timer Pointer the timer to increment
 * @param[in] timeout Timeout value
 * @return TRUE if the timer has expired, else FALSE
 **/

bool_t stpIncrementTimer(StpTimer *timer, uint_t timeout)
{
   bool_t flag;

   //Initialize flag
   flag = FALSE;

   //Check whether the timer is active
   if(timer->active)
   {
      //Increment the timer and check for expiration
      if(++timer->value >= timeout)
      {
         //The timer has expired
         flag = TRUE;
         //Stop the timer
         timer->active = FALSE;
      }
   }

   //Return TRUE if the timer has expired
   return flag;
}

#endif

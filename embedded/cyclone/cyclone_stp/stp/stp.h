/**
 * @file stp.h
 * @brief STP (Spanning Tree Protocol)
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

#ifndef _STP_H
#define _STP_H

//Forward declaration of StpBridgeContext structure
struct _StpBridgeContext;
#define StpBridgeContext struct _StpBridgeContext

//Forward declaration of StpBridgePort structure
struct _StpBridgePort;
#define StpBridgePort struct _StpBridgePort

//Dependencies
#include "stp/stp_common.h"
#include "stp/stp_bpdu.h"

//STP bridge support
#ifndef STP_SUPPORT
   #define STP_SUPPORT DISABLED
#elif (STP_SUPPORT != ENABLED && STP_SUPPORT != DISABLED)
   #error STP_SUPPORT parameter is not valid
#endif

//STP tick interval (in milliseconds)
#ifndef STP_TICK_INTERVAL
   #define STP_TICK_INTERVAL 1000
#elif (STP_TICK_INTERVAL < 10)
   #error STP_TICK_INTERVAL parameter is not valid
#endif

//Default Bridge Priority Value
#ifndef STP_DEFAULT_BRIDGE_PRIORITY
   #define STP_DEFAULT_BRIDGE_PRIORITY 32768
#elif (STP_DEFAULT_BRIDGE_PRIORITY < 0 || STP_DEFAULT_BRIDGE_PRIORITY > 61440)
   #error STP_DEFAULT_BRIDGE_PRIORITY parameter is not valid
#endif

//Default Port Priority Value
#ifndef STP_DEFAULT_PORT_PRIORITY
   #define STP_DEFAULT_PORT_PRIORITY 128
#elif (STP_DEFAULT_PORT_PRIORITY < 0 || STP_DEFAULT_PORT_PRIORITY > 240)
   #error STP_DEFAULT_PORT_PRIORITY parameter is not valid
#endif

//Message Age increment
#ifndef STP_MESSAGE_AGE_INCREMENT
   #define STP_MESSAGE_AGE_INCREMENT 1
#elif (STP_MESSAGE_AGE_INCREMENT < 1 || STP_MESSAGE_AGE_INCREMENT > 4)
   #error STP_MESSAGE_AGE_INCREMENT parameter is not valid
#endif

//Minimum Bridge Max Age value
#ifndef STP_MIN_BRIDGE_MAX_AGE
   #define STP_MIN_BRIDGE_MAX_AGE 6
#elif (STP_MIN_BRIDGE_MAX_AGE < 0)
   #error STP_MIN_BRIDGE_MAX_AGE parameter is not valid
#endif

//Default Bridge Max Age value
#ifndef STP_DEFAULT_BRIDGE_MAX_AGE
   #define STP_DEFAULT_BRIDGE_MAX_AGE 20
#elif (STP_DEFAULT_BRIDGE_MAX_AGE < STP_MIN_BRIDGE_MAX_AGE)
   #error STP_DEFAULT_BRIDGE_MAX_AGE parameter is not valid
#endif

//Maximum Bridge Max Age value
#ifndef STP_MAX_BRIDGE_MAX_AGE
   #define STP_MAX_BRIDGE_MAX_AGE 40
#elif (STP_MAX_BRIDGE_MAX_AGE < STP_DEFAULT_BRIDGE_MAX_AGE)
   #error STP_MAX_BRIDGE_MAX_AGE parameter is not valid
#endif

//Minimum Bridge Hello Time value
#ifndef STP_MIN_BRIDGE_HELLO_TIME
   #define STP_MIN_BRIDGE_HELLO_TIME 1
#elif (STP_MIN_BRIDGE_HELLO_TIME < 0)
   #error STP_MIN_BRIDGE_HELLO_TIME parameter is not valid
#endif

//Default Bridge Hello Time value
#ifndef STP_DEFAULT_BRIDGE_HELLO_TIME
   #define STP_DEFAULT_BRIDGE_HELLO_TIME 2
#elif (STP_DEFAULT_BRIDGE_HELLO_TIME < STP_MIN_BRIDGE_HELLO_TIME)
   #error STP_DEFAULT_BRIDGE_HELLO_TIME parameter is not valid
#endif

//Maximum Bridge Hello Time value
#ifndef STP_MAX_BRIDGE_HELLO_TIME
   #define STP_MAX_BRIDGE_HELLO_TIME 10
#elif (STP_MAX_BRIDGE_HELLO_TIME < STP_DEFAULT_BRIDGE_HELLO_TIME)
   #error STP_MAX_BRIDGE_HELLO_TIME parameter is not valid
#endif

//Minimum Bridge Forward Delay value
#ifndef STP_MIN_BRIDGE_FORWARD_DELAY
   #define STP_MIN_BRIDGE_FORWARD_DELAY 4
#elif (STP_MIN_BRIDGE_FORWARD_DELAY < 0)
   #error STP_MIN_BRIDGE_FORWARD_DELAY parameter is not valid
#endif

//Default Bridge Forward Delay value
#ifndef STP_DEFAULT_BRIDGE_FORWARD_DELAY
   #define STP_DEFAULT_BRIDGE_FORWARD_DELAY 15
#elif (STP_DEFAULT_BRIDGE_FORWARD_DELAY < STP_MIN_BRIDGE_FORWARD_DELAY)
   #error STP_DEFAULT_BRIDGE_FORWARD_DELAY parameter is not valid
#endif

//Maximum Bridge Forward Delay value
#ifndef STP_MAX_BRIDGE_FORWARD_DELAY
   #define STP_MAX_BRIDGE_FORWARD_DELAY 30
#elif (STP_MAX_BRIDGE_FORWARD_DELAY < STP_DEFAULT_BRIDGE_FORWARD_DELAY)
   #error STP_MAX_BRIDGE_FORWARD_DELAY parameter is not valid
#endif

//Default Hold Time value
#ifndef STP_DEFAULT_HOLD_TIME
   #define STP_DEFAULT_HOLD_TIME 1
#elif STP_DEFAULT_HOLD_TIME < 0
   #error STP_DEFAULT_HOLD_TIME parameter is not valid
#endif

//Minimum Ageing Time value
#ifndef STP_MIN_AGEING_TIME
   #define STP_MIN_AGEING_TIME 10
#elif (STP_MIN_AGEING_TIME < 0)
   #error STP_MIN_AGEING_TIME parameter is not valid
#endif

//Default Ageing Time value
#ifndef STP_DEFAULT_AGEING_TIME
   #define STP_DEFAULT_AGEING_TIME 300
#elif (STP_DEFAULT_AGEING_TIME < STP_MIN_AGEING_TIME)
   #error STP_DEFAULT_AGEING_TIME parameter is not valid
#endif

//Maximum Ageing Time value
#ifndef STP_MAX_AGEING_TIME
   #define STP_MAX_AGEING_TIME 1000000
#elif (STP_MAX_AGEING_TIME < STP_DEFAULT_AGEING_TIME)
   #error STP_MAX_AGEING_TIME parameter is not valid
#endif

//Minimum Port Path Cost value
#ifndef STP_MIN_PORT_PATH_COST
   #define STP_MIN_PORT_PATH_COST 1
#elif (STP_MIN_PORT_PATH_COST < 0)
   #error STP_MIN_PORT_PATH_COST parameter is not valid
#endif

//Default Port Path Cost value
#ifndef STP_DEFAULT_PORT_PATH_COST
   #define STP_DEFAULT_PORT_PATH_COST 200000
#elif (STP_DEFAULT_PORT_PATH_COST < STP_MIN_PORT_PATH_COST)
   #error STP_DEFAULT_PORT_PATH_COST parameter is not valid
#endif

//Maximum Port Path Cost value
#ifndef STP_MAX_PORT_PATH_COST
   #define STP_MAX_PORT_PATH_COST 200000000
#elif (STP_MAX_PORT_PATH_COST < STP_DEFAULT_PORT_PATH_COST)
   #error STP_MAX_PORT_PATH_COST parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief STP timer
 **/

typedef struct
{
   bool_t active;
   uint_t value;
} StpTimer;


/**
 * @brief Bridge port
 **/

struct _StpBridgePort
{
   StpBridgeContext *context;     ///<STP bridge context

   uint8_t portIndex;             ///<Port index
   MacAddr macAddr;               ///<MAC address of the port

   bool_t macOperState;           ///<The MAC entity is in a functioning state
   uint_t forwardTransitions;     ///<Number of times the port has transitioned to Forwarding state

   uint16_t portId;               ///<Port identifier (8.5.5.1)
   StpPortState state;            ///<Current state of the port (8.5.5.2)
   uint32_t pathCost;             ///<Contribution of the path through this port (8.5.5.3)
   StpBridgeId designatedRoot;    ///<Unique identifier of the bridge recorded as the Root (8.5.5.4)
   uint32_t designatedCost;       ///<Designated cost (8.5.5.5)
   StpBridgeId designatedBridge;  ///<Designated bridge (8.5.5.6)
   uint16_t designatedPort;       ///<Designated port (8.5.5.7)
   bool_t topologyChangeAck;      ///<Topology Change Acknowledgment flag (8.5.5.8)
   bool_t configPending;          ///<A Configuration BPDU should be transmitted on expiry of the Hold Timer (8.5.5.9)
   bool_t changeDetectionEnabled; ///<Detection of topology changes is enabled for the associated port(8.5.5.10)

   StpTimer messageAgeTimer;      ///<Message age timer (8.5.6.1)
   StpTimer forwardDelayTimer;    ///<Forward delay timer (8.5.6.2)
   StpTimer holdTimer;            ///<Hold timer (8.5.6.3)
};


/**
 * @brief STP bridge settings
 **/

typedef struct
{
   NetInterface *interface; ///<Underlying network interface
   uint_t numPorts;         ///<Number of ports
   StpBridgePort *ports;    ///<Bridge's ports
} StpBridgeSettings;


/**
 * @brief STP bridge context
 **/

struct _StpBridgeContext
{
   NetInterface *interface;        ///<Underlying network interface
   uint_t numPorts;                ///<Number of ports
   StpBridgePort *ports;           ///<Bridge's ports
   bool_t running;                 ///<STP bridge operation state

   StpBridgeId designatedRoot;     ///<Unique identifier of the bridge assumed to be the Root (8.5.3.1)
   uint32_t rootPathCost;          ///<Cost of the path to the Root from this bridge (8.5.3.2)
   uint16_t rootPort;              ///<Port identifier of the port that offers the lowest cost path to the Root (8.5.3.3)
   uint_t maxAge;                  ///<Maximum age of received protocol information before it is discarded (8.5.3.4)
   uint_t helloTime;               ///<Time interval between the transmission of Configuration BPDUs (8.5.3.5)
   uint_t forwardDelay;            ///<Time spent in the Listening/Learning state before moving to the Learning/Forwarding state (8.5.3.6)
   StpBridgeId bridgeId;           ///<Unique identifier assigned to the bridge (8.5.3.7)
   uint_t bridgeMaxAge;            ///<Value of the Max Age parameter when the bridge is the Root (8.5.3.8)
   uint_t bridgeHelloTime;         ///<Value of the Hello Time parameter when the bridge is the Root (8.5.3.9)
   uint_t bridgeForwardDelay;      ///<Value of the Forward Delay parameter when the bridge is the Root (8.5.3.10)
   bool_t topologyChangeDetected;  ///<A topology change has been detected by or notified to the bridge (8.5.3.11)
   bool_t topologyChange;          ///<Boolean (8.5.3.12)
   uint_t topologyChangeTime;      ///<Time period for which Configuration messages indicate topology change (8.5.3.13)
   uint_t holdTime;                ///<Minimum time period between transmission of Configuration BPDUs (8.5.3.14)

   StpTimer helloTimer;            ///<Hello timer (8.5.4.1)
   StpTimer tcnTimer;              ///<Topology change notification timer (8.5.4.2)
   StpTimer topologyChangeTimer;   ///<Topology change timer (8.5.4.3)

   uint_t ageingTime;              ///<Ageing time for filtering database entries (7.9.2)
   StpTimer rapidAgeingTimer;      ///<Rapid ageing timer

   uint_t timeSinceTopologyChange; ///<Time since the last topology change
   uint_t topologyChangeCount;     ///<Number of topology changes
};


//STP related functions
void stpGetDefaultSettings(StpBridgeSettings *settings);
error_t stpInit(StpBridgeContext *context, StpBridgeSettings *settings);

error_t stpStart(StpBridgeContext *context);
error_t stpStop(StpBridgeContext *context);

error_t stpSetBridgePriority(StpBridgeContext *context, uint16_t value);
error_t stpSetBridgeMaxAge(StpBridgeContext *context, uint_t value);
error_t stpSetBridgeHelloTime(StpBridgeContext *context, uint_t value);
error_t stpSetBridgeForwardDelay(StpBridgeContext *context, uint_t value);
error_t stpSetAgeingTime(StpBridgeContext *context, uint_t value);

error_t stpGetNumPorts(StpBridgeContext *context, uint_t *value);
error_t stpGetBridgeAddr(StpBridgeContext *context, MacAddr *value);
error_t stpGetBridgePriority(StpBridgeContext *context, uint16_t *value);
error_t stpGetBridgeMaxAge(StpBridgeContext *context, uint_t *value);
error_t stpGetBridgeHelloTime(StpBridgeContext *context, uint_t *value);
error_t stpGetBridgeForwardDelay(StpBridgeContext *context, uint_t *value);
error_t stpGetHoldTime(StpBridgeContext *context, uint_t *value);
error_t stpGetAgeingTime(StpBridgeContext *context, uint_t *value);
error_t stpGetDesignatedRoot(StpBridgeContext *context, StpBridgeId *value);
error_t stpGetRootPathCost(StpBridgeContext *context, uint32_t *value);
error_t stpGetRootPort(StpBridgeContext *context, uint16_t *value);
error_t stpGetMaxAge(StpBridgeContext *context, uint_t *value);
error_t stpGetHelloTime(StpBridgeContext *context, uint_t *value);
error_t stpGetForwardDelay(StpBridgeContext *context, uint_t *value);
error_t stpGetTopologyChanges(StpBridgeContext *context, uint_t *value);

error_t stpGetTimeSinceTopologyChange(StpBridgeContext *context,
   uint_t *value);

error_t stpSetPortNum(StpBridgeContext *context, uint_t portIndex,
   uint16_t value);

error_t stpSetPortAddr(StpBridgeContext *context, uint_t portIndex,
   const MacAddr *value);

error_t stpSetPortPriority(StpBridgeContext *context, uint_t portIndex,
   uint8_t value);

error_t stpSetAdminPortState(StpBridgeContext *context, uint_t portIndex,
   bool_t value);

error_t stpSetPortPathCost(StpBridgeContext *context, uint_t portIndex,
   uint32_t value);

error_t stpGetPortNum(StpBridgeContext *context, uint_t portIndex,
   uint16_t *value);

error_t stpGetPortAddr(StpBridgeContext *context, uint_t portIndex,
   MacAddr *value);

error_t stpGetPortPriority(StpBridgeContext *context, uint_t portIndex,
   uint8_t *value);

error_t stpGetAdminPortState(StpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t stpGetMacOperState(StpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t stpGetPortPathCost(StpBridgeContext *context, uint_t portIndex,
   uint32_t *value);

error_t stpGetPortState(StpBridgeContext *context, uint_t portIndex,
   StpPortState *value);

error_t stpGetPortRole(StpBridgeContext *context, uint_t portIndex,
   StpPortRole *value);

error_t stpGetPortDesignatedRoot(StpBridgeContext *context, uint_t portIndex,
   StpBridgeId *value);

error_t stpGetPortDesignatedCost(StpBridgeContext *context, uint_t portIndex,
   uint32_t *value);

error_t stpGetPortDesignatedBridge(StpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value);

error_t stpGetPortDesignatedPort(StpBridgeContext *context, uint_t portIndex,
   uint16_t *value);

error_t stpGetForwardTransitions(StpBridgeContext *context, uint_t portIndex,
   uint_t *value);

void stpDeinit(StpBridgeContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

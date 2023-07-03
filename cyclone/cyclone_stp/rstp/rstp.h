/**
 * @file rstp.h
 * @brief RSTP (Rapid Spanning Tree Protocol)
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

#ifndef _RSTP_H
#define _RSTP_H

//Forward declaration of RstpBridgeContext structure
struct _RstpBridgeContext;
#define RstpBridgeContext struct _RstpBridgeContext

//Forward declaration of RstpBridgePort structure
struct _RstpBridgePort;
#define RstpBridgePort struct _RstpBridgePort

//Dependencies
#include "stp/stp_common.h"
#include "rstp/rstp_pti.h"
#include "rstp/rstp_prx.h"
#include "rstp/rstp_ppm.h"
#include "rstp/rstp_bdm.h"
#include "rstp/rstp_ptx.h"
#include "rstp/rstp_pim.h"
#include "rstp/rstp_prs.h"
#include "rstp/rstp_prt.h"
#include "rstp/rstp_pst.h"
#include "rstp/rstp_tcm.h"
#include "rstp/rstp_bpdu.h"

//RSTP bridge support
#ifndef RSTP_SUPPORT
   #define RSTP_SUPPORT DISABLED
#elif (RSTP_SUPPORT != ENABLED && RSTP_SUPPORT != DISABLED)
   #error RSTP_SUPPORT parameter is not valid
#endif

//RSTP tick interval (in milliseconds)
#ifndef RSTP_TICK_INTERVAL
   #define RSTP_TICK_INTERVAL 1000
#elif (RSTP_TICK_INTERVAL < 10)
   #error RSTP_TICK_INTERVAL parameter is not valid
#endif

//Default Bridge Priority Value
#ifndef RSTP_DEFAULT_BRIDGE_PRIORITY
   #define RSTP_DEFAULT_BRIDGE_PRIORITY 32768
#elif (RSTP_DEFAULT_BRIDGE_PRIORITY < 0 || RSTP_DEFAULT_BRIDGE_PRIORITY > 61440)
   #error RSTP_DEFAULT_BRIDGE_PRIORITY parameter is not valid
#endif

//Default Port Priority Value
#ifndef RSTP_DEFAULT_PORT_PRIORITY
   #define RSTP_DEFAULT_PORT_PRIORITY 128
#elif (RSTP_DEFAULT_PORT_PRIORITY < 0 || RSTP_DEFAULT_PORT_PRIORITY > 240)
   #error RSTP_DEFAULT_PORT_PRIORITY parameter is not valid
#endif

//Default Migrate Time value
#ifndef RSTP_DEFAULT_MIGRATE_TIME
   #define RSTP_DEFAULT_MIGRATE_TIME 3
#elif (RSTP_DEFAULT_MIGRATE_TIME < 0)
   #error RSTP_DEFAULT_MIGRATE_TIME parameter is not valid
#endif

//Minimum Bridge Max Age value
#ifndef RSTP_MIN_BRIDGE_MAX_AGE
   #define RSTP_MIN_BRIDGE_MAX_AGE 6
#elif (RSTP_MIN_BRIDGE_MAX_AGE < 0)
   #error RSTP_MIN_BRIDGE_MAX_AGE parameter is not valid
#endif

//Default Bridge Max Age value
#ifndef RSTP_DEFAULT_BRIDGE_MAX_AGE
   #define RSTP_DEFAULT_BRIDGE_MAX_AGE 20
#elif (RSTP_DEFAULT_BRIDGE_MAX_AGE < RSTP_MIN_BRIDGE_MAX_AGE)
   #error RSTP_DEFAULT_BRIDGE_MAX_AGE parameter is not valid
#endif

//Maximum Bridge Max Age value
#ifndef RSTP_MAX_BRIDGE_MAX_AGE
   #define RSTP_MAX_BRIDGE_MAX_AGE 40
#elif (RSTP_MAX_BRIDGE_MAX_AGE < RSTP_DEFAULT_BRIDGE_MAX_AGE)
   #error RSTP_MAX_BRIDGE_MAX_AGE parameter is not valid
#endif

//Minimum Bridge Hello Time value
#ifndef RSTP_MIN_BRIDGE_HELLO_TIME
   #define RSTP_MIN_BRIDGE_HELLO_TIME 1
#elif (RSTP_MIN_BRIDGE_HELLO_TIME < 0)
   #error RSTP_MIN_BRIDGE_HELLO_TIME parameter is not valid
#endif

//Default Bridge Hello Time value
#ifndef RSTP_DEFAULT_BRIDGE_HELLO_TIME
   #define RSTP_DEFAULT_BRIDGE_HELLO_TIME 2
#elif (RSTP_DEFAULT_BRIDGE_HELLO_TIME < RSTP_MIN_BRIDGE_HELLO_TIME)
   #error RSTP_DEFAULT_BRIDGE_HELLO_TIME parameter is not valid
#endif

//Maximum Bridge Hello Time value
#ifndef RSTP_MAX_BRIDGE_HELLO_TIME
   #define RSTP_MAX_BRIDGE_HELLO_TIME 10
#elif (RSTP_MAX_BRIDGE_HELLO_TIME < RSTP_DEFAULT_BRIDGE_HELLO_TIME)
   #error RSTP_MAX_BRIDGE_HELLO_TIME parameter is not valid
#endif

//Minimum Bridge Forward Delay value
#ifndef RSTP_MIN_BRIDGE_FORWARD_DELAY
   #define RSTP_MIN_BRIDGE_FORWARD_DELAY 4
#elif (RSTP_MIN_BRIDGE_FORWARD_DELAY < 0)
   #error RSTP_MIN_BRIDGE_FORWARD_DELAY parameter is not valid
#endif

//Default Bridge Forward Delay value
#ifndef RSTP_DEFAULT_BRIDGE_FORWARD_DELAY
   #define RSTP_DEFAULT_BRIDGE_FORWARD_DELAY 15
#elif (RSTP_DEFAULT_BRIDGE_FORWARD_DELAY < RSTP_MIN_BRIDGE_FORWARD_DELAY)
   #error RSTP_DEFAULT_BRIDGE_FORWARD_DELAY parameter is not valid
#endif

//Maximum Bridge Forward Delay value
#ifndef RSTP_MAX_BRIDGE_FORWARD_DELAY
   #define RSTP_MAX_BRIDGE_FORWARD_DELAY 30
#elif (RSTP_MAX_BRIDGE_FORWARD_DELAY < RSTP_DEFAULT_BRIDGE_FORWARD_DELAY)
   #error RSTP_MAX_BRIDGE_FORWARD_DELAY parameter is not valid
#endif

//Minimum Transmit Hold Count value
#ifndef RSTP_MIN_TRANSMIT_HOLD_COUNT
   #define RSTP_MIN_TRANSMIT_HOLD_COUNT 1
#elif (RSTP_MIN_TRANSMIT_HOLD_COUNT < 0)
   #error RSTP_MIN_TRANSMIT_HOLD_COUNT parameter is not valid
#endif

//Default Transmit Hold Count value
#ifndef RSTP_DEFAULT_TRANSMIT_HOLD_COUNT
   #define RSTP_DEFAULT_TRANSMIT_HOLD_COUNT 6
#elif (RSTP_DEFAULT_TRANSMIT_HOLD_COUNT < RSTP_MIN_TRANSMIT_HOLD_COUNT)
   #error RSTP_DEFAULT_TRANSMIT_HOLD_COUNT parameter is not valid
#endif

//Maximum Transmit Hold Count value
#ifndef RSTP_MAX_TRANSMIT_HOLD_COUNT
   #define RSTP_MAX_TRANSMIT_HOLD_COUNT 10
#elif (RSTP_MAX_TRANSMIT_HOLD_COUNT < RSTP_DEFAULT_TRANSMIT_HOLD_COUNT)
   #error RSTP_MAX_TRANSMIT_HOLD_COUNT parameter is not valid
#endif

//Minimum Ageing Time value
#ifndef RSTP_MIN_AGEING_TIME
   #define RSTP_MIN_AGEING_TIME 10
#elif (RSTP_MIN_AGEING_TIME < 0)
   #error RSTP_MIN_AGEING_TIME parameter is not valid
#endif

//Default Ageing Time value
#ifndef RSTP_DEFAULT_AGEING_TIME
   #define RSTP_DEFAULT_AGEING_TIME 300
#elif (RSTP_DEFAULT_AGEING_TIME < RSTP_MIN_AGEING_TIME)
   #error RSTP_DEFAULT_AGEING_TIME parameter is not valid
#endif

//Maximum Ageing Time value
#ifndef RSTP_MAX_AGEING_TIME
   #define RSTP_MAX_AGEING_TIME 1000000
#elif (RSTP_MAX_AGEING_TIME < RSTP_DEFAULT_AGEING_TIME)
   #error RSTP_MAX_AGEING_TIME parameter is not valid
#endif

//Minimum Port Path Cost value
#ifndef RSTP_MIN_PORT_PATH_COST
   #define RSTP_MIN_PORT_PATH_COST 1
#elif (RSTP_MIN_PORT_PATH_COST < 0)
   #error RSTP_MIN_PORT_PATH_COST parameter is not valid
#endif

//Default Port Path Cost value
#ifndef RSTP_DEFAULT_PORT_PATH_COST
   #define RSTP_DEFAULT_PORT_PATH_COST 200000
#elif (RSTP_DEFAULT_PORT_PATH_COST < RSTP_MIN_PORT_PATH_COST)
   #error RSTP_DEFAULT_PORT_PATH_COST parameter is not valid
#endif

//Maximum Port Path Cost value
#ifndef RSTP_MAX_PORT_PATH_COST
   #define RSTP_MAX_PORT_PATH_COST 200000000
#elif (RSTP_MAX_PORT_PATH_COST < RSTP_DEFAULT_PORT_PATH_COST)
   #error RSTP_MAX_PORT_PATH_COST parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief State of the received Spanning Tree information
 **/

typedef enum
{
   RSTP_RCVD_INFO_SUPERIOR_DESIGNATED     = 0,
   RSTP_RCVD_INFO_REPEATED_DESIGNATED     = 1,
   RSTP_RCVD_INFO_INFERIOR_DESIGNATED     = 2,
   RSTP_RCVD_INFO_INFERIOR_ROOT_ALTERNATE = 3,
   RSTP_RCVD_INFO_OTHER                   = 4
} RstpRcvdInfo;


/**
 * @brief Origin/state of the port's Spanning Tree information
 **/

typedef enum
{
   RSTP_INFO_IS_DISABLED = 0,
   RSTP_INFO_IS_RECEIVED = 1,
   RSTP_INFO_IS_MINE     = 2,
   RSTP_INFO_IS_AGED     = 3
} RstpInfoIs;


/**
 * @brief Administrative state of the point-to-point status
 **/

typedef enum
{
   RSTP_ADMIN_P2P_MAC_FORCE_FALSE = 0,
   RSTP_ADMIN_P2P_MAC_FORCE_TRUE  = 1,
   RSTP_ADMIN_P2P_MAC_AUTO        = 2
} RstpAdminPointToPointMac;


/**
 * @brief RSTP timer parameter values
 **/

typedef struct
{
   uint_t messageAge;
   uint_t maxAge;
   uint_t forwardDelay;
   uint_t helloTime;
} RstpTimes;


/**
 * @brief Spanning Tree priority vector
 **/

typedef struct
{
   StpBridgeId rootBridgeId;
   uint32_t rootPathCost;
   StpBridgeId designatedBridgeId;
   uint16_t designatedPortId;
   uint16_t bridgePortId;
} RstpPriority;


/**
 * @brief RSTP bridge parameters
 **/

typedef struct
{
   uint_t ageingTime;           ///<Ageing Time parameter for the bridge (17.13.2)
   uint_t forceProtocolVersion; ///<Force Protocol Version parameter for the bridge (17.13.4)
   uint_t bridgeForwardDelay;   ///<Delay used by STP bridges to transition Root and Designated ports to Forwarding (17.13.5)
   uint_t bridgeHelloTime;      ///<Interval between periodic transmissions of Configuration messages by Designated ports (17.13.6)
   uint_t bridgeMaxAge;         ///<Maximum age of the information transmitted by the bridge when it is the Root bridge (17.13.8)
   uint_t migrateTime;          ///<Initial value of the mdelayWhile and edgeDelayWhile timers (17.13.9)
   uint_t transmitHoldCount;    ///<Value used to limit the maximum transmission rate (17.13.12)
} RstpBridgeParams;


/**
 * @brief Bridge port parameters
 **/

typedef struct
{
   bool_t adminPortState;                         ///<Administrative bridge port state (14.8.2.2)
   uint32_t adminPathCost;                        ///<Contribution of this port to the path cost
   RstpAdminPointToPointMac adminPointToPointMac; ///<Administrative state of the point-to-point status (6.4.3)
   bool_t adminEdgePort;                          ///<AdminEdgePort parameter for the port (17.13.1)
   bool_t autoEdgePort;                           ///<AutoEdgePort parameter for the port (17.13.3)
} RstpPortParams;


/**
 * @brief Bridge port
 **/

struct _RstpBridgePort
{
   RstpBridgeContext *context;      ///<RSTP bridge context

   uint8_t portIndex;               ///<Port index
   MacAddr macAddr;                 ///<MAC address of the port

   RstpPortParams params;           ///<Port parameters

   uint32_t linkSpeed;              ///<Link speed
   NicDuplexMode duplexMode;        ///<Duplex mode
   bool_t macOperState;             ///<The MAC entity is in a functioning state (6.4.2)
   bool_t operPointToPointMac;      ///<The MAC is connected to a point-to-point LAN (6.4.3)
   uint_t forwardTransitions;       ///<Number of times the port has transitioned to Forwarding state

   RstpPtiState ptiState;           ///<Port Timers state machine (17.22)
   RstpPrxState prxState;           ///<Port Receive state machine (17.23)
   RstpPpmState ppmState;           ///<Port Protocol Migration state machine (17.24)
   RstpBdmState bdmState;           ///<Bridge Detection state machine (17.25)
   RstpPtxState ptxState;           ///<Port Transmit state machine (17.26)
   RstpPimState pimState;           ///<Port Information state machine (17.27)
   RstpPrtState prtState;           ///<Port Role Transition state machine (17.29)
   RstpPstState pstState;           ///<Port State Transition state machine (17.30)
   RstpTcmState tcmState;           ///<Topology Change state machine (17.31)

   uint_t edgeDelayWhile;           ///<Edge Delay timer (17.17.1)
   uint_t fdWhile;                  ///<Forward Delay timer (17.17.2)
   uint_t helloWhen;                ///<Hello timer (17.17.3)
   uint_t mdelayWhile;              ///<Migration Delay timer (17.17.4)
   uint_t rbWhile;                  ///<Recent Backup timer (17.17.5)
   uint_t rcvdInfoWhile;            ///<Received Info timer (17.17.6)
   uint_t rrWhile;                  ///<Recent Root timer (17.17.7)
   uint_t tcWhile;                  ///<Topology Change timer (17.17.8)

   bool_t agree;                    ///<Boolean (17.19.2)
   bool_t agreed;                   ///<Boolean (17.19.3)
   RstpPriority designatedPriority; ///<First four components of the designated priority vector value (17.19.4)
   RstpTimes designatedTimes;       ///<Set of timer parameter values used to update Port Times (17.19.5)
   bool_t disputed;                 ///<Boolean (17.19.6)
   bool_t fdbFlush;                 ///<Instruct the filtering database to remove all entries for this port (17.19.7)
   bool_t forward;                  ///<Boolean (17.19.8)
   bool_t forwarding;               ///<Boolean (17.19.9)
   RstpInfoIs infoIs;               ///<Origin/state of the port's Spanning Tree information held for the port (17.19.10)
   bool_t learn;                    ///<Boolean (17.19.11)
   bool_t learning;                 ///<Boolean (17.19.12)
   bool_t mcheck;                   ///<Force PPM state machine to transmit RST BPDUs for a MigrateTime period (17.19.13)
   RstpPriority msgPriority;        ///<First four components of the message priority vector (17.19.14)
   RstpTimes msgTimes;              ///<Set of timer parameter values conveyed in a received BPDU (17.19.15)
   bool_t newInfo;                  ///<Set if a BPDU is to be transmitted (17.19.16)
   bool_t operEdge;                 ///<Boolean (17.19.17)
   bool_t portEnabled;              ///<Set if the port can be used transmit and receive frames (17.19.18)
   uint16_t portId;                 ///<Port identifier (17.19.19)
   uint32_t portPathCost;           ///<Port's contribution to the root path cost (17.19.20)
   RstpPriority portPriority;       ///<First four components of the port priority vector value (17.19.21)
   RstpTimes portTimes;             ///<Set of timer parameter values used in transmitted BPDUs (17.19.22)
   bool_t proposed;                 ///<Boolean (17.19.23)
   bool_t proposing;                ///<Boolean (17.19.24)
   bool_t rcvdBpdu;                 ///<A valid Configuration, TCN or RST BPDU is received on the port (17.19.25)
   RstpRcvdInfo rcvdInfo;           ///<State of the received Spanning Tree information (17.19.26)
   bool_t rcvdMsg;                  ///<Boolean (17.19.27)
   bool_t rcvdRstp;                 ///<Boolean (17.19.28)
   bool_t rcvdStp;                  ///<Boolean (17.19.29)
   bool_t rcvdTc;                   ///<Boolean (17.19.30)
   bool_t rcvdTcAck;                ///<Boolean (17.19.31)
   bool_t rcvdTcn;                  ///<Boolean (17.19.32)
   bool_t reRoot;                   ///<Boolean (17.19.33)
   bool_t reselect;                 ///<Boolean (17.19.34)
   StpPortRole role;                ///<Assigned Port Role (17.19.35)
   bool_t selected;                 ///<Boolean (17.19.36)
   StpPortRole selectedRole;        ///<Newly computed role for the port (17.19.37)
   bool_t sendRstp;                 ///<Set if an RSTP BPDU is to be transmitted (17.19.38)
   bool_t sync;                     ///<Boolean (17.19.39)
   bool_t synced;                   ///<Boolean (17.19.40)
   bool_t tcAck;                    ///<Set if a Configuration message with a TC ACK flag is to be transmitted (17.19.41)
   bool_t tcProp;                   ///<Set if a topology change should be propagated through this port (17.19.42)
   bool_t tick;                     ///<Tick signal (17.19.43)
   uint_t txCount;                  ///<Counter incremented on every BPDU transmission (17.19.44)
   bool_t updtInfo;                 ///<Set to tell that portPriority and portTimes should be updated (17.19.45)
};


/**
 * @brief RSTP bridge settings
 **/

typedef struct
{
   NetInterface *interface; ///<Underlying network interface
   uint_t numPorts;         ///<Number of ports
   RstpBridgePort *ports;   ///<Bridge's ports
} RstpBridgeSettings;


/**
 * @brief RSTP bridge context
 **/

struct _RstpBridgeContext
{
   NetInterface *interface;        ///<Underlying network interface
   uint_t numPorts;                ///<Number of ports
   RstpBridgePort *ports;          ///<Bridge's ports
   bool_t running;                 ///<RSTP bridge operation state

   RstpBridgeParams params;        ///<RSTP bridge parameters (17.13)

   StpBridgeId bridgeId;          ///<Unique identifier assigned to the bridge (17.18.2)
   RstpPriority bridgePriority;    ///<Bridge priority vector (17.18.3)
   RstpTimes bridgeTimes;          ///<Bridge's timer parameter values (17.18.4)
   uint16_t rootPortId;            ///<Port Identifier of the Root port (17.18.5)
   RstpPriority rootPriority;      ///<First four components of the bridge's root priority vector (17.18.6)
   RstpTimes rootTimes;            ///<Bridge's operational timer parameter values (7.18.7)

   RstpPrsState prsState;          ///<Port Role Selection state machine (17.28)

   uint_t ageingTime;              ///<Ageing time for filtering database entries (17.19.1)
   uint_t rapidAgeingWhile;        ///<Rapid ageing timer

   uint_t timeSinceTopologyChange; ///<Time since the last topology change
   uint_t topologyChangeCount;     ///<Number of topology changes
   RstpBpdu bpdu;                  ///<Received BPDU
   bool_t busy;                    ///<Busy flag
};


//RSTP related functions
void rstpGetDefaultSettings(RstpBridgeSettings *settings);
error_t rstpInit(RstpBridgeContext *context, RstpBridgeSettings *settings);

error_t rstpStart(RstpBridgeContext *context);
error_t rstpStop(RstpBridgeContext *context);

error_t rstpSetVersion(RstpBridgeContext *context, uint_t value);
error_t rstpSetBridgePriority(RstpBridgeContext *context, uint16_t value);
error_t rstpSetBridgeMaxAge(RstpBridgeContext *context, uint_t value);
error_t rstpSetBridgeHelloTime(RstpBridgeContext *context, uint_t value);
error_t rstpSetBridgeForwardDelay(RstpBridgeContext *context, uint_t value);
error_t rstpSetTxHoldCount(RstpBridgeContext *context, uint_t value);
error_t rstpSetAgeingTime(RstpBridgeContext *context, uint_t value);

error_t rstpGetNumPorts(RstpBridgeContext *context, uint_t *value);
error_t rstpGetVersion(RstpBridgeContext *context, uint_t *value);
error_t rstpGetBridgeAddr(RstpBridgeContext *context, MacAddr *value);
error_t rstpGetBridgePriority(RstpBridgeContext *context, uint16_t *value);
error_t rstpGetBridgeMaxAge(RstpBridgeContext *context, uint_t *value);
error_t rstpGetBridgeHelloTime(RstpBridgeContext *context, uint_t *value);
error_t rstpGetBridgeForwardDelay(RstpBridgeContext *context, uint_t *value);
error_t rstpGetTxHoldCount(RstpBridgeContext *context, uint_t *value);
error_t rstpGetAgeingTime(RstpBridgeContext *context, uint_t *value);
error_t rstpGetDesignatedRoot(RstpBridgeContext *context, StpBridgeId *value);
error_t rstpGetRootPathCost(RstpBridgeContext *context, uint32_t *value);
error_t rstpGetRootPort(RstpBridgeContext *context, uint16_t *value);
error_t rstpGetMaxAge(RstpBridgeContext *context, uint_t *value);
error_t rstpGetHelloTime(RstpBridgeContext *context, uint_t *value);
error_t rstpGetForwardDelay(RstpBridgeContext *context, uint_t *value);
error_t rstpGetTopologyChanges(RstpBridgeContext *context, uint_t *value);

error_t rstpGetTimeSinceTopologyChange(RstpBridgeContext *context,
   uint_t *value);

error_t rstpSetPortNum(RstpBridgeContext *context, uint_t portIndex,
   uint16_t value);

error_t rstpSetPortAddr(RstpBridgeContext *context, uint_t portIndex,
   const MacAddr *value);

error_t rstpSetPortPriority(RstpBridgeContext *context, uint_t portIndex,
   uint8_t value);

error_t rstpSetAdminPortState(RstpBridgeContext *context, uint_t portIndex,
   bool_t value);

error_t rstpSetAdminPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t value);

error_t rstpSetAdminPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, RstpAdminPointToPointMac value);

error_t rstpSetAdminEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t value);

error_t rstpSetAutoEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t value);

error_t rstpSetProtocolMigration(RstpBridgeContext *context, uint_t portIndex,
   bool_t value);

error_t rstpGetPortNum(RstpBridgeContext *context, uint_t portIndex,
   uint16_t *value);

error_t rstpGetPortAddr(RstpBridgeContext *context, uint_t portIndex,
   MacAddr *value);

error_t rstpGetPortPriority(RstpBridgeContext *context, uint_t portIndex,
   uint8_t *value);

error_t rstpGetAdminPortState(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t rstpGetMacOperState(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t rstpGetAdminPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t *value);

error_t rstpGetPortPathCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t *value);

error_t rstpGetAdminPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, RstpAdminPointToPointMac *value);

error_t rstpGetOperPointToPointMac(RstpBridgeContext *context,
   uint_t portIndex, bool_t *value);

error_t rstpGetAdminEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t rstpGetAutoEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t rstpGetOperEdgePort(RstpBridgeContext *context, uint_t portIndex,
   bool_t *value);

error_t rstpGetPortState(RstpBridgeContext *context, uint_t portIndex,
   StpPortState *value);

error_t rstpGetPortRole(RstpBridgeContext *context, uint_t portIndex,
   StpPortRole *value);

error_t rstpGetPortDesignatedRoot(RstpBridgeContext *context, uint_t portIndex,
   StpBridgeId *value);

error_t rstpGetPortDesignatedCost(RstpBridgeContext *context, uint_t portIndex,
   uint32_t *value);

error_t rstpGetPortDesignatedBridge(RstpBridgeContext *context,
   uint_t portIndex, StpBridgeId *value);

error_t rstpGetPortDesignatedPort(RstpBridgeContext *context, uint_t portIndex,
   uint16_t *value);

error_t rstpGetForwardTransitions(RstpBridgeContext *context, uint_t portIndex,
   uint_t *value);

void rstpDeinit(RstpBridgeContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

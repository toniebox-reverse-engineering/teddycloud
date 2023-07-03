/**
 * @file lldp.h
 * @brief LLDP (Link Layer Discovery Protocol)
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

#ifndef _LLDP_H
#define _LLDP_H

//Forward declaration of LldpDataUnit structure
struct _LldpDataUnit;
#define LldpDataUnit struct _LldpDataUnit

//Forward declaration of LldpAgentContext structure
struct _LldpAgentContext;
#define LldpAgentContext struct _LldpAgentContext

//Forward declaration of LldpPortEntry structure
struct _LldpPortEntry;
#define LldpPortEntry struct _LldpPortEntry

//Dependencies
#include "core/net.h"
#include "lldp/lldp_rx_fsm.h"
#include "lldp/lldp_tx_fsm.h"
#include "lldp/lldp_tlv.h"

//LLDP agent support
#ifndef LLDP_SUPPORT
   #define LLDP_SUPPORT DISABLED
#elif (LLDP_SUPPORT != ENABLED && LLDP_SUPPORT != DISABLED)
   #error LLDP_SUPPORT parameter is not valid
#endif

//LLDP TX mode support
#ifndef LLDP_TX_MODE_SUPPORT
   #define LLDP_TX_MODE_SUPPORT ENABLED
#elif (LLDP_TX_MODE_SUPPORT != ENABLED && LLDP_TX_MODE_SUPPORT != DISABLED)
   #error LLDP_TX_MODE_SUPPORT parameter is not valid
#endif

//LLDP RX mode support
#ifndef LLDP_RX_MODE_SUPPORT
   #define LLDP_RX_MODE_SUPPORT ENABLED
#elif (LLDP_RX_MODE_SUPPORT != ENABLED && LLDP_RX_MODE_SUPPORT != DISABLED)
   #error LLDP_RX_MODE_SUPPORT parameter is not valid
#endif

//Stack size required to run the LLDP agent
#ifndef LLDP_TASK_STACK_SIZE
   #define LLDP_TASK_STACK_SIZE 500
#elif (LLDP_TASK_STACK_SIZE < 1)
   #error LLDP_TASK_STACK_SIZE parameter is not valid
#endif

//Priority at which the LLDP agent should run
#ifndef LLDP_TASK_PRIORITY
   #define LLDP_TASK_PRIORITY OS_TASK_PRIORITY_NORMAL
#endif

//LLDP tick interval (in milliseconds)
#ifndef LLDP_TICK_INTERVAL
   #define LLDP_TICK_INTERVAL 1000
#elif (LLDP_TICK_INTERVAL < 10)
   #error LLDP_TICK_INTERVAL parameter is not valid
#endif

//Maximum LLDP data unit size
#ifndef LLDP_MAX_LLDPDU_SIZE
   #define LLDP_MAX_LLDPDU_SIZE 500
#elif (LLDP_MAX_LLDPDU_SIZE < 100 || LLDP_MAX_LLDPDU_SIZE > 1500)
   #error LLDP_MAX_LLDPDU_SIZE parameter is not valid
#endif

//Maximum number of management addresses
#ifndef LLDP_MAX_MGMT_ADDRS
   #define LLDP_MAX_MGMT_ADDRS 10
#elif (LLDP_MAX_MGMT_ADDRS < 1 || LLDP_MAX_MGMT_ADDRS > 32)
   #error LLDP_MAX_MGMT_ADDRS parameter is not valid
#endif

//Minimum msgTxInterval value
#define LLDP_MIN_MSG_TX_INTERVAL 1
//Default msgTxInterval value
#define LLDP_DEFAULT_MSG_TX_INTERVAL 30
//Maximum msgTxInterval value
#define LLDP_MAX_MSG_TX_INTERVAL 3600

//Minimum msgTxHold value
#define LLDP_MIN_MSG_TX_HOLD 1
//Default msgTxHold value
#define LLDP_DEFAULT_MSG_TX_HOLD 4
//Maximum msgTxHold value
#define LLDP_MAX_MSG_TX_HOLD 100

//Minimum reinitDelay value
#define LLDP_MIN_REINIT_DELAY 1
//Default reinitDelay value
#define LLDP_DEFAULT_REINIT_DELAY 2
//Maximum reinitDelay value
#define LLDP_MAX_REINIT_DELAY 10

//Minimum txDelay value
#define LLDP_MIN_TX_DELAY 1
//Default txDelay value
#define LLDP_DEFAULT_TX_DELAY 2
//Maximum txDelay value
#define LLDP_MAX_TX_DELAY 900

//Minimum notification interval
#define LLDP_MIN_NOTIFICATION_INTERVAL 5
//Default notification interval
#define LLDP_DEFAULT_NOTIFICATION_INTERVAL 5
//Maximum notification interval
#define LLDP_MAX_NOTIFICATION_INTERVAL 3600

//Management address filter
#define LLDP_MGMT_ADDR_FILTER_0   0x00000001
#define LLDP_MGMT_ADDR_FILTER_1   0x00000002
#define LLDP_MGMT_ADDR_FILTER_2   0x00000004
#define LLDP_MGMT_ADDR_FILTER_3   0x00000008
#define LLDP_MGMT_ADDR_FILTER_4   0x00000010
#define LLDP_MGMT_ADDR_FILTER_5   0x00000020
#define LLDP_MGMT_ADDR_FILTER_6   0x00000040
#define LLDP_MGMT_ADDR_FILTER_7   0x00000080
#define LLDP_MGMT_ADDR_FILTER_8   0x00000100
#define LLDP_MGMT_ADDR_FILTER_9   0x00000200
#define LLDP_MGMT_ADDR_FILTER_10  0x00000400
#define LLDP_MGMT_ADDR_FILTER_11  0x00000800
#define LLDP_MGMT_ADDR_FILTER_12  0x00001000
#define LLDP_MGMT_ADDR_FILTER_13  0x00002000
#define LLDP_MGMT_ADDR_FILTER_14  0x00004000
#define LLDP_MGMT_ADDR_FILTER_15  0x00008000
#define LLDP_MGMT_ADDR_FILTER_16  0x00010000
#define LLDP_MGMT_ADDR_FILTER_17  0x00020000
#define LLDP_MGMT_ADDR_FILTER_18  0x00040000
#define LLDP_MGMT_ADDR_FILTER_19  0x00080000
#define LLDP_MGMT_ADDR_FILTER_20  0x00100000
#define LLDP_MGMT_ADDR_FILTER_21  0x00200000
#define LLDP_MGMT_ADDR_FILTER_22  0x00400000
#define LLDP_MGMT_ADDR_FILTER_23  0x00800000
#define LLDP_MGMT_ADDR_FILTER_24  0x01000000
#define LLDP_MGMT_ADDR_FILTER_25  0x02000000
#define LLDP_MGMT_ADDR_FILTER_26  0x04000000
#define LLDP_MGMT_ADDR_FILTER_27  0x08000000
#define LLDP_MGMT_ADDR_FILTER_28  0x10000000
#define LLDP_MGMT_ADDR_FILTER_29  0x20000000
#define LLDP_MGMT_ADDR_FILTER_30  0x40000000
#define LLDP_MGMT_ADDR_FILTER_31  0x80000000
#define LLDP_MGMT_ADDR_FILTER_ALL 0xFFFFFFFF

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Administrative status
 **/

typedef enum
{
   LLDP_ADMIN_STATUS_DISABLED        = 0, ///<The local LLDP agent can neither transmit or receive LLDP frames
   LLDP_ADMIN_STATUS_ENABLED_TX_ONLY = 1, ///<The local LLDP agent can only transmit LLDP frames
   LLDP_ADMIN_STATUS_ENABLED_RX_ONLY = 2, ///<The local LLDP agent can only receive LLDP frames
   LLDP_ADMIN_STATUS_ENABLED_TX_RX   = 3, ////The local LLDP agent can both transmit and receive LLDP frames
} LldpAdminStatus;


/**
 * @brief Basic TLV filter
 **/

typedef enum
{
   LLDP_BASIC_TLV_FILTER_PORT_DESC = 0x01, ///<Port Description TLV
   LLDP_BASIC_TLV_FILTER_SYS_NAME  = 0x02, ///<System Name TLV
   LLDP_BASIC_TLV_FILTER_SYS_DESC  = 0x04, ///<System Description TLV
   LLDP_BASIC_TLV_FILTER_SYS_CAP   = 0x08, ///<System Capabilities TLV
   LLDP_BASIC_TLV_FILTER_ALL       = 0x0F  ///<All Basic TLVs
} LldpBasicTlvFilter;


/**
 * @brief LLDP frame transmission callback function
 **/

typedef void (*LldpSendCallback)(LldpPortEntry *port, LldpDataUnit *lldpdu);


/**
 * @brief LLDP frame reception callback function
 **/

typedef void (*LldpReceiveCallback)(LldpPortEntry *port, LldpDataUnit *lldpdu);


/**
 * @brief Tick callback function
 **/

typedef void (*LldpTickCallback)(LldpAgentContext *context);


/**
 * @brief LLDP data unit
 **/

struct _LldpDataUnit
{
   uint8_t data[LLDP_MAX_LLDPDU_SIZE];
   size_t length;
   size_t pos;
};


/**
 * @brief MSAP identifier
 **/

typedef struct
{
   const uint8_t *chassisId; ///<Chassis identifier
   size_t chassisIdLen;      ///<Length of the chassis identifier, in bytes
   const uint8_t *portId;    ///<Port identifier
   size_t portIdLen;         ///<Length of the port identifier, in bytes
} LldpMsapId;


/**
 * @brief LLDP neighbor entry
 **/

typedef struct
{
   uint32_t index;      ///<Arbitrary local integer value used to identify the entry
   uint32_t timeMark;   ///<Timestamp used to implement time-filtered rows
   uint_t portIndex;    ///<Port on which the LLDPDU was received
   uint_t rxInfoTTL;    ///<Time remaining until the information is no longer valid
   LldpDataUnit rxInfo; ///<Remote system information
} LldpNeighborEntry;


/**
 * @brief LLDP port entry
 **/

struct _LldpPortEntry
{
   LldpAgentContext *context;           ///<LLDP agent context
   uint8_t portIndex;                   ///<Port index
   LldpAdminStatus adminStatus;         ///<Indicates whether the local LLDP agent is enabled
   bool_t portEnabled;                  ///<Operational state of the MAC service supporting the port

#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   MacAddr macAddr;                     ///<MAC address of the port
   LldpDataUnit txInfo;                 ///<Local system information
   uint8_t basicTlvFilter;              ///<Bit-map indicating the basic TLVs enabled for transmission
   uint32_t mgmtAddrFilter;             ///<Bit-map indicating the management addresses enabled for transmission
   LldpTxState txState;                 ///<LLDP transmit state
   uint_t txShutdownWhile;              ///<Number of seconds remaining until LLDP re-initialization can occur
   uint_t txDelayWhile;                 ///<Minimum delay between transmission of successive LLDP frames
   uint_t txTTR;                        ///<Transmit time to refresh timer
   bool_t somethingChangedLocal;        ///<Status/value of one or more objects in the LLDP local system MIB has changed
   uint_t txTTL;                        ///<Time remaining before information in the outgoing LLDPDU will no longer be valid
   uint32_t statsFramesOutTotal;        ///<Count of all LLDP frames transmitted
   uint32_t lldpduLengthErrors;         ///<The number of LLDPDU length errors recorded for the port
#endif

#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   LldpRxState rxState;                 ///<LLDP receive state
   bool_t notificationEnable;           ///<Enable or disable notifications
   bool_t rcvFrame;                     ///<An LLDP frame has been recognized by the LLDP LSAP function
   uint_t rxInfoAge;                    ///<The rxInfoTTL timing counter has expired
   uint32_t statsFramesDiscardedTotal;  ///<Count of all LLDPDUs received and then discarded
   uint32_t statsFramesInErrorsTotal;   ///<Count of all LLDPDUs received with one or more detectable errors
   uint32_t statsFramesInTotal;         ///<Count of all LLDP frames received
   uint32_t statsTLVsDiscardedTotal;    ///<Count of all TLVs received and then discarded for any reason
   uint32_t statsTLVsUnrecognizedTotal; ///<Count of all TLVs received on the port that are not recognized
   uint32_t statsAgeoutsTotal;          ///<Count of the times that a neighbor's information has been aged out
#endif
};


/**
 * @brief LLDP agent settings
 **/

typedef struct
{
   NetInterface *interface;             ///<Network interface to configure
   uint_t numPorts;                     ///<Number of ports
   LldpPortEntry *ports;                ///<Port table
   uint_t numNeighbors;                 ///<Maximum number of entries in the neighbor table
   LldpNeighborEntry *neighbors;        ///<Neighbor table
   LldpSendCallback sendCallback;       ///<LLDP frame transmission callback function
   LldpReceiveCallback receiveCallback; ///<LLDP frame reception callback function
   LldpTickCallback tickCallback;       ///<Tick callback function
} LldpAgentSettings;


/**
 * @brief LLDP agent context
 **/

struct _LldpAgentContext
{
   NetInterface *interface;                     ///<Underlying network interface
   uint_t numPorts;                             ///<Number of ports
   LldpPortEntry *ports;                        ///<Port table
   uint_t numNeighbors;                         ///<Maximum number of entries in the neighbor table
   LldpNeighborEntry *neighbors;                ///<Neighbor table
   LldpSendCallback sendCallback;               ///<LLDP frame transmission callback function
   LldpReceiveCallback receiveCallback;         ///<LLDP frame reception callback function
   LldpTickCallback tickCallback;               ///<Tick callback function

   bool_t running;                              ///<This flag tells whether the LLDP agent is running or not
   bool_t stop;                                 ///<Stop request
   OsMutex mutex;                               ///<Mutex preventing simultaneous access to LLDP agent context
   OsEvent event;                               ///<Event object used to poll the underlying socket
   OsTaskId taskId;                             ///<Task identifier
#if (OS_STATIC_TASK_SUPPORT == ENABLED)
   OsTaskTcb taskTcb;                           ///<Task control block
   OsStackType taskStack[LLDP_TASK_STACK_SIZE]; ///<Task stack
#endif
   Socket *socket;                              ///<Underlying socket
   systime_t timestamp;                         ///<Timestamp to manage timeout
   LldpDataUnit lldpdu;                         ///<Incoming/outgoing LLDP data unit

#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   LldpDataUnit txInfo;                         ///<Local system information
   uint_t msgTxInterval;                        ///<Interval at which LLDP frames are transmitted
   uint_t msgTxHold;                            ///<Transmit hold multiplier
   uint_t reinitDelay;                          ///<Delay before re-initialization will be attempted
   uint_t txDelay;                              ///<Delay between successive LLDP frame transmissions
   uint32_t mgmtAddrMap;                        ///<Bit-map indicating the management addresses that are configured
#endif

#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   uint32_t index;                              ///<Monotonically increasing index used to identify entries
   uint_t notificationInterval;                 ///<Notification interval
   uint_t tooManyNeighborsTimer;                ///<Too many neighbors timer
   bool_t badFrame;                             ///<Incoming failed validation and was discarded
   bool_t rxChanges;                            ///<The incoming LLDPDU has been received with different TLV values
   uint_t rxTTL;                                ///<The TTL extracted from the received LLDPDU
   bool_t somethingChangedRemote;               ///<Per-MSAP variable set after all the information has been updated
   bool_t tooManyNeighbors;                     ///<Insufficient space to store information from all neighbors
   uint32_t statsRemTablesLastChangeTime;
   uint32_t statsRemTablesInserts;
   uint32_t statsRemTablesDeletes;
   uint32_t statsRemTablesDrops;
   uint32_t statsRemTablesAgeouts;
#endif

   bool_t busy;                                 ///<Busy flag
};


//LLDP agent related functions
void lldpGetDefaultSettings(LldpAgentSettings *settings);

error_t lldpInit(LldpAgentContext *context,
   const LldpAgentSettings *settings);

error_t lldpStart(LldpAgentContext *context);
error_t lldpStop(LldpAgentContext *context);

error_t lldpSetPortAddr(LldpAgentContext *context, uint_t portIndex,
   const MacAddr *macAddr);

error_t lldpSetAdminStatus(LldpAgentContext *context, uint_t portIndex,
   LldpAdminStatus adminStatus);

error_t lldpSetBasicTlvFilter(LldpAgentContext *context, uint_t portIndex,
   uint8_t mask);

error_t lldpSetMgmtAddrFilter(LldpAgentContext *context, uint_t portIndex,
   uint32_t mask);

error_t lldpSetMsgTxInterval(LldpAgentContext *context, uint_t msgTxInterval);
error_t lldpSetMsgTxHold(LldpAgentContext *context, uint_t msgTxHold);
error_t lldpSetReinitDelay(LldpAgentContext *context, uint_t reinitDelay);
error_t lldpSetTxDelay(LldpAgentContext *context, uint_t txDelay);

error_t lldpSetLocalChassisId(LldpAgentContext *context,
   LldpChassisIdSubtype chassisIdSubtype, const void *chassisId,
   size_t chassisIdLen);

error_t lldpSetLocalPortId(LldpAgentContext *context, uint_t portIndex,
   LldpPortIdSubtype portIdSubtype, const void *portId, size_t portIdLen);

error_t lldpSetLocalPortDesc(LldpAgentContext *context, uint_t portIndex,
   const char_t *portDesc);

error_t lldpSetLocalSysName(LldpAgentContext *context, const char_t *sysName);
error_t lldpSetLocalSysDesc(LldpAgentContext *context, const char_t *sysDesc);

error_t lldpSetLocalSysCap(LldpAgentContext *context, uint16_t supportedCap,
   uint16_t enabledCap);

error_t lldpSetLocalMgmtAddr(LldpAgentContext *context, uint_t index,
   LldpMgmtAddrSubtype mgmtAddrSubtype, const void *mgmtAddr,
   size_t mgmtAddrLen, LldpIfNumSubtype ifNumSubtype, uint32_t ifNum,
   const uint8_t *oid, size_t oidLen);

error_t lldpDeleteLocalTlv(LldpAgentContext *context, LldpTlvType type);

void lldpTask(LldpAgentContext *context);

void lldpDeinit(LldpAgentContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

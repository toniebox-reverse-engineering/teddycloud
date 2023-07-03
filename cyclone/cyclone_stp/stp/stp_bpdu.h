/**
 * @file stp_bpdu.h
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

#ifndef _STP_BPDU_H
#define _STP_BPDU_H

//Dependencies
#include "stp/stp.h"

//Size of BPDUs
#define STP_TCN_BPDU_SIZE    4
#define STP_CONFIG_BPDU_SIZE 35

//Port identifier field
#define STP_PORT_PRIORITY_MASK 0xFF00
#define STP_PORT_NUM_MASK      0x00FF

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief BPDU types
 **/

typedef enum
{
   STP_BPDU_TYPE_CONFIG = 0x00,
   STP_BPDU_TYPE_TCN    = 0x80,
} StpBpduTypes;


/**
 * @brief BPDU flags
 **/

typedef enum
{
   STP_BPDU_FLAG_TC     = 0x01,
   STP_BPDU_FLAG_TC_ACK = 0x80
} StpBpduFlags;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief Spanning Tree BPDU
 **/

typedef __start_packed struct
{
   uint16_t protocolId;       //0-1
   uint8_t protocolVersionId; //2
   uint8_t bpduType;          //3
   uint8_t flags;             //4
   StpBridgeId rootId;       //5-12
   uint32_t rootPathCost;     //13-16
   StpBridgeId bridgeId;     //17-24
   uint16_t portId;           //25-26
   uint16_t messageAge;       //27-28
   uint16_t maxAge;           //29-30
   uint16_t helloTime;        //31-32
   uint16_t forwardDelay;     //33-34
} __end_packed StpBpdu;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//Bridge group address
extern const MacAddr STP_BRIDGE_GROUP_ADDR;

//STP related functions
void stpProcessLlcFrame(NetInterface *interface, EthHeader *ethHeader,
   const uint8_t *data, size_t length, NetRxAncillary *ancillary, void *param);

error_t stpProcessBpdu(StpBridgePort *port, const StpBpdu *bpdu,
   size_t length);

error_t stpSendBpdu(StpBridgePort *port, const StpBpdu *bpdu,
   size_t length);

error_t stpDumpBpdu(const StpBpdu *bpdu, size_t length);
void stpDumpFlags(uint8_t flags);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

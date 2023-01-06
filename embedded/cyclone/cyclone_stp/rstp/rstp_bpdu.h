/**
 * @file rstp_bpdu.h
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

#ifndef _RSTP_BPDU_H
#define _RSTP_BPDU_H

//Dependencies
#include "rstp/rstp.h"

//Size of BPDUs
#define RSTP_TCN_BPDU_SIZE    4
#define RSTP_CONFIG_BPDU_SIZE 35
#define RSTP_RST_BPDU_SIZE    36

//Port identifier field
#define RSTP_PORT_PRIORITY_MASK 0xF000
#define RSTP_PORT_NUM_MASK      0x0FFF

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief BPDU types
 **/

typedef enum
{
   RSTP_BPDU_TYPE_CONFIG = 0x00,
   RSTP_BPDU_TYPE_TCN    = 0x80,
   RSTP_BPDU_TYPE_RST    = 0x02,
} RstpBpduTypes;


/**
 * @brief BPDU flags
 **/

typedef enum
{
   RSTP_BPDU_FLAG_TC                   = 0x01,
   RSTP_BPDU_FLAG_PROPOSAL             = 0x02,
   RSTP_BPDU_FLAG_PORT_ROLE            = 0x0C,
   RSTP_BPDU_FLAG_PORT_ROLE_UNKNOWN    = 0x00,
   RSTP_BPDU_FLAG_PORT_ROLE_ALT_BACKUP = 0x04,
   RSTP_BPDU_FLAG_PORT_ROLE_ROOT       = 0x08,
   RSTP_BPDU_FLAG_PORT_ROLE_DESIGNATED = 0x0C,
   RSTP_BPDU_FLAG_LEARNING             = 0x10,
   RSTP_BPDU_FLAG_FORWARDING           = 0x20,
   RSTP_BPDU_FLAG_AGREEMENT            = 0x40,
   RSTP_BPDU_FLAG_TC_ACK               = 0x80
} RstpBpduFlags;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief Rapid Spanning Tree BPDU
 **/

typedef __start_packed struct
{
   uint16_t protocolId;       //0-1
   uint8_t protocolVersionId; //2
   uint8_t bpduType;          //3
   uint8_t flags;             //4
   StpBridgeId rootId;        //5-12
   uint32_t rootPathCost;     //13-16
   StpBridgeId bridgeId;      //17-24
   uint16_t portId;           //25-26
   uint16_t messageAge;       //27-28
   uint16_t maxAge;           //29-30
   uint16_t helloTime;        //31-32
   uint16_t forwardDelay;     //33-34
   uint8_t version1Length;    //35
} __end_packed RstpBpdu;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//Bridge group address
extern const MacAddr RSTP_BRIDGE_GROUP_ADDR;

//RSTP related functions
void rstpProcessLlcFrame(NetInterface *interface, EthHeader *ethHeader,
   const uint8_t *data, size_t length, NetRxAncillary *ancillary, void *param);

error_t rstpProcessBpdu(RstpBridgePort *port, const RstpBpdu *bpdu,
   size_t length);

error_t rstpValidateConfigBpdu(RstpBridgePort *port, const RstpBpdu *bpdu,
   size_t length);

error_t rstpSendBpdu(RstpBridgePort *port, const RstpBpdu *bpdu,
   size_t length);

error_t rstpDumpBpdu(const RstpBpdu *bpdu, size_t length);
void rstpDumpFlags(uint8_t flags);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

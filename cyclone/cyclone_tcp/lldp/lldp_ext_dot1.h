/**
 * @file lldp_ext_dot1.h
 * @brief IEEE 802.1 LLDP extension
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

#ifndef _LLDP_EXT_DOT1_H
#define _LLDP_EXT_DOT1_H

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"

//Minimum length of VLAN name
#define LLDP_DOT1_MIN_VLAN_NAME_LEN 1
//Maximum length of VLAN name
#define LLDP_DOT1_MAX_VLAN_NAME_LEN 31

//Minimum length of protocol identity
#define LLDP_DOT1_MIN_PROTOCOL_ID_LEN 1
//Maximum length of protocol identity
#define LLDP_DOT1_MAX_PROTOCOL_ID_LEN 255

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief IEEE 802.1 subtypes
 **/

typedef enum
{
   LLDP_DOT1_SUBTYPE_RESERVED           = 0, ///<Reserved
   LLDP_DOT1_SUBTYPE_PORT_VLAN_ID       = 1, ///<Port VLAN ID
   LLDP_DOT1_SUBTYPE_PORT_PROTO_VLAN_ID = 2, ///<Port And Protocol VLAN ID
   LLDP_DOT1_SUBTYPE_VLAN_NAME          = 3, ///<VLAN Name
   LLDP_DOT1_SUBTYPE_PROTOCOL_ID        = 4  ///<Protocol Identity
} LldpDot1Subtype;


/**
 * @brief Port and protocol capability/status flags
 **/

typedef enum
{
   LLDP_DOT1_PORT_PROTO_FLAG_RESERVED  = 0x01, ///<Reserved
   LLDP_DOT1_PORT_PROTO_FLAG_SUPPORTED = 0x02, ///<Port and protocol VLAN supported
   LLDP_DOT1_PORT_PROTO_FLAG_ENABLED   = 0x04, ///<Port and protocol VLAN enabled
} LldpDot1PortProtoFlags;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief Port VLAN ID TLV
 **/

typedef __start_packed struct
{
   uint16_t pvid;  //0-2
} __end_packed LldpDot1PortVlanIdTlv;


/**
 * @brief Port And Protocol VLAN ID TLV
 **/

typedef __start_packed struct
{
   uint8_t flags;  //0
   uint16_t ppvid; //1-2
} __end_packed LldpDot1PortProtoVlanIdTlv;


/**
 * @brief VLAN Name TLV
 **/

typedef __start_packed struct
{
   uint16_t vlanId;        //0
   uint8_t vlanNameLen; //1
   char_t vlanName[];   //2
} __end_packed LldpDot1VlanNameTlv;


/**
 * @brief Protocol Identity TLV
 **/

typedef __start_packed struct
{
   uint8_t protocolIdLen; //0
   uint8_t protocolId[];  //1
} __end_packed LldpDot1ProtocolIdTlv;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//IEEE 802.1 related functions
error_t lldpDot1SetLocalPortVlanId(LldpAgentContext *context,
   uint_t portIndex, uint16_t pvid);

error_t lldpDot1SetLocalPortProtoVlanId(LldpAgentContext *context,
   uint_t portIndex, uint8_t flags, uint16_t ppvid);

error_t lldpDot1SetLocalVlanName(LldpAgentContext *context,
   uint_t portIndex, uint16_t vlanId, const char_t *vlanName);

error_t lldpDot1SetLocalProtocolId(LldpAgentContext *context,
   uint_t portIndex, const uint8_t *protocolId, size_t protocolIdLen);

error_t lldpDot1DeleteLocalTlv(LldpAgentContext *context,
   LldpDot1Subtype subtype);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

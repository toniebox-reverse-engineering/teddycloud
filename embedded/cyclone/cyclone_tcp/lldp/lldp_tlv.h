/**
 * @file lldp_tlv.h
 * @brief TLV parsing and formatting
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

#ifndef _LLDP_TLV_H
#define _LLDP_TLV_H

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"

//Size of organizationally unique identifiers
#define LLDP_OUI_SIZE 3

//Maximum length of TLV information string
#define LLDP_MAX_TLV_INFO_LEN 511
//Maximum length of organizationally defined information string
#define LLDP_MAX_ORG_SPECIFIC_INFO_LEN 507

//Minimum length of chassis ID
#define LLDP_MIN_CHASSIS_ID_LEN 1
//Maximum length of chassis ID
#define LLDP_MAX_CHASSIS_ID_LEN 255

//Minimum length of port ID
#define LLDP_MIN_PORT_ID_LEN 1
//Maximum length of port ID
#define LLDP_MAX_PORT_ID_LEN 255

//Minimum length of port description
#define LLDP_MIN_PORT_DESC_LEN 1
//Maximum length of port description
#define LLDP_MAX_PORT_DESC_LEN 255

//Minimum length of system name
#define LLDP_MIN_SYS_NAME_LEN 1
//Maximum length of system name
#define LLDP_MAX_SYS_NAME_LEN 255

//Minimum length of system description
#define LLDP_MIN_SYS_DESC_LEN 1
//Maximum length of system description
#define LLDP_MAX_SYS_DESC_LEN 255

//Minimum length of management address
#define LLDP_MIN_MGMT_ADDR_LEN 1
//Maximum length of management address
#define LLDP_MAX_MGMT_ADDR_LEN 31

//Minimum length of object identifier
#define LLDP_MIN_OID_LEN 0
//Maximum length of object identifier
#define LLDP_MAX_OID_LEN 128

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief TLV type values
 **/

typedef enum
{
   LLDP_TLV_TYPE_END_OF_LLDPDU = 0,  ///<End Of LLDPDU
   LLDP_TLV_TYPE_CHASSIS_ID    = 1,  ///<Chassis ID
   LLDP_TLV_TYPE_PORT_ID       = 2,  ///<Port ID
   LLDP_TLV_TYPE_TIME_TO_LIVE  = 3,  ///<Time To Live
   LLDP_TLV_TYPE_PORT_DESC     = 4,  ///<Port Description
   LLDP_TLV_TYPE_SYS_NAME      = 5,  ///<System Name
   LLDP_TLV_TYPE_SYS_DESC      = 6,  ///<System Description
   LLDP_TLV_TYPE_SYS_CAP       = 7,  ///<System Capabilities
   LLDP_TLV_TYPE_MGMT_ADDR     = 8,  ///<Management Address
   LLDP_TLV_TYPE_ORG_DEFINED   = 127 ///<Organizationally Specific TLVs
} LldpTlvType;


/**
 * @brief Chassis ID subtypes
 **/

typedef enum
{
   LLDP_CHASSIS_ID_SUBTYPE_RESERVED          = 0, ///<Reserved
   LLDP_CHASSIS_ID_SUBTYPE_CHASSIS_COMPONENT = 1, ///<Chassis component
   LLDP_CHASSIS_ID_SUBTYPE_INTERFACE_ALIAS   = 2, ///<Interface alias
   LLDP_CHASSIS_ID_SUBTYPE_PORT_COMPONENT    = 3, ///<Port component
   LLDP_CHASSIS_ID_SUBTYPE_MAC_ADDR          = 4, ///<MAC address
   LLDP_CHASSIS_ID_SUBTYPE_NETWORK_ADDR      = 5, ///<Network address
   LLDP_CHASSIS_ID_SUBTYPE_INTERFACE_NAME    = 6, ///<Interface name
   LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED  = 7  ///<Locally assigned
} LldpChassisIdSubtype;


/**
 * @brief Port ID subtypes
 **/

typedef enum
{
   LLDP_PORT_ID_SUBTYPE_RESERVED         = 0, ///<Reserved
   LLDP_PORT_ID_SUBTYPE_INTERFACE_ALIAS  = 1, ///<Interface alias
   LLDP_PORT_ID_SUBTYPE_PORT_COMPONENT   = 2, ///<Port component
   LLDP_PORT_ID_SUBTYPE_MAC_ADDR         = 3, ///<MAC address
   LLDP_PORT_ID_SUBTYPE_NETWORK_ADDR     = 4, ///<Network address
   LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME   = 5, ///<Interface name
   LLDP_PORT_ID_SUBTYPE_AGENT_CIRCUIT_ID = 6, ///<Agent circuit ID
   LLDP_PORT_ID_SUBTYPE_LOCALLY_ASSIGNED = 7  ///<Locally assigned
} LldpPortIdSubtype;


/**
 * @brief System capabilities
 **/

typedef enum
{
   LLDP_SYS_CAP_OTHER               = 0x0001, ///<Other
   LLDP_SYS_CAP_REPEATER            = 0x0002, ///<Repeater
   LLDP_SYS_CAP_BRIDGE              = 0x0004, ///<Bridge
   LLDP_SYS_CAP_WLAN_ACCESS_POINT   = 0x0008, ///<WLAN Access Point
   LLDP_SYS_CAP_ROUTER              = 0x0010, ///<Router
   LLDP_SYS_CAP_TELEPHONE           = 0x0020, ///<Telephone
   LLDP_SYS_CAP_DOCSIS_CABLE_DEVICE = 0x0040, ///<DOCSIS cable device
   LLDP_SYS_CAP_STATION_ONLY        = 0x0080  ///<Station Only
} LldpSysCap;


/**
 * @brief Management address subtypes
 **/

typedef enum
{
   LLDP_MGMT_ADDR_SUBTYPE_OTHER   = 0, ///<Other
   LLDP_MGMT_ADDR_SUBTYPE_IPV4    = 1, ///<IPv4 address
   LLDP_MGMT_ADDR_SUBTYPE_IPV6    = 2, ///<IPv6 address
   LLDP_MGMT_ADDR_SUBTYPE_ALL_802 = 6  ///<MAC address
} LldpMgmtAddrSubtype;


/**
 * @brief Interface numbering subtypes
 **/

typedef enum
{
   LLDP_IF_NUM_SUBTYPE_UNKNOWN      = 1, ///<Unknown
   LLDP_IF_NUM_SUBTYPE_IF_INDEX     = 2, ///<Interface index
   LLDP_IF_NUM_SUBTYPE_SYS_PORT_NUM = 3  ///<System port number
} LldpIfNumSubtype;


/**
 * @brief Organizationally unique identifiers
 **/

typedef enum
{
   LLDP_DOT1_OUI = 0x0080C2, ///<IEEE 802.1
   LLDP_DOT3_OUI = 0x00120F, ///<IEEE 802.3
   LLDP_MED_OUI  = 0x0012BB, ///<LLDP-MED
   LLDP_PNO_OUI  = 0x000ECF  ///<PROFIBUS
} LldpOui;


/**
 * @brief TLV structure
 **/

typedef struct
{
   size_t pos;
   uint8_t type;
   size_t length;
   uint8_t *value;
} LldpTlv;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief TLV header
 **/

typedef __start_packed struct
{
#if defined(_CPU_BIG_ENDIAN) && !defined(__ICCRX__)
   uint8_t type : 7;    //0
   uint8_t lengthH : 1;
   uint8_t lengthL;     //1
   uint8_t value[];     //2
#else
   uint8_t lengthH : 1; //0
   uint8_t type : 7;
   uint8_t lengthL;     //1
   uint8_t value[];     //2
#endif
} __end_packed LldpTlvHeader;


/**
 * @brief Chassis ID TLV
 **/

typedef __start_packed struct
{
   uint8_t chassisIdSubtype; //0
   uint8_t chassisId[];      //1
} __end_packed LldpChassisIdTlv;


/**
 * @brief Port ID TLV
 **/

typedef __start_packed struct
{
   uint8_t portIdSubtype; //0
   uint8_t portId[];      //1
} __end_packed LldpPortIdTlv;


/**
 * @brief Time To Live TLV
 **/

typedef __start_packed struct
{
   uint16_t ttl; //0-1
} __end_packed LldpTimeToLiveTlv;


/**
 * @brief System Capabilities TLV
 **/

typedef __start_packed struct
{
   uint16_t supportedCap; //0-1
   uint16_t enabledCap;   //2-3
} __end_packed LldpSysCapTlv;


/**
 * @brief Management Address TLV (part 1)
 **/

typedef __start_packed struct
{
   uint8_t mgmtAddrLen;     //0
   uint8_t mgmtAddrSubtype; //1
   uint8_t mgmtAddr[];      //2
} __end_packed LldpMgmtAddrTlv1;


/**
 * @brief Management Address TLV (part 2)
 **/

typedef __start_packed struct
{
   uint8_t ifNumSubtype; //0
   uint32_t ifNum;       //1-4
   uint8_t oidLen;       //5
   uint8_t oid[];        //6
} __end_packed LldpMgmtAddrTlv2;


/**
 * @brief Organizationally Specific TLV
 **/

typedef __start_packed struct
{
   uint8_t oui[LLDP_OUI_SIZE]; //0-2
   uint8_t subtype;            //3
   uint8_t value[];            //4
} __end_packed LldpOrgDefTlv;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//LLDP related functions
error_t lldpSetTlv(LldpDataUnit *lldpdu, uint8_t type, uint_t index,
   const uint8_t *value, size_t length, bool_t replace);

error_t lldpGetTlv(LldpDataUnit *lldpdu, uint8_t type, uint_t index,
   const uint8_t **value, size_t *length);

error_t lldpGetFirstTlv(LldpDataUnit *lldpdu, LldpTlv *tlv);
error_t lldpGetNextTlv(LldpDataUnit *lldpdu, LldpTlv *tlv);

error_t lldpDeleteTlv(LldpDataUnit *lldpdu, uint8_t type, uint_t index);

error_t lldpDecodeMgmtAddrTlv(const uint8_t *value, size_t length,
   const LldpMgmtAddrTlv1 **mgmtAddr1, const LldpMgmtAddrTlv2 **mgmtAddr2);

error_t lldpSetOrgDefTlv(LldpDataUnit *lldpdu, uint32_t oui, uint8_t subtype,
   uint_t index, const uint8_t *value, size_t length, bool_t replace);

error_t lldpGetOrgDefTlv(LldpDataUnit *lldpdu, uint32_t oui, uint8_t subtype,
   uint_t index, const uint8_t **value, size_t *length);

error_t lldpDeleteOrgDefTlv(LldpDataUnit *lldpdu, uint32_t oui, uint8_t subtype,
   uint_t index);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

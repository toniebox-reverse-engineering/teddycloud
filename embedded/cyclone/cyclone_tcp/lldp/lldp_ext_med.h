/**
 * @file lldp_ext_med.h
 * @brief LLDP-MED extension (LLDP for Media Endpoint Devices)
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

#ifndef _LLDP_EXT_MED_H
#define _LLDP_EXT_MED_H

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"

//Minimum length of hardware revision
#define LLDP_MED_MIN_INVENTORY_STRING_LEN 0
//Maximum length of hardware revision
#define LLDP_MED_MAX_INVENTORY_STRING_LEN 32

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief LLDP-MED subtypes
 **/

typedef enum
{
   LLDP_MED_SUBTYPE_RESERVED          = 0,  ///<Reserved
   LLDP_MED_SUBTYPE_LLDP_MED_CAP      = 1,  ///<LLDP-MED Capabilities
   LLDP_MED_SUBTYPE_NETWORK_POLICY    = 2,  ///<Network Policy
   LLDP_MED_SUBTYPE_LOCATION_ID       = 3,  ///<Location Identification
   LLDP_MED_SUBTYPE_EXT_POWER_VIA_MDI = 4,  ///<Extended Power-via-MDI
   LLDP_MED_SUBTYPE_HARDWARE_REVISION = 5,  ///<Inventory - Hardware Revision
   LLDP_MED_SUBTYPE_FIRMWARE_REVISION = 6,  ///<Inventory - Firmware Revision
   LLDP_MED_SUBTYPE_SOFTWARE_REVISION = 7,  ///<Inventory - Software Revision
   LLDP_MED_SUBTYPE_SERIAL_NUMBER     = 8,  ///<Inventory - Serial Number
   LLDP_MED_SUBTYPE_MANUFACTURER_NAME = 9,  ///<Inventory - Manufacturer Name
   LLDP_MED_SUBTYPE_MODEL_NAME        = 10, ///<Inventory - Model Name
   LLDP_MED_SUBTYPE_ASSET_ID          = 11  ///<Inventory - Asset ID
} LldpMedSubtype;


/**
 * @brief LLDP-MED capabilities
 **/

typedef enum
{
   LLDP_MED_CAP                = 0x0001, ///<LLDP-MED capabilities
   LLDP_MED_CAP_NETWORK_POLICY = 0x0002, ///<Network policy
   LLDP_MED_CAP_LOCATION       = 0x0004, ///<Location identification
   LLDP_MED_CAP_EXTENDED_PSE   = 0x0008, ///<Extended power via MDI - PSE
   LLDP_MED_CAP_EXTENDED_PD    = 0x0010, ///<Extended power via MDI - PD
   LLDP_MED_CAP_INVENTORY      = 0x0020  ///<Inventory
} LldpMedCap;


/**
 * @brief LLDP-MED device type
 **/

typedef enum
{
   LLDP_MED_DEVICE_TYPE_NOT_DEFINED          = 0, ///<Type not defined
   LLDP_MED_DEVICE_TYPE_ENDPOINT_CLASS_1     = 1, ///<Endpoint class I
   LLDP_MED_DEVICE_TYPE_ENDPOINT_CLASS_2     = 2, ///<Endpoint class II
   LLDP_MED_DEVICE_TYPE_ENDPOINT_CLASS_3     = 3, ///<Endpoint class III
   LLDP_MED_DEVICE_TYPE_NETWORK_CONNECTIVITY = 4  ///<Network connectivity
} LldpMedDeviceType;


/**
 * @brief Application type
 **/

typedef enum
{
   LLDP_MED_APP_TYPE_RESERVED              = 0, ///<Reserved
   LLDP_MED_APP_TYPE_VOICE                 = 1, ///<Voice
   LLDP_MED_APP_TYPE_VOICE_SIGNALING       = 2, ///<Voice signaling
   LLDP_MED_APP_TYPE_GUEST_VOICE           = 3, ///<Guest Voice
   LLDP_MED_APP_TYPE_GUEST_VOICE_SIGNALING = 4, ///<Guest Voice Signaling
   LLDP_MED_APP_TYPE_SOFTPHONE_VOICE       = 5, ///<Softphone Voice
   LLDP_MED_APP_TYPE_VIDEO_CONFERENCING    = 6, ///<Video Conferencing
   LLDP_MED_APP_TYPE_STREAMING_VIDEO       = 7, ///<Streaming Video
   LLDP_MED_APP_TYPE_VIDEO_SIGNALING       = 8  ///<Video signaling
} LldpMedAppType;


/**
 * @brief Location data format
 **/

typedef enum
{
   LLDP_MED_LOCATION_DATA_FORMAT_INVALID         = 0, ///<Invalid
   LLDP_MED_LOCATION_DATA_FORMAT_COORD_BASED_LCI = 1, ///<Coordinate-based LCI
   LLDP_MED_LOCATION_DATA_FORMAT_CIVIC_ADDR_LCI  = 2, ///<Civic Address LCI
   LLDP_MED_LOCATION_DATA_FORMAT_ECS_ELIN        = 3  ///<ECS ELIN
} LldpMedLocationDataFormat;


/**
 * @brief Power type
 **/

typedef enum
{
   LLDP_MED_POWER_TYPE_PSE_DEVICE = 0, ///<PSE Device
   LLDP_MED_POWER_TYPE_PD_DEVICE  = 1, ///<PD Device
   LLDP_MED_POWER_TYPE_RESERVED_1 = 2, ///<Reserved
   LLDP_MED_POWER_TYPE_RESERVED_2 = 3  ///<Reserved
} LldpMedPowerType;


/**
 * @brief Power source
 **/

typedef enum
{
   LLDP_MED_PD_POWER_SOURCE_UNKNOWN       = 0, ///<Unknown (PD device type)
   LLDP_MED_PD_POWER_SOURCE_PSE           = 1, ///<PSE (PD device type)
   LLDP_MED_PD_POWER_SOURCE_LOCAL         = 2, ///<Local (PD device type)
   LLDP_MED_PD_POWER_SOURCE_PSE_AND_LOCAL = 3, ///<PSE and local (PD device type)
   LLDP_MED_PSE_POWER_SOURCE_UNKNOWN      = 0, ///<Unknown (PSE device type)
   LLDP_MED_PSE_POWER_SOURCE_PRIMARY      = 1, ///<Primary Power Source (PSE device type)
   LLDP_MED_PSE_POWER_SOURCE_BACKUP       = 2, ///<Backup Power Source (PSE device type)
   LLDP_MED_PSE_POWER_SOURCE_RESERVED     = 3  ///<Reserved (PSE device type)
} LldpMedPowerSource;


/**
 * @brief Power priority
 **/

typedef enum
{
   LLDP_MED_POWER_PRIORITY_UNKNOWN  = 0, ///<Unknown
   LLDP_MED_POWER_PRIORITY_CRITICAL = 1, ///<Critical
   LLDP_MED_POWER_PRIORITY_HIGH     = 2, ///<High
   LLDP_MED_POWER_PRIORITY_LOW      = 3  ///<Low
} LldpMedPowerPriority;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief LLDP-MED Capabilities TLV
 **/

typedef __start_packed struct
{
   uint16_t capabilities; //0-1
   uint8_t deviceType;    //2
} __end_packed LldpMedCapTlv;


/**
 * @brief Network Policy TLV
 **/

typedef __start_packed struct
{
#if defined(_CPU_BIG_ENDIAN) && !defined(__ICCRX__)
   uint8_t appType;         //0
   uint8_t u : 1;           //1
   uint8_t t : 1;
   uint8_t x : 1;
   uint8_t vlanIdH : 5;
   uint8_t vlanIdL : 7;     //2
   uint8_t l2PriorityH : 1;
   uint8_t l2PriorityL : 2; //3
   uint8_t dscpValue : 6;
#else
   uint8_t appType;         //0
   uint8_t vlanIdH : 5;     //1
   uint8_t x : 1;
   uint8_t t : 1;
   uint8_t u : 1;
   uint8_t l2PriorityH : 1; //2
   uint8_t vlanIdL : 7;
   uint8_t dscpValue : 6;   //3
   uint8_t l2PriorityL : 2;
#endif
} __end_packed LldpMedNetworkPolicyTlv;


/**
 * @brief Location Identification TLV
 **/

typedef __start_packed struct
{
   uint8_t locationDataFormat; //0-1
   uint8_t locationId[];       //2
} __end_packed LldpMedLocationIdTlv;


/**
 * @brief Extended Power-Via-MDI TLV
 **/

typedef __start_packed struct
{
#if defined(_CPU_BIG_ENDIAN) && !defined(__ICCRX__)
   uint8_t powerType : 2;     //0
   uint8_t powerSource : 2;
   uint8_t powerPriority : 4;
   uint16_t powerValue;       //1-2
#else
   uint8_t powerPriority : 4; //0
   uint8_t powerSource : 2;
   uint8_t powerType : 2;
   uint16_t powerValue;       //1-2
#endif
} __end_packed LldpMedExtPowerViaMdiTlv;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//LLDP-MED related functions
error_t lldpMedSetLocalCap(LldpAgentContext *context, uint16_t capabilities,
   LldpMedDeviceType deviceType);

error_t lldpMedSetLocalNetworkPolicy(LldpAgentContext *context,
   uint_t portIndex, LldpMedAppType appType, bool_t u, bool_t t,
   uint16_t vlanId, uint8_t l2Priority, uint8_t dscpValue);

error_t lldpMedSetLocalLocationId(LldpAgentContext *context,
   uint_t portIndex, LldpMedLocationDataFormat locationDataFormat,
   const void *locationId, size_t locationIdLen);

error_t lldpMedSetLocalExtPowerViaMdi(LldpAgentContext *context,
   uint_t portIndex, LldpMedPowerType powerType, LldpMedPowerSource powerSource,
   LldpMedPowerPriority powerPriority, uint16_t powerValue);

error_t lldpMedSetLocalHardwareRevision(LldpAgentContext *context,
   const char_t *hardwareRevision);

error_t lldpMedSetLocalFirmwareRevision(LldpAgentContext *context,
   const char_t *firmwareRevision);

error_t lldpMedSetLocalSoftwareRevision(LldpAgentContext *context,
   const char_t *softwareRevision);

error_t lldpMedSetLocalSerialNumber(LldpAgentContext *context,
   const char_t *serialNumber);

error_t lldpMedSetLocalManufacturerName(LldpAgentContext *context,
   const char_t *manufacturerName);

error_t lldpMedSetLocalModelName(LldpAgentContext *context,
   const char_t *modelName);

error_t lldpMedSetLocalAssetId(LldpAgentContext *context,
   const char_t *assetId);

error_t lldpMedDeleteLocalTlv(LldpAgentContext *context,
   LldpMedSubtype subtype);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

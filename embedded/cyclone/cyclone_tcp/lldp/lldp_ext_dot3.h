/**
 * @file lldp_ext_dot3.h
 * @brief IEEE 802.3 LLDP extension
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

#ifndef _LLDP_EXT_DOT3_H
#define _LLDP_EXT_DOT3_H

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief IEEE 802.3 subtypes
 **/

typedef enum
{
   LLDP_DOT3_SUBTYPE_RESERVED              = 0, ///<Reserved
   LLDP_DOT3_SUBTYPE_MAC_PHY_CONFIG_STATUS = 1, ///<MAC/PHY Configuration/Status
   LLDP_DOT3_SUBTYPE_POWER_VIA_MDI         = 2, ///<Power Via MDI
   LLDP_DOT3_SUBTYPE_LINK_AGGREGATION      = 3, ///<Link Aggregation
   LLDP_DOT3_SUBTYPE_MAX_FRAME_SIZE        = 4, ///<Maximum Frame Size
   LLDP_DOT3_SUBTYPE_POWER_VIA_MDI_MEAS    = 8  ///<Power Via MDI Measurements
} LldpDot3Subtype;


/**
 * @brief Auto-negotiation support/status flags
 **/

typedef enum
{
   LLDP_DOT3_AN_FLAG_SUPPORT = 0x01, ///<Auto-negotiation support
   LLDP_DOT3_AN_FLAG_STATUS  = 0x02  ///<Auto-negotiation status
} LldpDot3AnFlags;


/**
 * @brief PMD auto-negotiation advertised capability
 **/

typedef enum
{
   LLDP_DOT3_PMD_AN_ADV_CAP_OTHER          = 0x8000, ///<Other or unknown
   LLDP_DOT3_PMD_AN_ADV_CAP_10BT_HD        = 0x4000, ///<10BASE-T half-duplex mode
   LLDP_DOT3_PMD_AN_ADV_CAP_10BT_FD        = 0x2000, ///<10BASE-T full-duplex mode
   LLDP_DOT3_PMD_AN_ADV_CAP_100BT4         = 0x1000, ///<100BASE-T4
   LLDP_DOT3_PMD_AN_ADV_CAP_100BT_HD       = 0x0800, ///<100BASE-TX half-duplex mode
   LLDP_DOT3_PMD_AN_ADV_CAP_100BT_FD       = 0x0400, ///<100BASE-TX full-duplex mode
   LLDP_DOT3_PMD_AN_ADV_CAP_100BT2_HD      = 0x0200, ///<100BASE-T2 half-duplex mode
   LLDP_DOT3_PMD_AN_ADV_CAP_100BT2_FD      = 0x0100, ///<100BASE-T2 full-duplex mode
   LLDP_DOT3_PMD_AN_ADV_CAP_PAUSE          = 0x0080, ///<PAUSE for full-duplex links
   LLDP_DOT3_PMD_AN_ADV_CAP_ASYM_PAUSE     = 0x0040, ///<Asymmetric PAUSE for full-duplex links
   LLDP_DOT3_PMD_AN_ADV_CAP_SYM_PAUSE      = 0x0020, ///<Symmetric PAUSE for full-duplex links
   LLDP_DOT3_PMD_AN_ADV_CAP_ASYM_SYM_PAUSE = 0x0010, ///<Asymmetric and Symmetric PAUSE for full-duplex links
   LLDP_DOT3_PMD_AN_ADV_CAP_1000BX_HD      = 0x0008, ///<1000BASE-X, -LX, -SX, -CX half-duplex mode
   LLDP_DOT3_PMD_AN_ADV_CAP_1000BX_FD      = 0x0004, ///<1000BASE-X, -LX, -SX, -CX full-duplex mode
   LLDP_DOT3_PMD_AN_ADV_CAP_1000BT_HD      = 0x0002, ///<1000BASE-T half-duplex mode
   LLDP_DOT3_PMD_AN_ADV_CAP_1000BT_FD      = 0x0001  ///<1000BASE-T full-duplex mode
} LldpDot3PmdAnAdvCapability;


/**
 * @brief Operational MAU types
 **/

typedef enum
{
   LLDP_DOT3_MAU_TYPE_INVALID   = 0,   ///<Invalid
   LLDP_DOT3_MAU_TYPE_10BT_HD   = 10,  ///<dot3MauType10BaseTHD
   LLDP_DOT3_MAU_TYPE_10BT_FD   = 11,  ///<dot3MauType10BaseTFD
   LLDP_DOT3_MAU_TYPE_100BT4    = 14,  ///<dot3MauType100BaseT4
   LLDP_DOT3_MAU_TYPE_100BTX_HD = 15,  ///<dot3MauType100BaseTXHD
   LLDP_DOT3_MAU_TYPE_100BTX_FD = 16,  ///<dot3MauType100BaseTXFD
   LLDP_DOT3_MAU_TYPE_100BT2_HD = 19,  ///<dot3MauType100BaseT2HD
   LLDP_DOT3_MAU_TYPE_100BT2_FD = 20,  ///<dot3MauType100BaseT2FD
   LLDP_DOT3_MAU_TYPE_1000BX_HD = 21,  ///<dot3MauType1000BaseXHD
   LLDP_DOT3_MAU_TYPE_1000BX_FD = 22,  ///<dot3MauType1000BaseXFD
   LLDP_DOT3_MAU_TYPE_1000BT_HD = 29,  ///<dot3MauType1000BaseTHD
   LLDP_DOT3_MAU_TYPE_1000BT_FD = 30,  ///<dot3MauType1000BaseTFD
   LLDP_DOT3_MAU_TYPE_100BT1    = 105, ///<dot3MauType100baseT1
   LLDP_DOT3_MAU_TYPE_10BT1L    = 141  ///<dot3MauType10baseT1L
} LldpDot3MauType;


/**
 * @brief MDI power capability/status flags
 **/

typedef enum
{
   LLDP_DOT3_MDI_POWER_FLAG_PORT_CLASS             = 0x01, ///<Port class
   LLDP_DOT3_MDI_POWER_FLAG_PORT_CLASS_PD          = 0x00, ///<Port class - PD
   LLDP_DOT3_MDI_POWER_FLAG_PORT_CLASS_PSE         = 0x01, ///<Port class - PSE
   LLDP_DOT3_MDI_POWER_FLAG_PSE_MDI_POWER_SUPPORT  = 0x02, ///<PSE MDI power support
   LLDP_DOT3_MDI_POWER_FLAG_PSE_MDI_POWER_STATE    = 0x04, ///<PSE MDI power state
   LLDP_DOT3_MDI_POWER_FLAG_PSE_PAIRS_CTRL_ABILITY = 0x08, ///<PSE pairs control ability
} LldpDot3MdiPowerFlags;


/**
 * @brief PSE power pair
 **/

typedef enum
{
   LLDP_DOT3_PSE_POWER_PAIR_SIGNAL = 1, ///<Signal
   LLDP_DOT3_PSE_POWER_PAIR_SPARE  = 2, ///<Spare
   LLDP_DOT3_PSE_POWER_PAIR_ALT_A  = 1, ///<Alternative A
   LLDP_DOT3_PSE_POWER_PAIR_ALT_B  = 2  ///<Alternative B
} LldpDot3PsePowerPair;


/**
 * @brief power class
 **/

typedef enum
{
   LLDP_DOT3_POWER_CLASS_0 = 1, ///<Class 0 PD
   LLDP_DOT3_POWER_CLASS_1 = 2, ///<Class 1 PD
   LLDP_DOT3_POWER_CLASS_2 = 3, ///<Class 2 PD
   LLDP_DOT3_POWER_CLASS_3 = 4, ///<Class 3 PD
   LLDP_DOT3_POWER_CLASS_4 = 5  ///<Class 4 and above PD
} LldpDot3PowerClass;


/**
 * @brief power type
 **/

typedef enum
{
   LLDP_DOT3_POWER_TYPE_2_PSE = 0, ///<Type 2 PSE
   LLDP_DOT3_POWER_TYPE_2_PD  = 1, ///<Type 2 PD
   LLDP_DOT3_POWER_TYPE_1_PSE = 2, ///<Type 1 PSE
   LLDP_DOT3_POWER_TYPE_1_PD  = 3  ///<Type 1 PD
} LldpDot3PowerType;


/**
 * @brief power source
 **/

typedef enum
{
   LLDP_DOT3_PD_POWER_SOURCE_UNKNOWN       = 0, ///<Unknown (PD device type)
   LLDP_DOT3_PD_POWER_SOURCE_PSE           = 1, ///<PSE (PD device type)
   LLDP_DOT3_PD_POWER_SOURCE_RESERVED      = 2, ///<Reserved (PD device type)
   LLDP_DOT3_PD_POWER_SOURCE_PSE_AND_LOCAL = 3, ///<PSE and local (PD device type)
   LLDP_DOT3_PSE_POWER_SOURCE_UNKNOWN      = 0, ///<Unknown (PSE device type)
   LLDP_DOT3_PSE_POWER_SOURCE_PRIMARY      = 1, ///<Primary power source (PSE device type)
   LLDP_DOT3_PSE_POWER_SOURCE_BACKUP       = 2, ///<Backup source (PSE device type)
   LLDP_DOT3_PSE_POWER_SOURCE_RESERVED     = 3  ///<Reserved (PSE device type)
} LldpDot3PowerSource;


/**
 * @brief Power priority
 **/

typedef enum
{
   LLDP_DOT3_POWER_PRIORITY_UNKNOWN  = 0, ///<Unknown
   LLDP_DOT3_POWER_PRIORITY_CRITICAL = 1, ///<Critical
   LLDP_DOT3_POWER_PRIORITY_HIGH     = 2, ///<High
   LLDP_DOT3_POWER_PRIORITY_LOW      = 3  ///<Low
} LldpDot3PowerPriority;


/**
 * @brief Power status
 **/

typedef enum
{
   LLDP_DOT3_POWER_STATUS_POWER_CLASS_EXT                             = 0x000F,
   LLDP_DOT3_POWER_STATUS_POWER_CLASS_EXT_CLASS_1                     = 0x0001,
   LLDP_DOT3_POWER_STATUS_POWER_CLASS_EXT_CLASS_2                     = 0x0002,
   LLDP_DOT3_POWER_STATUS_POWER_CLASS_EXT_CLASS_3                     = 0x0003,
   LLDP_DOT3_POWER_STATUS_POWER_CLASS_EXT_CLASS_4                     = 0x0004,
   LLDP_DOT3_POWER_STATUS_POWER_CLASS_EXT_CLASS_5                     = 0x0005,
   LLDP_DOT3_POWER_STATUS_POWER_CLASS_EXT_CLASS_6                     = 0x0006,
   LLDP_DOT3_POWER_STATUS_POWER_CLASS_EXT_CLASS_7                     = 0x0007,
   LLDP_DOT3_POWER_STATUS_POWER_CLASS_EXT_CLASS_8                     = 0x0008,
   LLDP_DOT3_POWER_STATUS_POWER_CLASS_EXT_DUAL_SIGN_PD                = 0x000F,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_B                 = 0x0070,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_B_CLASS_1         = 0x0010,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_B_CLASS_2         = 0x0020,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_B_CLASS_3         = 0x0030,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_B_CLASS_4         = 0x0040,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_B_CLASS_5         = 0x0050,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_B_SINGLE_SIGN_PD  = 0x0070,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_B_2_PAIR_ONLY_PSE = 0x0070,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_A                 = 0x0380,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_A_CLASS_1         = 0x0080,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_A_CLASS_2         = 0x0100,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_A_CLASS_3         = 0x0180,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_A_CLASS_4         = 0x0200,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_A_CLASS_5         = 0x0280,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_A_SINGLE_SIGN_PD  = 0x0380,
   LLDP_DOT3_POWER_STATUS_DUAL_SIGN_POWER_CLASS_EXT_A_2_PAIR_ONLY_PSE = 0x0380,
   LLDP_DOT3_POWER_STATUS_PSE_POWER_PAIRS_EXT                         = 0x0C00,
   LLDP_DOT3_POWER_STATUS_PSE_POWER_PAIRS_EXT_ALT_A                   = 0x0400,
   LLDP_DOT3_POWER_STATUS_PSE_POWER_PAIRS_EXT_ALT_B                   = 0x0800,
   LLDP_DOT3_POWER_STATUS_PSE_POWER_PAIRS_EXT_BOTH                    = 0x0C00,
   LLDP_DOT3_POWER_STATUS_PD_POWERED_STATUS                           = 0x3000,
   LLDP_DOT3_POWER_STATUS_PD_POWERED_STATUS_SINGLE_SIGN_PD            = 0x1000,
   LLDP_DOT3_POWER_STATUS_PD_POWERED_STATUS_2_PAIR_DUAL_SIGN_PD       = 0x2000,
   LLDP_DOT3_POWER_STATUS_PD_POWERED_STATUS_4_PAIR_DUAL_SIGN_PD       = 0x3000,
   LLDP_DOT3_POWER_STATUS_PSE_POWERING_STATUS                         = 0xC000,
   LLDP_DOT3_POWER_STATUS_PSE_POWERING_STATUS_2_PAIR                  = 0x4000,
   LLDP_DOT3_POWER_STATUS_PSE_POWERING_STATUS_4_PAIR_SINGLE_SIGN_PD   = 0x8000,
   LLDP_DOT3_POWER_STATUS_PSE_POWERING_STATUS_4_PAIR_DUAL_SIGN_PD     = 0xC000
} LldpDot3PowerStatus;


/**
 * @brief System setup
 **/

typedef enum
{
   LLDP_DOT3_SYSTEM_SETUP_PD_LOAD                              = 0x01,
   LLDP_DOT3_SYSTEM_SETUP_POWER_TYPE_EXT                       = 0x0E,
   LLDP_DOT3_SYSTEM_SETUP_POWER_TYPE_EXT_TYPE_3_PSE            = 0x00,
   LLDP_DOT3_SYSTEM_SETUP_POWER_TYPE_EXT_TYPE_4_PSE            = 0x02,
   LLDP_DOT3_SYSTEM_SETUP_POWER_TYPE_EXT_TYPE_3_SINGLE_SIGN_PD = 0x04,
   LLDP_DOT3_SYSTEM_SETUP_POWER_TYPE_EXT_TYPE_3_DUAL_SIGN_PD   = 0x06,
   LLDP_DOT3_SYSTEM_SETUP_POWER_TYPE_EXT_TYPE_4_SINGLE_SIGN_PD = 0x08,
   LLDP_DOT3_SYSTEM_SETUP_POWER_TYPE_EXT_TYPE_4_DUAL_SIGN_PD   = 0x0A,
   LLDP_DOT3_SYSTEM_SETUP_POWER_TYPE_RESERVED                  = 0xF0
} LldpDot3SystemSetup;


/**
 * @brief Autoclass field
 **/

typedef enum
{
   LLDP_DOT3_AUTOCLASS_REQUEST     = 0x01,
   LLDP_DOT3_AUTOCLASS_COMPLETED   = 0x02,
   LLDP_DOT3_AUTOCLASS_PSE_SUPPORT = 0x04,
   LLDP_DOT3_AUTOCLASS_RESERVED    = 0xF8
} LldpDot3Autoclass;


/**
 * @brief Power down field
 **/

typedef enum
{
   LLDP_DOT3_POWER_DOWN_REQUEST = 0x740000,
   LLDP_DOT3_POWER_DOWN_TIME    = 0x03FFFF
} LldpDot3PowerDown;


/**
 * @brief Link aggregation capability/status flags
 **/

typedef enum
{
   LLDP_DOT3_LINK_AGGREGATION_FLAG_CAP    = 0x01, ///<Aggregation capability
   LLDP_DOT3_LINK_AGGREGATION_FLAG_STATUS = 0x02, ///<Aggregation status
} LldpDot3LinkAggregationFlag;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief MAC/PHY Configuration/Status TLV
 **/

typedef __start_packed struct
{
   uint8_t autoNegSupportStatus; //0
   uint16_t pmdAutoNegAdvCap;    //1-2
   uint16_t operationalMauType;  //3-4
} __end_packed LldpDot3MacPhyConfigStatusTlv;


/**
 * @brief Power Via MDI TLV
 **/

typedef __start_packed struct
{
   uint8_t mdiPowerSupport; //0
   uint8_t psePowerPair;    //1
   uint8_t powerClass;      //2
} __end_packed LldpDot3PowerViaMdiTlv;


/**
 * @brief Link Aggregation TLV
 **/

typedef __start_packed struct
{
   uint8_t aggregationStatus; //0
   uint32_t aggregatedPortId; //2-5
} __end_packed LldpDot3LinkAggregationTlv;


/**
 * @brief Maximum Frame Size TLV
 **/

typedef __start_packed struct
{
   uint16_t maxFrameSize; //0-1
} __end_packed LldpDot3MaxFrameSizeTlv;


/**
 * @brief Power Via MDI Measurements TLV
 **/

typedef __start_packed struct
{
   uint8_t measurements[20];    //0-19
   uint16_t psePowerPriceIndex; //20-21
} __end_packed LldpDot3PowerViaMdiMeasTlv;


/**
 * @brief DLL Classification extension
 **/

typedef __start_packed struct
{
#if defined(_CPU_BIG_ENDIAN) && !defined(__ICCRX__)
   uint8_t powerType : 2;      //0
   uint8_t powerSource : 2;
   uint8_t reserved : 1;
   uint8_t pd4pid : 1;
   uint8_t powerPriority : 2;
#else
   uint8_t powerPriority : 2;  //0
   uint8_t pd4pid : 1;
   uint8_t reserved : 1;
   uint8_t powerSource : 2;
   uint8_t powerType : 2;
#endif
   uint16_t pdRequestedPower;  //1-2
   uint16_t pseAllocatedPower; //3-4
} __end_packed LldpDot3DllClassExt;


/**
 * @brief Type 3 and Type 4 extension
 **/

typedef __start_packed struct
{
   uint16_t pdRequestedPowerA;    //0-1
   uint16_t pdRequestedPowerB;    //2-3
   uint16_t pseAllocatedPowerA;   //4-5
   uint16_t pseAllocatedPowerB;   //6-7
   uint16_t powerStatus;          //8-9
   uint8_t systemSetup;           //10
   uint16_t pseMaxAvailablePower; //11-12
   uint8_t autoclass;             //13
   uint8_t powerDown[3];          //14-16
} __end_packed LldpDot3Type34Ext;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//IEEE 802.3 related functions
error_t lldpDot3SetLocalMacPhyConfigStatus(LldpAgentContext *context,
   uint_t portIndex, uint8_t autoNegSupportStatus, uint16_t pmdAutoNegAdvCap,
   uint16_t operationalMauType);

error_t lldpDot3SetLocalPowerViaMdi(LldpAgentContext *context,
   uint_t portIndex, uint8_t mdiPowerSupport,
   LldpDot3PsePowerPair psePowerPair, LldpDot3PowerClass powerClass,
   const LldpDot3DllClassExt *dllClassExt, const LldpDot3Type34Ext *type34Ext);

error_t lldpDot3SetLocalLinkAggregation(LldpAgentContext *context,
   uint_t portIndex, uint8_t aggregationStatus, uint32_t aggregatedPortId);

error_t lldpDot3SetLocalMaxFrameSize(LldpAgentContext *context,
   uint_t portIndex, uint16_t maxFrameSize);

error_t lldpDot3SetLocalPowerViaMdiMeas(LldpAgentContext *context,
   uint_t portIndex, uint8_t measurements[20], uint16_t psePowerPriceIndex);

error_t lldpDot3DeleteLocalTlv(LldpAgentContext *context,
   LldpDot3Subtype subtype);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

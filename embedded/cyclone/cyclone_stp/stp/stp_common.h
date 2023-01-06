/**
 * @file stp_common.h
 * @brief STP common definitions
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

#ifndef _STP_COMMON_H
#define _STP_COMMON_H

//Dependencies
#include "stp_config.h"
#include "core/net.h"


/*
 * CycloneSTP Open is licensed under GPL version 2. In particular:
 *
 * - If you link your program to CycloneSTP Open, the result is a derivative
 *   work that can only be distributed under the same GPL license terms.
 *
 * - If additions or changes to CycloneSTP Open are made, the result is a
 *   derivative work that can only be distributed under the same license terms.
 *
 * - The GPL license requires that you make the source code available to
 *   whoever you make the binary available to.
 *
 * - If you sell or distribute a hardware product that runs CycloneSTP Open,
 *   the GPL license requires you to provide public and full access to all
 *   source code on a nondiscriminatory basis.
 *
 * If you fully understand and accept the terms of the GPL license, then edit
 * the os_port_config.h header and add the following directive:
 *
 * #define GPL_LICENSE_TERMS_ACCEPTED
 */

#ifndef GPL_LICENSE_TERMS_ACCEPTED
   #error Before compiling CycloneSTP Open, you must accept the terms of the GPL license
#endif

//Version string
#define CYCLONE_STP_VERSION_STRING "2.2.0"
//Major version
#define CYCLONE_STP_MAJOR_VERSION 2
//Minor version
#define CYCLONE_STP_MINOR_VERSION 2
//Revision number
#define CYCLONE_STP_REV_NUMBER 0

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Protocol identifier
#define STP_PROTOCOL_ID 0

//LLC header fields
#define STP_LLC_DSAP 0x42
#define STP_LLC_SSAP 0x42
#define STP_LLC_CTRL 0x03

//Minimum size of BPDUs
#define STP_MIN_BPDU_SIZE 4


/**
 * @brief Protocol versions
 **/

typedef enum
{
   STP_PROTOCOL_VERSION  = 0, ///<STP version
   RSTP_PROTOCOL_VERSION = 2, ///<RSTP version
   MSTP_PROTOCOL_VERSION = 3  ///<MSTP version
} StpProtocolVersion;


/**
 * @brief Port states
 **/

typedef enum
{
   STP_PORT_STATE_DISABLED   = 0,
   STP_PORT_STATE_BROKEN     = 1,
   STP_PORT_STATE_BLOCKING   = 2,
   STP_PORT_STATE_LISTENING  = 3,
   STP_PORT_STATE_LEARNING   = 4,
   STP_PORT_STATE_FORWARDING = 5
} StpPortState;


/**
 * @brief Port role values
 **/

typedef enum
{
   STP_PORT_ROLE_DISABLED   = 0,
   STP_PORT_ROLE_ROOT       = 1,
   STP_PORT_ROLE_DESIGNATED = 2,
   STP_PORT_ROLE_ALTERNATE  = 3,
   STP_PORT_ROLE_BACKUP     = 4
} StpPortRole;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief Bridge identifier
 **/

typedef __start_packed struct
{
   uint16_t priority; //0-1
   MacAddr addr;      //2-7
} __end_packed StpBridgeId;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

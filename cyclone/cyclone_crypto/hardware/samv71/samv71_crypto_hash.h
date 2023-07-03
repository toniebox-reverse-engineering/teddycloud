/**
 * @file samv71_crypto_hash.h
 * @brief SAMV71 hash hardware accelerator
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
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

#ifndef _SAMV71_CRYPTO_HASH_H
#define _SAMV71_CRYPTO_HASH_H

//Dependencies
#include "core/crypto.h"

//Hash hardware accelerator
#ifndef SAMV71_CRYPTO_HASH_SUPPORT
   #define SAMV71_CRYPTO_HASH_SUPPORT DISABLED
#elif (SAMV71_CRYPTO_HASH_SUPPORT != ENABLED && SAMV71_CRYPTO_HASH_SUPPORT != DISABLED)
   #error SAMV71_CRYPTO_HASH_SUPPORT parameter is not valid
#endif

//Data buffer size
#ifndef SAMV71_ICM_BUFFER_SIZE
   #define SAMV71_ICM_BUFFER_SIZE 1024
#elif (SAMV71_ICM_BUFFER_SIZE < 64)
   #error SAMV71_ICM_BUFFER_SIZE parameter is not valid
#endif

//Name of the section where to place DMA buffers
#ifndef SAMV71_ICM_RAM_SECTION
   #define SAMV71_ICM_RAM_SECTION ".ram_no_cache"
#endif

//Hash algorithm identifiers
#define ICM_ALGO_SHA1        0
#define ICM_ALGO_SHA256      1
#define ICM_ALGO_SHA224      4

//ICM region configuration
#define ICM_RCFG_MRPROT      0x3F000000
#define ICM_RCFG_ALGO        0x00007000
#define ICM_RCFG_ALGO_SHA1   0x00000000
#define ICM_RCFG_ALGO_SHA256 0x00001000
#define ICM_RCFG_ALGO_SHA224 0x00004000
#define ICM_RCFG_PROCDLY     0x00000400
#define ICM_RCFG_SUIEN       0x00000200
#define ICM_RCFG_ECIEN       0x00000100
#define ICM_RCFG_WCIEN       0x00000080
#define ICM_RCFG_BEIEN       0x00000040
#define ICM_RCFG_DMIEN       0x00000020
#define ICM_RCFG_RHIEN       0x00000010
#define ICM_RCFG_EOM         0x00000004
#define ICM_RCFG_WRAP        0x00000002
#define ICM_RCFG_CDWBN       0x00000001

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ICM region descriptor
 **/

typedef struct
{
   uint32_t raddr; ///<ICM region start address
   uint32_t rcfg;  ///<ICM region configuration
   uint32_t rctrl; ///<ICM region control
   uint32_t rnext; ///<ICM region next address
} Same54IcmDesc;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif

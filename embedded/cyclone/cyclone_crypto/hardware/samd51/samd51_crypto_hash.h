/**
 * @file samd51_crypto_hash.h
 * @brief SAMD51 hash hardware accelerator
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

#ifndef _SAMD51_CRYPTO_HASH_H
#define _SAMD51_CRYPTO_HASH_H

//Dependencies
#include "core/crypto.h"

//Hash hardware accelerator
#ifndef SAMD51_CRYPTO_HASH_SUPPORT
   #define SAMD51_CRYPTO_HASH_SUPPORT DISABLED
#elif (SAMD51_CRYPTO_HASH_SUPPORT != ENABLED && SAMD51_CRYPTO_HASH_SUPPORT != DISABLED)
   #error SAMD51_CRYPTO_HASH_SUPPORT parameter is not valid
#endif

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
} Samd51IcmDesc;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif

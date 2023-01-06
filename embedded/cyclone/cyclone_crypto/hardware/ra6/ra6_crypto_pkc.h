/**
 * @file ra6_crypto_pkc.h
 * @brief RA6 public-key hardware accelerator
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

#ifndef _RA6_CRYPTO_PKC_H
#define _RA6_CRYPTO_PKC_H

//Dependencies
#include "hw_sce_private.h"
#include "core/crypto.h"

//Public-key hardware accelerator
#ifndef RA6_CRYPTO_PKC_SUPPORT
   #define RA6_CRYPTO_PKC_SUPPORT DISABLED
#elif (RA6_CRYPTO_PKC_SUPPORT != ENABLED && RA6_CRYPTO_PKC_SUPPORT != DISABLED)
   #error RA6_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RSA primitive arguments
 **/

typedef struct
{
#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   uint32_t n[128];
   uint32_t d[128];
   uint32_t e[1];
   uint32_t m[128];
   uint32_t c[128];
   uint32_t key[160];
   uint32_t wrappedKey[256];
#else
   uint32_t n[64];
   uint32_t d[64];
   uint32_t e[1];
   uint32_t m[64];
   uint32_t c[64];
   uint32_t key[160];
#endif
} Ra6RsaArgs;


/**
 * @brief EC primitive arguments
 **/

typedef struct
{
   uint32_t params[48];
   uint32_t g[24];
   uint32_t d[12];
   uint32_t q[24];
   uint32_t digest[12];
   uint32_t signature[24];
#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   uint32_t wrappedKey[32];
#endif
} Ra6EcArgs;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif

/**
 * @file mimxrt1170_crypto_pkc.h
 * @brief i.MX RT1170 public-key hardware accelerator
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

#ifndef _MIMXRT1170_CRYPTO_PKC_H
#define _MIMXRT1170_CRYPTO_PKC_H

//Dependencies
#include "core/crypto.h"

//Public-key hardware accelerator
#ifndef MIMXRT1170_CRYPTO_PKC_SUPPORT
   #define MIMXRT1170_CRYPTO_PKC_SUPPORT DISABLED
#elif (MIMXRT1170_CRYPTO_PKC_SUPPORT != ENABLED && MIMXRT1170_CRYPTO_PKC_SUPPORT != DISABLED)
   #error MIMXRT1170_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief PKHA primitive arguments
 **/

typedef struct
{
   uint8_t a[512];
   uint8_t b[512];
   uint8_t e[512];
   uint8_t p[512];
   uint8_t r[512];
} PkhaArgs;


/**
 * @brief PKHA ECC primitive arguments
 **/

typedef struct
{
   uint8_t p[66];
   uint8_t a[66];
   uint8_t b[66];
   uint8_t d[66];
   uint8_t gx[66];
   uint8_t gy[66];
   uint8_t qx[66];
   uint8_t qy[66];
} PkhaEccArgs;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif

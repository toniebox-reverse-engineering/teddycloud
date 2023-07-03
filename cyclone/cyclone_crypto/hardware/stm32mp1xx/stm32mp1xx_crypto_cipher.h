/**
 * @file stm32mp1xx_crypto_cipher.h
 * @brief STM32MP1 cipher hardware accelerator
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

#ifndef _STM32MP1XX_CRYPTO_CIPHER_H
#define _STM32MP1XX_CRYPTO_CIPHER_H

//Dependencies
#include "core/crypto.h"

//Cipher hardware accelerator
#ifndef STM32MP1XX_CRYPTO_CIPHER_SUPPORT
   #define STM32MP1XX_CRYPTO_CIPHER_SUPPORT DISABLED
#elif (STM32MP1XX_CRYPTO_CIPHER_SUPPORT != ENABLED && STM32MP1XX_CRYPTO_CIPHER_SUPPORT != DISABLED)
   #error STM32MP1XX_CRYPTO_CIPHER_SUPPORT parameter is not valid
#endif

//GCM_CCMPH  bitfield
#define CRYP_CR_GCM_CCMPH_INIT    0
#define CRYP_CR_GCM_CCMPH_HEADER  CRYP_CR_GCM_CCMPH_0
#define CRYP_CR_GCM_CCMPH_PAYLOAD CRYP_CR_GCM_CCMPH_1
#define CRYP_CR_GCM_CCMPH_FINAL   (CRYP_CR_GCM_CCMPH_1 | CRYP_CR_GCM_CCMPH_0)

//KEYSIZE bitfield
#define CRYP_CR_KEYSIZE_128B      0
#define CRYP_CR_KEYSIZE_192B      CRYP_CR_KEYSIZE_0
#define CRYP_CR_KEYSIZE_256B      CRYP_CR_KEYSIZE_1

//DATATYPE bitfield
#define CRYP_CR_DATATYPE_32B      0
#define CRYP_CR_DATATYPE_16B      CRYP_CR_DATATYPE_0
#define CRYP_CR_DATATYPE_8B       CRYP_CR_DATATYPE_1
#define CRYP_CR_DATATYPE_1B       (CRYP_CR_DATATYPE_1 | CRYP_CR_DATATYPE_0)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Cipher related functions
error_t crypInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

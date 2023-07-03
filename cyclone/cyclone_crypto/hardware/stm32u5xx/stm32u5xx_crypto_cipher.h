/**
 * @file stm32u5xx_crypto_cipher.h
 * @brief STM32U5 cipher hardware accelerator
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

#ifndef _STM32U5XX_CRYPTO_CIPHER_H
#define _STM32U5XX_CRYPTO_CIPHER_H

//Dependencies
#include "core/crypto.h"

//Cipher hardware accelerator
#ifndef STM32U5XX_CRYPTO_CIPHER_SUPPORT
   #define STM32U5XX_CRYPTO_CIPHER_SUPPORT DISABLED
#elif (STM32U5XX_CRYPTO_CIPHER_SUPPORT != ENABLED && STM32U5XX_CRYPTO_CIPHER_SUPPORT != DISABLED)
   #error STM32U5XX_CRYPTO_CIPHER_SUPPORT parameter is not valid
#endif

//KEYSIZE bitfield
#define AES_CR_KEYSIZE_128B         0
#define AES_CR_KEYSIZE_256B         AES_CR_KEYSIZE

//GCMPH bitfield
#define AES_CR_GCMPH_INIT          0
#define AES_CR_GCMPH_HEADER        AES_CR_GCMPH_0
#define AES_CR_GCMPH_PAYLOAD       AES_CR_GCMPH_1
#define AES_CR_GCMPH_FINAL         (AES_CR_GCMPH_1 | AES_CR_GCMPH_0)

//CHMOD bitfield
#define AES_CR_CHMOD_ECB           0
#define AES_CR_CHMOD_CBC           AES_CR_CHMOD_0
#define AES_CR_CHMOD_CTR           AES_CR_CHMOD_1
#define AES_CR_CHMOD_GCM_GMAC      (AES_CR_CHMOD_0 | AES_CR_CHMOD_1)
#define AES_CR_CHMOD_CCM           AES_CR_CHMOD_2

//MODE bitfield
#define AES_CR_MODE_ENCRYPTION     0
#define AES_CR_MODE_KEY_DERIVATION AES_CR_MODE_0
#define AES_CR_MODE_DECRYPTION     AES_CR_MODE_1

//DATATYPE bitfield
#define AES_CR_DATATYPE_32B        0
#define AES_CR_DATATYPE_16B        AES_CR_DATATYPE_0
#define AES_CR_DATATYPE_8B         AES_CR_DATATYPE_1
#define AES_CR_DATATYPE_1B         (AES_CR_DATATYPE_1 | AES_CR_DATATYPE_0)

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

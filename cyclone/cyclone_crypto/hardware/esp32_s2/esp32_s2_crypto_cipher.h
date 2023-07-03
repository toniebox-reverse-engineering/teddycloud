/**
 * @file esp32_s2_crypto_cipher.h
 * @brief ESP32-S2 cipher hardware accelerator
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

#ifndef _ESP32_S2_CRYPTO_CIPHER_H
#define _ESP32_S2_CRYPTO_CIPHER_H

//Dependencies
#include "core/crypto.h"

//Cipher hardware accelerator
#ifndef ESP32_S2_CRYPTO_CIPHER_SUPPORT
   #define ESP32_S2_CRYPTO_CIPHER_SUPPORT DISABLED
#elif (ESP32_S2_CRYPTO_CIPHER_SUPPORT != ENABLED && ESP32_S2_CRYPTO_CIPHER_SUPPORT != DISABLED)
   #error ESP32_S2_CRYPTO_CIPHER_SUPPORT parameter is not valid
#endif

//AES Operation Mode register
#define AES_MODE_ENC          0x00000000
#define AES_MODE_DEC          0x00000004
#define AES_MODE_128_BITS     0x00000000
#define AES_MODE_192_BITS     0x00000001
#define AES_MODE_256_BITS     0x00000002

//AES Block Mode register
#define AES_BLOCK_MODE_ECB    0x00000000
#define AES_BLOCK_MODE_CBC    0x00000001
#define AES_BLOCK_MODE_OFB    0x00000002
#define AES_BLOCK_MODE_CTR    0x00000003
#define AES_BLOCK_MODE_CFB8   0x00000004
#define AES_BLOCK_MODE_CFB128 0x00000005
#define AES_BLOCK_MODE_GCM    0x00000006

//Endianness Configuration register
#define AES_ENDIAN_DEFAULT    0x0000003F

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Cipher related functions
void esp32s2AesInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

/**
 * @file saml11_crypto.h
 * @brief SAML11 hardware cryptographic accelerator
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

#ifndef _SAML11_CRYPTO_H
#define _SAML11_CRYPTO_H

//Dependencies
#include "core/crypto.h"

//CRYA function entry points
#define CRYA_SHA_ADDR        0x02001900
#define CRYA_AES_ENC_ADDR    0x02001904
#define CRYA_AES_DEC_ADDR    0x02001908
#define CRYA_GF_MULT128_ADDR 0x0200190C

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//CRYA function prototypes
typedef void (*crya_sha_process_t)(uint32_t digest[8],
   const uint8_t data[64], uint32_t buffer[64]);

typedef void (*crya_aes_encrypt_t)(const uint8_t *key, uint32_t keyLen,
   const uint8_t *src, uint8_t *dest);

typedef void (*crya_aes_decrypt_t)(const uint8_t *key, uint32_t keyLen,
   const uint8_t *src, uint8_t *dest);

typedef void (*crya_gf_mult128_t)(const uint32_t *block1,
   const uint32_t *block2, uint32_t *dest);

//CRYA related functions
#define crya_sha_process ((crya_sha_process_t) (CRYA_SHA_ADDR | 1))
#define crya_aes_encrypt ((crya_aes_encrypt_t) (CRYA_AES_ENC_ADDR | 1))
#define crya_aes_decrypt ((crya_aes_decrypt_t) (CRYA_AES_DEC_ADDR | 1))
#define crya_gf_mult128 ((crya_gf_mult128_t) (CRYA_GF_MULT128_ADDR | 1))

//Global variables
extern OsMutex saml11CryptoMutex;

//SAML11 hardware cryptographic accelerator related functions
error_t saml11CryptoInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

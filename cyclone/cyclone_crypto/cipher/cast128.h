/**
 * @file cast128.h
 * @brief CAST-128 encryption algorithm
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

#ifndef _CAST128_H
#define _CAST128_H

//Dependencies
#include "core/crypto.h"

//CAST-128 block size
#define CAST128_BLOCK_SIZE 8
//Common interface for encryption algorithms
#define CAST128_CIPHER_ALGO (&cast128CipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief CAST-128 algorithm context
 **/

typedef struct
{
   uint_t nr;
   uint32_t km[16];
   uint32_t kr[16];
} Cast128Context;


//CAST-128 related constants
extern const CipherAlgo cast128CipherAlgo;

//CAST-128 related functions
error_t cast128Init(Cast128Context *context, const uint8_t *key, size_t keyLen);

void cast128EncryptBlock(Cast128Context *context, const uint8_t *input,
   uint8_t *output);

void cast128DecryptBlock(Cast128Context *context, const uint8_t *input,
   uint8_t *output);

void cast128Deinit(Cast128Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

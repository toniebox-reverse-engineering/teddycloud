/**
 * @file cast256.h
 * @brief CAST-256 encryption algorithm
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

#ifndef _CAST256_H
#define _CAST256_H

//Dependencies
#include "core/crypto.h"

//CAST-256 block size
#define CAST256_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define CAST256_CIPHER_ALGO (&cast256CipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief CAST-256 algorithm context
 **/

typedef struct
{
   uint32_t km[12][4];
   uint8_t kr[12][4];
} Cast256Context;


//CAST-256 related constants
extern const CipherAlgo cast256CipherAlgo;

//CAST-256 related functions
error_t cast256Init(Cast256Context *context, const uint8_t *key, size_t keyLen);

void cast256EncryptBlock(Cast256Context *context, const uint8_t *input,
   uint8_t *output);

void cast256DecryptBlock(Cast256Context *context, const uint8_t *input,
   uint8_t *output);

void cast256Deinit(Cast256Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

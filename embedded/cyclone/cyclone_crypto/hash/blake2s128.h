/**
 * @file blake2s128.h
 * @brief BLAKE2s-128 hash function
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

#ifndef _BLAKE2S128_H
#define _BLAKE2S128_H

//Dependencies
#include "core/crypto.h"
#include "hash/blake2s.h"

//BLAKE2s-128 block size
#define BLAKE2S128_BLOCK_SIZE 64
//BLAKE2s-128 digest size
#define BLAKE2S128_DIGEST_SIZE 16
//Minimum length of the padding string
#define BLAKE2S128_MIN_PAD_SIZE 0
//BLAKE2s-128 algorithm object identifier
#define BLAKE2S128_OID blake2s128Oid
//Common interface for hash algorithms
#define BLAKE2S128_HASH_ALGO (&blake2s128HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief BLAKE2s-128 algorithm context
 **/

typedef Blake2sContext Blake2s128Context;


//BLAKE2s-128 related constants
extern const uint8_t blake2s128Oid[11];
extern const HashAlgo blake2s128HashAlgo;

//BLAKE2s-128 related functions
error_t blake2s128Compute(const void *data, size_t length, uint8_t *digest);
void blake2s128Init(Blake2s128Context *context);
void blake2s128Update(Blake2s128Context *context, const void *data, size_t length);
void blake2s128Final(Blake2s128Context *context, uint8_t *digest);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

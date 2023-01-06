/**
 * @file sha3_512.h
 * @brief SHA3-512 hash function (SHA-3 with 512-bit output)
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

#ifndef _SHA3_512_H
#define _SHA3_512_H

//Dependencies
#include "core/crypto.h"
#include "xof/keccak.h"

//SHA3-512 block size
#define SHA3_512_BLOCK_SIZE 72
//SHA3-512 digest size
#define SHA3_512_DIGEST_SIZE 64
//Minimum length of the padding string
#define SHA3_512_MIN_PAD_SIZE 1
//SHA3-512 algorithm object identifier
#define SHA3_512_OID sha3_512Oid
//Common interface for hash algorithms
#define SHA3_512_HASH_ALGO (&sha3_512HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SHA3-512 algorithm context
 **/

typedef KeccakContext Sha3_512Context;


//SHA3-512 related constants
extern const uint8_t sha3_512Oid[9];
extern const HashAlgo sha3_512HashAlgo;

//SHA3-512 related functions
error_t sha3_512Compute(const void *data, size_t length, uint8_t *digest);
void sha3_512Init(Sha3_512Context *context);
void sha3_512Update(Sha3_512Context *context, const void *data, size_t length);
void sha3_512Final(Sha3_512Context *context, uint8_t *digest);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

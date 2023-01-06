/**
 * @file sha3_384.h
 * @brief SHA3-384 hash function (SHA-3 with 384-bit output)
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

#ifndef _SHA3_384_H
#define _SHA3_384_H

//Dependencies
#include "core/crypto.h"
#include "xof/keccak.h"

//SHA3-384 block size
#define SHA3_384_BLOCK_SIZE 104
//SHA3-384 digest size
#define SHA3_384_DIGEST_SIZE 48
//Minimum length of the padding string
#define SHA3_384_MIN_PAD_SIZE 1
//SHA3-384 algorithm object identifier
#define SHA3_384_OID sha3_384Oid
//Common interface for hash algorithms
#define SHA3_384_HASH_ALGO (&sha3_384HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SHA3-384 algorithm context
 **/

typedef KeccakContext Sha3_384Context;


//SHA3-384 related constants
extern const uint8_t sha3_384Oid[9];
extern const HashAlgo sha3_384HashAlgo;

//SHA3-384 related functions
error_t sha3_384Compute(const void *data, size_t length, uint8_t *digest);
void sha3_384Init(Sha3_384Context *context);
void sha3_384Update(Sha3_384Context *context, const void *data, size_t length);
void sha3_384Final(Sha3_384Context *context, uint8_t *digest);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

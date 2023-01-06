/**
 * @file blake2b384.h
 * @brief BLAKE2b-384 hash function
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

#ifndef _BLAKE2B384_H
#define _BLAKE2B384_H

//Dependencies
#include "core/crypto.h"
#include "hash/blake2b.h"

//BLAKE2b-384 block size
#define BLAKE2B384_BLOCK_SIZE 128
//BLAKE2b-384 digest size
#define BLAKE2B384_DIGEST_SIZE 48
//Minimum length of the padding string
#define BLAKE2B384_MIN_PAD_SIZE 0
//BLAKE2b-384 algorithm object identifier
#define BLAKE2B384_OID blake2b384Oid
//Common interface for hash algorithms
#define BLAKE2B384_HASH_ALGO (&blake2b384HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief BLAKE2b-384 algorithm context
 **/

typedef Blake2bContext Blake2b384Context;


//BLAKE2b-384 related constants
extern const uint8_t blake2b384Oid[11];
extern const HashAlgo blake2b384HashAlgo;

//BLAKE2b-384 related functions
error_t blake2b384Compute(const void *data, size_t length, uint8_t *digest);
void blake2b384Init(Blake2b384Context *context);
void blake2b384Update(Blake2b384Context *context, const void *data, size_t length);
void blake2b384Final(Blake2b384Context *context, uint8_t *digest);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

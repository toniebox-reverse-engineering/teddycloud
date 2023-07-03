/**
 * @file sha384.h
 * @brief SHA-384 (Secure Hash Algorithm 384)
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

#ifndef _SHA384_H
#define _SHA384_H

//Dependencies
#include "core/crypto.h"
#include "hash/sha512.h"

//SHA-384 block size
#define SHA384_BLOCK_SIZE 128
//SHA-384 digest size
#define SHA384_DIGEST_SIZE 48
//Minimum length of the padding string
#define SHA384_MIN_PAD_SIZE 17
//SHA-384 algorithm object identifier
#define SHA384_OID sha384Oid
//Common interface for hash algorithms
#define SHA384_HASH_ALGO (&sha384HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SHA-384 algorithm context
 **/

typedef Sha512Context Sha384Context;


//SHA-384 related constants
extern const uint8_t sha384Oid[9];
extern const HashAlgo sha384HashAlgo;

//SHA-384 related functions
error_t sha384Compute(const void *data, size_t length, uint8_t *digest);
void sha384Init(Sha384Context *context);
void sha384Update(Sha384Context *context, const void *data, size_t length);
void sha384Final(Sha384Context *context, uint8_t *digest);
void sha384FinalRaw(Sha384Context *context, uint8_t *digest);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif

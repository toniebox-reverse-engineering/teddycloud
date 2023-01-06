/**
 * @file blake2s256.c
 * @brief BLAKE2s-256 hash function
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

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/blake2s256.h"

//Check crypto library configuration
#if (BLAKE2S256_SUPPORT == ENABLED)

//BLAKE2s-256 object identifier (1.3.6.1.4.1.1722.12.2.2.8)
const uint8_t blake2s256Oid[11] = {0x43, 0x06, 0x01, 0x04, 0x01, 0x8D, 0x3A, 0x0C, 0x02, 0x02, 0x08};

//Common interface for hash algorithms
const HashAlgo blake2s256HashAlgo =
{
   "BLAKE2s-256",
   blake2s256Oid,
   sizeof(blake2s256Oid),
   sizeof(Blake2s256Context),
   BLAKE2S256_BLOCK_SIZE,
   BLAKE2S256_DIGEST_SIZE,
   BLAKE2S256_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) blake2s256Compute,
   (HashAlgoInit) blake2s256Init,
   (HashAlgoUpdate) blake2s256Update,
   (HashAlgoFinal) blake2s256Final,
   NULL
};


/**
 * @brief Digest a message using BLAKE2s-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t blake2s256Compute(const void *data, size_t length, uint8_t *digest)
{
   //Compute the unkeyed hash with BLAKE2s-256
   return blake2sCompute(NULL, 0, data, length, digest, BLAKE2S256_DIGEST_SIZE);
}


/**
 * @brief Initialize BLAKE2s-256 hash computation
 * @param[in] context Pointer to the BLAKE2s context to initialize
 **/

void blake2s256Init(Blake2s256Context *context)
{
   //Initialize the hashing context
   blake2sInit(context, NULL, 0, BLAKE2S256_DIGEST_SIZE);
}


/**
 * @brief Update BLAKE2s-256 hash computation
 * @param[in] context Pointer to the BLAKE2s context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void blake2s256Update(Blake2s256Context *context, const void *data, size_t length)
{
   //Digest the data
   blake2sUpdate(context, data, length);
}


/**
 * @brief Finish BLAKE2s-256 hash computation
 * @param[in] context Pointer to the BLAKE2s context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void blake2s256Final(Blake2s256Context *context, uint8_t *digest)
{
   //Generate the message digest
   blake2sFinal(context, digest);
}

#endif

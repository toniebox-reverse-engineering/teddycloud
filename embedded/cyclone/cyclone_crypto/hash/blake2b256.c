/**
 * @file blake2b256.c
 * @brief BLAKE2b-256 hash function
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
#include "hash/blake2b256.h"

//Check crypto library configuration
#if (BLAKE2B256_SUPPORT == ENABLED)

//BLAKE2b-256 object identifier (1.3.6.1.4.1.1722.12.2.1.8)
const uint8_t blake2b256Oid[11] = {0x43, 0x06, 0x01, 0x04, 0x01, 0x8D, 0x3A, 0x0C, 0x02, 0x01, 0x08};

//Common interface for hash algorithms
const HashAlgo blake2b256HashAlgo =
{
   "BLAKE2b-256",
   blake2b256Oid,
   sizeof(blake2b256Oid),
   sizeof(Blake2b256Context),
   BLAKE2B256_BLOCK_SIZE,
   BLAKE2B256_DIGEST_SIZE,
   BLAKE2B256_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) blake2b256Compute,
   (HashAlgoInit) blake2b256Init,
   (HashAlgoUpdate) blake2b256Update,
   (HashAlgoFinal) blake2b256Final,
   NULL
};


/**
 * @brief Digest a message using BLAKE2b-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t blake2b256Compute(const void *data, size_t length, uint8_t *digest)
{
   //Compute the unkeyed hash with BLAKE2b-256
   return blake2bCompute(NULL, 0, data, length, digest, BLAKE2B256_DIGEST_SIZE);
}


/**
 * @brief Initialize BLAKE2b-256 hash computation
 * @param[in] context Pointer to the BLAKE2b context to initialize
 **/

void blake2b256Init(Blake2b256Context *context)
{
   //Initialize the hashing context
   blake2bInit(context, NULL, 0, BLAKE2B256_DIGEST_SIZE);
}


/**
 * @brief Update BLAKE2b-256 hash computation
 * @param[in] context Pointer to the BLAKE2b context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void blake2b256Update(Blake2b256Context *context, const void *data, size_t length)
{
   //Digest the data
   blake2bUpdate(context, data, length);
}


/**
 * @brief Finish BLAKE2b-256 hash computation
 * @param[in] context Pointer to the BLAKE2b context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void blake2b256Final(Blake2b256Context *context, uint8_t *digest)
{
   //Generate the message digest
   blake2bFinal(context, digest);
}

#endif

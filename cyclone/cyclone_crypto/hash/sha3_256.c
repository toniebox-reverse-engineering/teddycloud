/**
 * @file sha3_256.c
 * @brief SHA3-256 hash function (SHA-3 with 256-bit output)
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
 * @section Description
 *
 * SHA-3 is a secure hash algorithm for computing a condensed representation
 * of an electronic message. Refer to FIPS 202 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/sha3_256.h"

//Check crypto library configuration
#if (SHA3_256_SUPPORT == ENABLED)

//SHA3-256 object identifier (2.16.840.1.101.3.4.2.8)
const uint8_t sha3_256Oid[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08};

//Common interface for hash algorithms
const HashAlgo sha3_256HashAlgo =
{
   "SHA3-256",
   sha3_256Oid,
   sizeof(sha3_256Oid),
   sizeof(Sha3_256Context),
   SHA3_256_BLOCK_SIZE,
   SHA3_256_DIGEST_SIZE,
   SHA3_256_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) sha3_256Compute,
   (HashAlgoInit) sha3_256Init,
   (HashAlgoUpdate) sha3_256Update,
   (HashAlgoFinal) sha3_256Final,
   NULL
};


/**
 * @brief Digest a message using SHA3-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha3_256Compute(const void *data, size_t length, uint8_t *digest)
{
   error_t error;
   Sha3_256Context *context;

   //Allocate a memory buffer to hold the SHA3-256 context
   context = cryptoAllocMem(sizeof(Sha3_256Context));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the SHA3-256 context
      sha3_256Init(context);
      //Digest the message
      sha3_256Update(context, data, length);
      //Finalize the SHA3-256 message digest
      sha3_256Final(context, digest);

      //Free previously allocated memory
      cryptoFreeMem(context);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Initialize SHA3-256 message digest context
 * @param[in] context Pointer to the SHA3-256 context to initialize
 **/

void sha3_256Init(Sha3_256Context *context)
{
   //The capacity of the sponge is twice the digest length
   keccakInit(context, 2 * 256);
}


/**
 * @brief Update the SHA3-256 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA3-256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha3_256Update(Sha3_256Context *context, const void *data, size_t length)
{
   //Absorb the input data
   keccakAbsorb(context, data, length);
}


/**
 * @brief Finish the SHA3-256 message digest
 * @param[in] context Pointer to the SHA3-256 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha3_256Final(Sha3_256Context *context, uint8_t *digest)
{
   //Finish absorbing phase (padding byte is 0x06 for SHA-3)
   keccakFinal(context, KECCAK_SHA3_PAD);
   //Extract data from the squeezing phase
   keccakSqueeze(context, digest, SHA3_256_DIGEST_SIZE);
}

#endif

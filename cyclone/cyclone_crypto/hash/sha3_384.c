/**
 * @file sha3_384.c
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
#include "hash/sha3_384.h"

//Check crypto library configuration
#if (SHA3_384_SUPPORT == ENABLED)

//SHA3-384 object identifier (2.16.840.1.101.3.4.2.9)
const uint8_t sha3_384Oid[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09};

//Common interface for hash algorithms
const HashAlgo sha3_384HashAlgo =
{
   "SHA3-384",
   sha3_384Oid,
   sizeof(sha3_384Oid),
   sizeof(Sha3_384Context),
   SHA3_384_BLOCK_SIZE,
   SHA3_384_DIGEST_SIZE,
   SHA3_384_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) sha3_384Compute,
   (HashAlgoInit) sha3_384Init,
   (HashAlgoUpdate) sha3_384Update,
   (HashAlgoFinal) sha3_384Final,
   NULL
};


/**
 * @brief Digest a message using SHA3-384
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha3_384Compute(const void *data, size_t length, uint8_t *digest)
{
   error_t error;
   Sha3_384Context *context;

   //Allocate a memory buffer to hold the SHA3-384 context
   context = cryptoAllocMem(sizeof(Sha3_384Context));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the SHA3-384 context
      sha3_384Init(context);
      //Digest the message
      sha3_384Update(context, data, length);
      //Finalize the SHA3-384 message digest
      sha3_384Final(context, digest);

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
 * @brief Initialize SHA3-384 message digest context
 * @param[in] context Pointer to the SHA3-384 context to initialize
 **/

void sha3_384Init(Sha3_384Context *context)
{
   //The capacity of the sponge is twice the digest length
   keccakInit(context, 2 * 384);
}


/**
 * @brief Update the SHA3-384 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA3-384 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha3_384Update(Sha3_384Context *context, const void *data, size_t length)
{
   //Absorb the input data
   keccakAbsorb(context, data, length);
}


/**
 * @brief Finish the SHA3-384 message digest
 * @param[in] context Pointer to the SHA3-384 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha3_384Final(Sha3_384Context *context, uint8_t *digest)
{
   //Finish absorbing phase (padding byte is 0x06 for SHA-3)
   keccakFinal(context, KECCAK_SHA3_PAD);
   //Extract data from the squeezing phase
   keccakSqueeze(context, digest, SHA3_384_DIGEST_SIZE);
}

#endif

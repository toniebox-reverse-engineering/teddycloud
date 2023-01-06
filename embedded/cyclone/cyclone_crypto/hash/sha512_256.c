/**
 * @file sha512_256.c
 * @brief SHA-512/256 (Secure Hash Algorithm)
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
 * SHA-512/256 is a secure hash algorithm for computing a condensed representation
 * of an electronic message. Refer to FIPS 180-4 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/sha512_256.h"

//Check crypto library configuration
#if (SHA512_256_SUPPORT == ENABLED)

//SHA-512/256 object identifier (2.16.840.1.101.3.4.2.6)
const uint8_t sha512_256Oid[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06};

//Common interface for hash algorithms
const HashAlgo sha512_256HashAlgo =
{
   "SHA-512/256",
   sha512_256Oid,
   sizeof(sha512_256Oid),
   sizeof(Sha512_256Context),
   SHA512_256_BLOCK_SIZE,
   SHA512_256_DIGEST_SIZE,
   SHA512_256_MIN_PAD_SIZE,
   TRUE,
   (HashAlgoCompute) sha512_256Compute,
   (HashAlgoInit) sha512_256Init,
   (HashAlgoUpdate) sha512_256Update,
   (HashAlgoFinal) sha512_256Final,
   NULL
};


/**
 * @brief Digest a message using SHA-512/256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

__weak_func error_t sha512_256Compute(const void *data, size_t length, uint8_t *digest)
{
   error_t error;
   Sha512_256Context *context;

   //Allocate a memory buffer to hold the SHA-512/256 context
   context = cryptoAllocMem(sizeof(Sha512_256Context));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the SHA-512/256 context
      sha512_256Init(context);
      //Digest the message
      sha512_256Update(context, data, length);
      //Finalize the SHA-512/256 message digest
      sha512_256Final(context, digest);

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
 * @brief Initialize SHA-512/256 message digest context
 * @param[in] context Pointer to the SHA-512/256 context to initialize
 **/

__weak_func void sha512_256Init(Sha512_256Context *context)
{
   //Set initial hash value
   context->h[0] = 0x22312194FC2BF72C;
   context->h[1] = 0x9F555FA3C84C64C2;
   context->h[2] = 0x2393B86B6F53B151;
   context->h[3] = 0x963877195940EABD;
   context->h[4] = 0x96283EE2A88EFFE3;
   context->h[5] = 0xBE5E1E2553863992;
   context->h[6] = 0x2B0199FC2C85B8AA;
   context->h[7] = 0x0EB72DDC81C52CA2;

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the SHA-512/256 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-512/256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

__weak_func void sha512_256Update(Sha512_256Context *context, const void *data, size_t length)
{
   //The function is defined in the exact same manner as SHA-512
   sha512Update(context, data, length);
}


/**
 * @brief Finish the SHA-512/256 message digest
 * @param[in] context Pointer to the SHA-512/256 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

__weak_func void sha512_256Final(Sha512_256Context *context, uint8_t *digest)
{
   //The function is defined in the exact same manner as SHA-512
   sha512Final(context, NULL);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA512_256_DIGEST_SIZE);
   }
}

#endif

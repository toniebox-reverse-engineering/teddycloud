/**
 * @file pbkdf.c
 * @brief PBKDF (Password-Based Key Derivation Function)
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
#include "kdf/pbkdf.h"
#include "mac/hmac.h"

//Check crypto library configuration
#if (PBKDF_SUPPORT == ENABLED)

//PBKDF2 OID (1.2.840.113549.1.5.12)
const uint8_t PBKDF2_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C};


/**
 * @brief PBKDF1 key derivation function
 *
 * PBKDF1 applies a hash function, which shall be MD2, MD5 or SHA-1, to derive
 * keys. The length of the derived key is bounded by the length of the hash
 * function output, which is 16 octets for MD2 and MD5 and 20 octets for SHA-1
 *
 * @param[in] hash Underlying hash function (MD2, MD5 or SHA-1)
 * @param[in] p Password, an octet string
 * @param[in] pLen Length in octets of password
 * @param[in] s Salt, an octet string
 * @param[in] sLen Length in octets of salt
 * @param[in] c Iteration count
 * @param[out] dk Derived key
 * @param[in] dkLen Intended length in octets of the derived key
 * @return Error code
 **/

error_t pbkdf1(const HashAlgo *hash, const uint8_t *p, size_t pLen,
   const uint8_t *s, size_t sLen, uint_t c, uint8_t *dk, size_t dkLen)
{
   uint_t i;
   HashContext *hashContext;
   uint8_t t[MAX_HASH_DIGEST_SIZE];

   //Check parameters
   if(hash == NULL || p == NULL || s == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The iteration count must be a positive integer
   if(c < 1)
      return ERROR_INVALID_PARAMETER;

   //Check the intended length of the derived key
   if(dkLen > hash->digestSize)
      return ERROR_INVALID_LENGTH;

   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hash->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Apply the hash function to the concatenation of P and S
   hash->init(hashContext);
   hash->update(hashContext, p, pLen);
   hash->update(hashContext, s, sLen);
   hash->final(hashContext, t);

   //Iterate as many times as required
   for(i = 1; i < c; i++)
   {
      //Apply the hash function to T(i - 1)
      hash->init(hashContext);
      hash->update(hashContext, t, hash->digestSize);
      hash->final(hashContext, t);
   }

   //Output the derived key DK
   osMemcpy(dk, t, dkLen);

   //Free previously allocated memory
   cryptoFreeMem(hashContext);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief PBKDF2 key derivation function
 *
 * PBKDF2 applies a pseudorandom function to derive keys. The
 * length of the derived key is essentially unbounded
 *
 * @param[in] hash Hash algorithm used by the underlying PRF
 * @param[in] p Password, an octet string
 * @param[in] pLen Length in octets of password
 * @param[in] s Salt, an octet string
 * @param[in] sLen Length in octets of salt
 * @param[in] c Iteration count
 * @param[out] dk Derived key
 * @param[in] dkLen Intended length in octets of the derived key
 * @return Error code
 **/

error_t pbkdf2(const HashAlgo *hash, const uint8_t *p, size_t pLen,
   const uint8_t *s, size_t sLen, uint_t c, uint8_t *dk, size_t dkLen)
{
   uint_t i;
   uint_t j;
   uint_t k;
   HmacContext *hashContext;
   uint8_t a[4];
   uint8_t t[MAX_HASH_DIGEST_SIZE];
   uint8_t u[MAX_HASH_DIGEST_SIZE];

   //Check parameters
   if(hash == NULL || p == NULL || s == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The iteration count must be a positive integer
   if(c < 1)
      return ERROR_INVALID_PARAMETER;

   //Allocate a memory buffer to hold the HMAC context
   hashContext = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;

   //For each block of the derived key apply the function F
   for(i = 1; dkLen > 0; i++)
   {
      //Calculate the 4-octet encoding of the integer i (MSB first)
      STORE32BE(i, a);

      //Compute U1 = PRF(P, S || INT(i))
      hmacInit(hashContext, hash, p, pLen);
      hmacUpdate(hashContext, s, sLen);
      hmacUpdate(hashContext, a, 4);
      hmacFinal(hashContext, u);

      //Save the resulting HMAC value
      osMemcpy(t, u, hash->digestSize);

      //Iterate as many times as required
      for(j = 1; j < c; j++)
      {
         //Compute U(j) = PRF(P, U(j-1))
         hmacInit(hashContext, hash, p, pLen);
         hmacUpdate(hashContext, u, hash->digestSize);
         hmacFinal(hashContext, u);

         //Compute T = U(1) xor U(2) xor ... xor U(c)
         for(k = 0; k < hash->digestSize; k++)
         {
            t[k] ^= u[k];
         }
      }

      //Number of octets in the current block
      k = MIN(dkLen, hash->digestSize);
      //Save the resulting block
      osMemcpy(dk, t, k);

      //Point to the next block
      dk += k;
      dkLen -= k;
   }

   //Free previously allocated memory
   cryptoFreeMem(hashContext);

   //Successful processing
   return NO_ERROR;
}

#endif

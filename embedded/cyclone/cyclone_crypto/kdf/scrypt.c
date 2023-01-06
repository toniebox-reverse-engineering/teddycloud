/**
 * @file scrypt.c
 * @brief scrypt PBKDF (Password-Based Key Derivation Function)
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
 * scrypt is a password-based key derivation function. The function derives
 * one or more secret keys from a secret string. It is based on memory-hard
 * functions, which offer added protection against attacks using custom
 * hardware. Refer to RFC 7914 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "kdf/scrypt.h"
#include "kdf/pbkdf.h"
#include "hash/sha256.h"
#include "cipher/salsa20.h"

//Check crypto library configuration
#if (SCRYPT_SUPPORT == ENABLED)


/**
 * @brief scrypt algorithm
 * @param[in] password NULL-terminated passphrase
 * @param[in] salt Random salt
 * @param[in] saltLen Length of the random salt, in bytes
 * @param[in] n CPU/Memory cost parameter
 * @param[in] r Block size parameter
 * @param[in] p Parallelization parameter
 * @param[out] dk Derived key
 * @param[in] dkLen Intended output length in octets of the derived key
 * @return Error code
 **/

error_t scrypt(const char_t *password, const uint8_t *salt, size_t saltLen,
   uint_t n, uint_t r, uint_t p, uint8_t *dk, size_t dkLen)
{
   error_t error;
   uint_t i;
   size_t blockSize;
   size_t passwordLen;
   uint8_t *b;
   uint8_t *v;
   uint8_t *y;

   //Check parameters
   if(password == NULL || salt == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   b = NULL;
   v = NULL;
   y = NULL;

   //The CPU/Memory cost parameter must be larger than 1, a power of 2, and
   //less than 2^(128 * r / 8)
   if(n <= 1 || (n & (n - 1)) != 0)
      return ERROR_INVALID_PARAMETER;

   //The block size parameter must be a positive integer
   if(r == 0)
      return ERROR_INVALID_PARAMETER;

   //The parallelization parameter must be a positive integer less than or equal
   //to ((2^32-1) * hLen) / MFLen where hLen is 32 and MFlen is 128 * r
   if(p == 0)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the passphrase
   passwordLen = osStrlen(password);

   //Each block consists of 128 * r octets
   blockSize = 128 * r;

   //Start of exception handling block
   do
   {
      //Initialize an array B consisting of p blocks
      b = cryptoAllocMem(p * blockSize);
      //Failed to allocate memory?
      if(b == NULL)
      {
         //Report an error
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //Initialize a working array V consisting of N blocks
      v = cryptoAllocMem(n * blockSize);
      //Failed to allocate memory?
      if(v == NULL)
      {
         //Report an error
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //Initialize a working array Y
      y = cryptoAllocMem(blockSize);
      //Failed to allocate memory?
      if(y == NULL)
      {
         //Report an error
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //Compute B = PBKDF2-HMAC-SHA256(P, S, 1, p * 128 * r)
      error = pbkdf2(SHA256_HASH_ALGO, (const uint8_t *) password, passwordLen,
         salt, saltLen, 1, b, p * blockSize);
      //Any error to report?
      if(error)
         break;

      //Iterate as many times as desired
      for(i = 0; i < p; i++)
      {
         //Compute B[i] = scryptROMix(r, B[i], N)
         scryptRoMix(r, b + i * blockSize, n, v, y);
      }

      //Compute DK = PBKDF2-HMAC-SHA256(P, B, 1, dkLen)
      error = pbkdf2(SHA256_HASH_ALGO, (const uint8_t *) password, passwordLen,
         b, p * blockSize, 1, dk, dkLen);
      //Any error to report?
      if(error)
         break;

      //End of exception handling block
   } while(0);

   //Release array B
   if(b != NULL)
      cryptoFreeMem(b);

   //Release working array V
   if(v != NULL)
      cryptoFreeMem(v);

   //Release working array Y
   if(y != NULL)
      cryptoFreeMem(y);

   //Return status code
   return error;
}


/**
 * @brief scryptROMix algorithm
 * @param[in] r Block size parameter
 * @param[in,out] b Octet vector of length 128 * r octets
 * @param[in] n CPU/Memory cost parameter
 * @param[in,out] v Working array
 * @param[in,out] y Working array
 **/

void scryptRoMix(uint_t r, uint8_t *b, uint_t n, uint8_t *v, uint8_t *y)
{
   uint_t i;
   uint32_t j;
   uint8_t *x;
   size_t blockSize;

   //Each block consists of 128 * r octets
   blockSize = 128 * r;

   //Let X = B
   x = b;

   //Compute V array
   for(i = 0; i < n; i++)
   {
      //Let V[i] = X
      osMemcpy(v + i * blockSize, x, blockSize);

      //Compute X = scryptBlockMix(r, X)
      scryptBlockMix(r, x, y);
   }

   //Compute B' array
   for(i = 0; i < n; i++)
   {
      //Compute j = Integerify(X) mod N
      j = LOAD32LE(x + blockSize - 64) & (n - 1);

      //Compute T = X xor V[j]
      scryptXorBlock(x, x, v + j * blockSize, blockSize);

      //Compute X = scryptBlockMix(r, T)
      scryptBlockMix(r, x, y);
   }
}


/**
 * @brief scryptBlockMix algorithm
 * @param[in] r Block size parameter
 * @param[in,out] b Octet vector of length 128 * r octets
 * @param[in,out] y Working array
 **/

void scryptBlockMix(uint_t r, uint8_t *b, uint8_t *y)
{
   uint_t i;
   uint8_t x[64];

   //Let X = B[2 * r - 1]
   osMemcpy(x, b + r * 128 - 64, 64);

   //Iterate as many times as desired
   for(i = 0; i < (2 * r); i++)
   {
      //Compute T = X xor B[i]
      scryptXorBlock(x, x, b + i * 64, 64);

      //Salsa20/8 Core is used as the hash function
      salsa20ProcessBlock(x, x, 8);

      //Let Y[i] = X
      osMemcpy(y + i * 64, x, 64);
   }

   //Let  B' = (Y[0], Y[2], ..., Y[2 * r - 2], Y[1], Y[3], ..., Y[2 * r - 1])
   for(i = 0; i < r; i++)
   {
      osMemcpy(b + i * 64, y + i * 128, 64);
      osMemcpy(b + (r + i) * 64, y + i * 128 + 64, 64);
   }
}


/**
 * @brief XOR operation
 * @param[out] x Block resulting from the XOR operation
 * @param[in] a First block
 * @param[in] b Second block
 * @param[in] n Size of the block
 **/

void scryptXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n)
{
   size_t i;

   //Perform XOR operation
   for(i = 0; i < n; i++)
   {
      x[i] = a[i] ^ b[i];
   }
}


#endif

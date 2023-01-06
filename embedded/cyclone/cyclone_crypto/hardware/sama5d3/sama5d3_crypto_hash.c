/**
 * @file sama5d3_crypto_hash.c
 * @brief SAMA5D3 hash hardware accelerator
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
#include "sama5d3x.h"
#include "core/crypto.h"
#include "hardware/sama5d3/sama5d3_crypto.h"
#include "hardware/sama5d3/sama5d3_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (SAMA5D3_CRYPTO_HASH_SUPPORT == ENABLED)


/**
 * @brief Process data block
 * @param[in] data Pointer to the data block
 * @param[in] length Length of the data block, in bytes
 **/

void hashProcessDataBlock(const uint8_t *data, size_t length)
{
   uint32_t *p;

   //Write the block to be processed in the input data registers
   p = (uint32_t *) data;
   SHA->SHA_IDATAR[0] = p[0];
   SHA->SHA_IDATAR[1] = p[1];
   SHA->SHA_IDATAR[2] = p[2];
   SHA->SHA_IDATAR[3] = p[3];
   SHA->SHA_IDATAR[4] = p[4];
   SHA->SHA_IDATAR[5] = p[5];
   SHA->SHA_IDATAR[6] = p[6];
   SHA->SHA_IDATAR[7] = p[7];
   SHA->SHA_IDATAR[8] = p[8];
   SHA->SHA_IDATAR[9] = p[9];
   SHA->SHA_IDATAR[10] = p[10];
   SHA->SHA_IDATAR[11] = p[11];
   SHA->SHA_IDATAR[12] = p[12];
   SHA->SHA_IDATAR[13] = p[13];
   SHA->SHA_IDATAR[14] = p[14];
   SHA->SHA_IDATAR[15] = p[15];

   //128-bit data block?
   if(length == 128)
   {
      SHA->SHA_IODATAR[0] = p[16];
      SHA->SHA_IODATAR[1] = p[17];
      SHA->SHA_IODATAR[2] = p[18];
      SHA->SHA_IODATAR[3] = p[19];
      SHA->SHA_IODATAR[4] = p[20];
      SHA->SHA_IODATAR[5] = p[21];
      SHA->SHA_IODATAR[6] = p[22];
      SHA->SHA_IODATAR[7] = p[23];
      SHA->SHA_IODATAR[8] = p[24];
      SHA->SHA_IODATAR[9] = p[25];
      SHA->SHA_IODATAR[10] = p[26];
      SHA->SHA_IODATAR[11] = p[27];
      SHA->SHA_IODATAR[12] = p[28];
      SHA->SHA_IODATAR[13] = p[29];
      SHA->SHA_IODATAR[14] = p[30];
      SHA->SHA_IODATAR[15] = p[31];
   }

   //Set the START bit to begin the processing
   SHA->SHA_CR = SHA_CR_START;

   //When processing completes, the DATRDY flag is raised
   while((SHA->SHA_ISR & SHA_ISR_DATRDY) == 0)
   {
   }
}


#if (SHA1_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-1
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha1Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   uint32_t *p;
   uint8_t buffer[64];

   //Acquire exclusive access to the SHA module
   osAcquireMutex(&sama5d3CryptoMutex);

   //Perform software reset
   SHA->SHA_CR = SHA_CR_SWRST;
   //Select the relevant hash algorithm
   SHA->SHA_MR = SHA_MR_ALGO_SHA1 | SHA_MR_SMOD_MANUAL_START;
   //For the first block of a message, the FIRST command must be set
   SHA->SHA_CR = SHA_CR_FIRST;

   //Digest the message
   for(n = length; n >= 64; n -= 64)
   {
      //Update hash value
      hashProcessDataBlock(data, 64);
      //Advance the data pointer
      data = (uint8_t *) data + 64;
   }

   //Copy the partial block, is any
   osMemset(buffer, 0, 64);
   osMemcpy(buffer, data, n);

   //Append the first byte of the padding string
   buffer[n] = 0x80;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(n >= 56)
   {
      hashProcessDataBlock(buffer, 64);
      osMemset(buffer, 0, 64);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 56);

   //Process the final block
   hashProcessDataBlock(buffer, 64);

   //Save the resulting hash value
   p = (uint32_t *) digest;
   p[0] = SHA->SHA_IODATAR[0];
   p[1] = SHA->SHA_IODATAR[1];
   p[2] = SHA->SHA_IODATAR[2];
   p[3] = SHA->SHA_IODATAR[3];
   p[4] = SHA->SHA_IODATAR[4];

   //Release exclusive access to the SHA module
   osReleaseMutex(&sama5d3CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#if (SHA224_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha224Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   uint32_t *p;
   uint8_t buffer[64];

   //Acquire exclusive access to the SHA module
   osAcquireMutex(&sama5d3CryptoMutex);

   //Perform software reset
   SHA->SHA_CR = SHA_CR_SWRST;
   //Select the relevant hash algorithm
   SHA->SHA_MR = SHA_MR_ALGO_SHA224 | SHA_MR_SMOD_MANUAL_START;
   //For the first block of a message, the FIRST command must be set
   SHA->SHA_CR = SHA_CR_FIRST;

   //Digest the message
   for(n = length; n >= 64; n -= 64)
   {
      //Update hash value
      hashProcessDataBlock(data, 64);
      //Advance the data pointer
      data = (uint8_t *) data + 64;
   }

   //Copy the partial block, is any
   osMemset(buffer, 0, 64);
   osMemcpy(buffer, data, n);

   //Append the first byte of the padding string
   buffer[n] = 0x80;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(n >= 56)
   {
      hashProcessDataBlock(buffer, 64);
      osMemset(buffer, 0, 64);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 56);

   //Process the final block
   hashProcessDataBlock(buffer, 64);

   //Save the resulting hash value
   p = (uint32_t *) digest;
   p[0] = SHA->SHA_IODATAR[0];
   p[1] = SHA->SHA_IODATAR[1];
   p[2] = SHA->SHA_IODATAR[2];
   p[3] = SHA->SHA_IODATAR[3];
   p[4] = SHA->SHA_IODATAR[4];
   p[5] = SHA->SHA_IODATAR[5];
   p[6] = SHA->SHA_IODATAR[6];

   //Release exclusive access to the SHA module
   osReleaseMutex(&sama5d3CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#if (SHA256_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha256Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   uint32_t *p;
   uint8_t buffer[64];

   //Acquire exclusive access to the SHA module
   osAcquireMutex(&sama5d3CryptoMutex);

   //Perform software reset
   SHA->SHA_CR = SHA_CR_SWRST;
   //Select the relevant hash algorithm
   SHA->SHA_MR = SHA_MR_ALGO_SHA256 | SHA_MR_SMOD_MANUAL_START;
   //For the first block of a message, the FIRST command must be set
   SHA->SHA_CR = SHA_CR_FIRST;

   //Digest the message
   for(n = length; n >= 64; n -= 64)
   {
      //Update hash value
      hashProcessDataBlock(data, 64);
      //Advance the data pointer
      data = (uint8_t *) data + 64;
   }

   //Copy the partial block, is any
   osMemset(buffer, 0, 64);
   osMemcpy(buffer, data, n);

   //Append the first byte of the padding string
   buffer[n] = 0x80;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(n >= 56)
   {
      hashProcessDataBlock(buffer, 64);
      osMemset(buffer, 0, 64);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 56);

   //Process the final block
   hashProcessDataBlock(buffer, 64);

   //Save the resulting hash value
   p = (uint32_t *) digest;
   p[0] = SHA->SHA_IODATAR[0];
   p[1] = SHA->SHA_IODATAR[1];
   p[2] = SHA->SHA_IODATAR[2];
   p[3] = SHA->SHA_IODATAR[3];
   p[4] = SHA->SHA_IODATAR[4];
   p[5] = SHA->SHA_IODATAR[5];
   p[6] = SHA->SHA_IODATAR[6];
   p[7] = SHA->SHA_IODATAR[7];

   //Release exclusive access to the SHA module
   osReleaseMutex(&sama5d3CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#if (SHA384_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-384
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha384Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   uint32_t *p;
   uint8_t buffer[128];

   //Acquire exclusive access to the SHA module
   osAcquireMutex(&sama5d3CryptoMutex);

   //Perform software reset
   SHA->SHA_CR = SHA_CR_SWRST;
   //Select the relevant hash algorithm
   SHA->SHA_MR = SHA_MR_ALGO_SHA384 | SHA_MR_SMOD_MANUAL_START;
   //For the first block of a message, the FIRST command must be set
   SHA->SHA_CR = SHA_CR_FIRST;

   //Digest the message
   for(n = length; n >= 128; n -= 128)
   {
      //Update hash value
      hashProcessDataBlock(data, 128);
      //Advance the data pointer
      data = (uint8_t *) data + 128;
   }

   //Copy the partial block, is any
   osMemset(buffer, 0, 128);
   osMemcpy(buffer, data, n);

   //Append the first byte of the padding string
   buffer[n] = 0x80;

   //Pad the message so that its length is congruent to 112 modulo 128
   if(n >= 112)
   {
      hashProcessDataBlock(buffer, 128);
      osMemset(buffer, 0, 128);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 120);

   //Process the final block
   hashProcessDataBlock(buffer, 128);

   //Save the resulting hash value
   p = (uint32_t *) digest;
   p[0] = SHA->SHA_IODATAR[0];
   p[1] = SHA->SHA_IODATAR[1];
   p[2] = SHA->SHA_IODATAR[2];
   p[3] = SHA->SHA_IODATAR[3];
   p[4] = SHA->SHA_IODATAR[4];
   p[5] = SHA->SHA_IODATAR[5];
   p[6] = SHA->SHA_IODATAR[6];
   p[7] = SHA->SHA_IODATAR[7];
   p[8] = SHA->SHA_IODATAR[8];
   p[9] = SHA->SHA_IODATAR[9];
   p[10] = SHA->SHA_IODATAR[10];
   p[11] = SHA->SHA_IODATAR[11];

   //Release exclusive access to the SHA module
   osReleaseMutex(&sama5d3CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#if (SHA512_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-512
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha512Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   uint32_t *p;
   uint8_t buffer[128];

   //Acquire exclusive access to the SHA module
   osAcquireMutex(&sama5d3CryptoMutex);

   //Perform software reset
   SHA->SHA_CR = SHA_CR_SWRST;
   //Select the relevant hash algorithm
   SHA->SHA_MR = SHA_MR_ALGO_SHA512 | SHA_MR_SMOD_MANUAL_START;
   //For the first block of a message, the FIRST command must be set
   SHA->SHA_CR = SHA_CR_FIRST;

   //Digest the message
   for(n = length; n >= 128; n -= 128)
   {
      //Update hash value
      hashProcessDataBlock(data, 128);
      //Advance the data pointer
      data = (uint8_t *) data + 128;
   }

   //Copy the partial block, is any
   osMemset(buffer, 0, 128);
   osMemcpy(buffer, data, n);

   //Append the first byte of the padding string
   buffer[n] = 0x80;

   //Pad the message so that its length is congruent to 112 modulo 128
   if(n >= 112)
   {
      hashProcessDataBlock(buffer, 128);
      osMemset(buffer, 0, 128);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 120);

   //Process the final block
   hashProcessDataBlock(buffer, 128);

   //Save the resulting hash value
   p = (uint32_t *) digest;
   p[0] = SHA->SHA_IODATAR[0];
   p[1] = SHA->SHA_IODATAR[1];
   p[2] = SHA->SHA_IODATAR[2];
   p[3] = SHA->SHA_IODATAR[3];
   p[4] = SHA->SHA_IODATAR[4];
   p[5] = SHA->SHA_IODATAR[5];
   p[6] = SHA->SHA_IODATAR[6];
   p[7] = SHA->SHA_IODATAR[7];
   p[8] = SHA->SHA_IODATAR[8];
   p[9] = SHA->SHA_IODATAR[9];
   p[10] = SHA->SHA_IODATAR[10];
   p[11] = SHA->SHA_IODATAR[11];
   p[12] = SHA->SHA_IODATAR[12];
   p[13] = SHA->SHA_IODATAR[13];
   p[14] = SHA->SHA_IODATAR[14];
   p[15] = SHA->SHA_IODATAR[15];

   //Release exclusive access to the SHA module
   osReleaseMutex(&sama5d3CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#endif

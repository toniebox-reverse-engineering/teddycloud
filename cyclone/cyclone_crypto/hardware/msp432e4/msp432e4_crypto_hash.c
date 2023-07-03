/**
 * @file msp432e4_crypto_hash.c
 * @brief MSP432E4 hash hardware accelerator
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
#include <stdint.h>
#include "msp432.h"
#include "inc/hw_shamd5.h"
#include "driverlib/types.h"
#include "core/crypto.h"
#include "hardware/msp432e4/msp432e4_crypto.h"
#include "hardware/msp432e4/msp432e4_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MSP432E4_CRYPTO_HASH_SUPPORT == ENABLED)


/**
 * @brief Reset SHA/MD5 module
 **/

void hashReset(void)
{
   uint32_t temp;

   //Perform software reset
   SHAMD5->SYSCONFIG |= SHAMD5_SYSCONFIG_SOFTRESET;

   //Wait for the reset to complete
   while((SHAMD5->SYSSTATUS & SHAMD5_SYSSTATUS_RESETDONE) == 0)
   {
   }

   //Force idle mode
   temp = SHAMD5->SYSCONFIG & ~SHAMD5_SYSCONFIG_SIDLE_M;
   SHAMD5->SYSCONFIG = temp | SHAMD5_SYSCONFIG_SIDLE_FORCE;
}


/**
 * @brief Update hash value
 * @param[in] data Pointer to the input buffer
 * @param[in] length Length of the input buffer
 * @param[out] digest Resulting digest value
 * @param[in] digestSize Size of the digest, in bytes
 **/

void hashProcessData(const uint8_t *data, size_t length, uint8_t *digest,
   size_t digestSize)
{
   size_t i;
   uint32_t temp;

   //Specify the length
   SHAMD5->LENGTH = length;

   //Digest input data
   while(length >= 64)
   {
      //Wait for the SHA/MD5 engine to be ready to accept data
      while((SHAMD5->IRQSTATUS & SHAMD5_IRQSTATUS_INPUT_READY) == 0)
      {
      }

      //Write 64-byte block
      SHAMD5->DATA_0_IN = LOAD32LE(data);
      SHAMD5->DATA_1_IN = LOAD32LE(data + 4);
      SHAMD5->DATA_2_IN = LOAD32LE(data + 8);
      SHAMD5->DATA_3_IN = LOAD32LE(data + 12);
      SHAMD5->DATA_4_IN = LOAD32LE(data + 16);
      SHAMD5->DATA_5_IN = LOAD32LE(data + 20);
      SHAMD5->DATA_6_IN = LOAD32LE(data + 24);
      SHAMD5->DATA_7_IN = LOAD32LE(data + 28);
      SHAMD5->DATA_8_IN = LOAD32LE(data + 32);
      SHAMD5->DATA_9_IN = LOAD32LE(data + 36);
      SHAMD5->DATA_10_IN = LOAD32LE(data + 40);
      SHAMD5->DATA_11_IN = LOAD32LE(data + 44);
      SHAMD5->DATA_12_IN = LOAD32LE(data + 48);
      SHAMD5->DATA_13_IN = LOAD32LE(data + 52);
      SHAMD5->DATA_14_IN = LOAD32LE(data + 56);
      SHAMD5->DATA_15_IN = LOAD32LE(data + 60);

      //Advance data pointer
      data += 64;
      length -= 64;
   }

   //Process final block
   if(length > 0)
   {
      //Wait for the SHA/MD5 engine to be ready to accept data
      while((SHAMD5->IRQSTATUS & SHAMD5_IRQSTATUS_INPUT_READY) == 0)
      {
      }

      //Write final block
      for(i = 0; i < length; i += 4)
      {
         //Write 32-bit word
         HWREG(SHAMD5_BASE + SHAMD5_O_DATA_0_IN + i) = LOAD32LE(data);
         //Advance data pointer
         data += 4;
      }
   }

   //Wait for the output to be ready
   while((SHAMD5->IRQSTATUS & SHAMD5_IRQSTATUS_OUTPUT_READY) == 0)
   {
   }

   //Read the resulting output value
   for(i = 0; i < digestSize; i += 4)
   {
      temp = HWREG(SHAMD5_BASE + SHAMD5_O_IDIGEST_A + i);
      STORE32LE(temp, digest + i);
   }
}


#if (MD5_SUPPORT == ENABLED)

/**
 * @brief Digest a message using MD5
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t md5Compute(const void *data, size_t length, uint8_t *digest)
{
   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_MD5 | SHAMD5_MODE_ALGO_CONSTANT |
      SHAMD5_MODE_CLOSE_HASH;

   //Digest the message
   hashProcessData(data, length, digest, MD5_DIGEST_SIZE);

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Initialize MD5 message digest context
 * @param[in] context Pointer to the MD5 context to initialize
 **/

void md5Init(Md5Context *context)
{
   //Set initial hash value
   context->h[0] = 0x67452301;
   context->h[1] = 0xEFCDAB89;
   context->h[2] = 0x98BADCFE;
   context->h[3] = 0x10325476;

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the MD5 context with a portion of the message being hashed
 * @param[in] context Pointer to the MD5 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void md5Update(Md5Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_MD5;

   //Restore hash context
   SHAMD5->IDIGEST_A = context->h[0];
   SHAMD5->IDIGEST_B = context->h[1];
   SHAMD5->IDIGEST_C = context->h[2];
   SHAMD5->IDIGEST_D = context->h[3];

   //Restore the value of the SHA_DIGEST_COUNT register
   SHAMD5->DIGEST_COUNT = context->totalSize;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //The length must be a multiple of 64 bytes
         n = length - (length % 64);

         //Update hash value
         hashProcessData(data, n, context->digest, MD5_DIGEST_SIZE);

         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 64 bytes
         n = MIN(length, 64 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the MD5 context
         context->size += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            hashProcessData(context->buffer, context->size, context->digest,
               MD5_DIGEST_SIZE);

            //Empty the buffer
            context->size = 0;
         }
      }
   }

   //Save the value of the SHA_DIGEST_COUNT register
   context->totalSize = SHAMD5->DIGEST_COUNT;

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);
}


/**
 * @brief Finish the MD5 message digest
 * @param[in] context Pointer to the MD5 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void md5Final(Md5Context *context, uint8_t *digest)
{
   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_MD5 | SHAMD5_MODE_CLOSE_HASH;

   //Restore hash context
   SHAMD5->IDIGEST_A = context->h[0];
   SHAMD5->IDIGEST_B = context->h[1];
   SHAMD5->IDIGEST_C = context->h[2];
   SHAMD5->IDIGEST_D = context->h[3];

   //Restore the value of the SHA_DIGEST_COUNT register
   SHAMD5->DIGEST_COUNT = context->totalSize;

   //Finish digest calculation
   hashProcessData(context->buffer, context->size, context->digest,
      MD5_DIGEST_SIZE);

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, MD5_DIGEST_SIZE);
   }
}


/**
 * @brief Finish the MD5 message digest (no padding added)
 * @param[in] context Pointer to the MD5 context
 * @param[out] digest Calculated digest
 **/

void md5FinalRaw(Md5Context *context, uint8_t *digest)
{
   //Copy the resulting digest
   osMemcpy(digest, context->digest, MD5_DIGEST_SIZE);
}

#endif
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
   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_SHA1 | SHAMD5_MODE_ALGO_CONSTANT |
      SHAMD5_MODE_CLOSE_HASH;

   //Digest the message
   hashProcessData(data, length, digest, SHA1_DIGEST_SIZE);

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Initialize SHA-1 message digest context
 * @param[in] context Pointer to the SHA-1 context to initialize
 **/

void sha1Init(Sha1Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH32(0x67452301);
   context->h[1] = BETOH32(0xEFCDAB89);
   context->h[2] = BETOH32(0x98BADCFE);
   context->h[3] = BETOH32(0x10325476);
   context->h[4] = BETOH32(0xC3D2E1F0);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the SHA-1 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-1 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha1Update(Sha1Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_SHA1;

   //Restore hash context
   SHAMD5->IDIGEST_A = context->h[0];
   SHAMD5->IDIGEST_B = context->h[1];
   SHAMD5->IDIGEST_C = context->h[2];
   SHAMD5->IDIGEST_D = context->h[3];
   SHAMD5->IDIGEST_E = context->h[4];

   //Restore the value of the SHA_DIGEST_COUNT register
   SHAMD5->DIGEST_COUNT = context->totalSize;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //The length must be a multiple of 64 bytes
         n = length - (length % 64);

         //Update hash value
         hashProcessData(data, n, context->digest, SHA1_DIGEST_SIZE);

         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 64 bytes
         n = MIN(length, 64 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-1 context
         context->size += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            hashProcessData(context->buffer, context->size, context->digest,
               SHA1_DIGEST_SIZE);

            //Empty the buffer
            context->size = 0;
         }
      }
   }

   //Save the value of the SHA_DIGEST_COUNT register
   context->totalSize = SHAMD5->DIGEST_COUNT;

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);
}


/**
 * @brief Finish the SHA-1 message digest
 * @param[in] context Pointer to the SHA-1 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha1Final(Sha1Context *context, uint8_t *digest)
{
   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_SHA1 | SHAMD5_MODE_CLOSE_HASH;

   //Restore hash context
   SHAMD5->IDIGEST_A = context->h[0];
   SHAMD5->IDIGEST_B = context->h[1];
   SHAMD5->IDIGEST_C = context->h[2];
   SHAMD5->IDIGEST_D = context->h[3];
   SHAMD5->IDIGEST_E = context->h[4];

   //Restore the value of the SHA_DIGEST_COUNT register
   SHAMD5->DIGEST_COUNT = context->totalSize;

   //Finish digest calculation
   hashProcessData(context->buffer, context->size, context->digest,
      SHA1_DIGEST_SIZE);

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA1_DIGEST_SIZE);
   }
}


/**
 * @brief Finish the SHA-1 message digest (no padding added)
 * @param[in] context Pointer to the SHA-1 context
 * @param[out] digest Calculated digest
 **/

void sha1FinalRaw(Sha1Context *context, uint8_t *digest)
{
   //Copy the resulting digest
   osMemcpy(digest, context->digest, SHA1_DIGEST_SIZE);
}

#endif
#if (SHA224_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-224
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha224Compute(const void *data, size_t length, uint8_t *digest)
{
   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_SHA224 | SHAMD5_MODE_ALGO_CONSTANT |
      SHAMD5_MODE_CLOSE_HASH;

   //Digest the message
   hashProcessData(data, length, digest, SHA224_DIGEST_SIZE);

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Initialize SHA-224 message digest context
 * @param[in] context Pointer to the SHA-224 context to initialize
 **/

void sha224Init(Sha224Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH32(0xC1059ED8);
   context->h[1] = BETOH32(0x367CD507);
   context->h[2] = BETOH32(0x3070DD17);
   context->h[3] = BETOH32(0xF70E5939);
   context->h[4] = BETOH32(0xFFC00B31);
   context->h[5] = BETOH32(0x68581511);
   context->h[6] = BETOH32(0x64F98FA7);
   context->h[7] = BETOH32(0xBEFA4FA4);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Finish the SHA-224 message digest
 * @param[in] context Pointer to the SHA-224 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha224Final(Sha224Context *context, uint8_t *digest)
{
   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_SHA224 | SHAMD5_MODE_CLOSE_HASH;

   //Restore hash context
   SHAMD5->IDIGEST_A = context->h[0];
   SHAMD5->IDIGEST_B = context->h[1];
   SHAMD5->IDIGEST_C = context->h[2];
   SHAMD5->IDIGEST_D = context->h[3];
   SHAMD5->IDIGEST_E = context->h[4];
   SHAMD5->IDIGEST_F = context->h[5];
   SHAMD5->IDIGEST_G = context->h[6];
   SHAMD5->IDIGEST_H = context->h[7];

   //Restore the value of the SHA_DIGEST_COUNT register
   SHAMD5->DIGEST_COUNT = context->totalSize;

   //Finish digest calculation
   hashProcessData(context->buffer, context->size, context->digest,
      SHA224_DIGEST_SIZE);

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA224_DIGEST_SIZE);
   }
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
   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_SHA256 | SHAMD5_MODE_ALGO_CONSTANT |
      SHAMD5_MODE_CLOSE_HASH;

   //Digest the message
   hashProcessData(data, length, digest, SHA256_DIGEST_SIZE);

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Initialize SHA-256 message digest context
 * @param[in] context Pointer to the SHA-256 context to initialize
 **/

void sha256Init(Sha256Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH32(0x6A09E667);
   context->h[1] = BETOH32(0xBB67AE85);
   context->h[2] = BETOH32(0x3C6EF372);
   context->h[3] = BETOH32(0xA54FF53A);
   context->h[4] = BETOH32(0x510E527F);
   context->h[5] = BETOH32(0x9B05688C);
   context->h[6] = BETOH32(0x1F83D9AB);
   context->h[7] = BETOH32(0x5BE0CD19);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the SHA-256 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha256Update(Sha256Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_SHA256;

   //Restore hash context
   SHAMD5->IDIGEST_A = context->h[0];
   SHAMD5->IDIGEST_B = context->h[1];
   SHAMD5->IDIGEST_C = context->h[2];
   SHAMD5->IDIGEST_D = context->h[3];
   SHAMD5->IDIGEST_E = context->h[4];
   SHAMD5->IDIGEST_F = context->h[5];
   SHAMD5->IDIGEST_G = context->h[6];
   SHAMD5->IDIGEST_H = context->h[7];

   //Restore the value of the SHA_DIGEST_COUNT register
   SHAMD5->DIGEST_COUNT = context->totalSize;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //The length must be a multiple of 64 bytes
         n = length - (length % 64);

         //Update hash value
         hashProcessData(data, n, context->digest, SHA256_DIGEST_SIZE);

         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 64 bytes
         n = MIN(length, 64 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-256 context
         context->size += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            hashProcessData(context->buffer, context->size, context->digest,
               SHA256_DIGEST_SIZE);

            //Empty the buffer
            context->size = 0;
         }
      }
   }

   //Save the value of the SHA_DIGEST_COUNT register
   context->totalSize = SHAMD5->DIGEST_COUNT;

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);
}


/**
 * @brief Finish the SHA-256 message digest
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha256Final(Sha256Context *context, uint8_t *digest)
{
   //Acquire exclusive access to the SHA/MD5 module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Reset the SHA/MD5 module before use
   hashReset();

   //Configure the SHA/MD5 module
   SHAMD5->MODE = SHAMD5_MODE_ALGO_SHA256 | SHAMD5_MODE_CLOSE_HASH;

   //Restore hash context
   SHAMD5->IDIGEST_A = context->h[0];
   SHAMD5->IDIGEST_B = context->h[1];
   SHAMD5->IDIGEST_C = context->h[2];
   SHAMD5->IDIGEST_D = context->h[3];
   SHAMD5->IDIGEST_E = context->h[4];
   SHAMD5->IDIGEST_F = context->h[5];
   SHAMD5->IDIGEST_G = context->h[6];
   SHAMD5->IDIGEST_H = context->h[7];

   //Restore the value of the SHA_DIGEST_COUNT register
   SHAMD5->DIGEST_COUNT = context->totalSize;

   //Finish digest calculation
   hashProcessData(context->buffer, context->size, context->digest,
      SHA256_DIGEST_SIZE);

   //Release exclusive access to the SHA/MD5 module
   osReleaseMutex(&msp432e4CryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA256_DIGEST_SIZE);
   }
}


/**
 * @brief Finish the SHA-256 message digest (no padding added)
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest
 **/

void sha256FinalRaw(Sha256Context *context, uint8_t *digest)
{
   //Copy the resulting digest
   osMemcpy(digest, context->digest, SHA256_DIGEST_SIZE);
}

#endif
#endif

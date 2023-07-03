/**
 * @file yarrow.c
 * @brief Yarrow PRNG
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
#include "rng/yarrow.h"
#include "debug.h"

//Check crypto library configuration
#if (YARROW_SUPPORT == ENABLED)

//Common interface for PRNG algorithms
const PrngAlgo yarrowPrngAlgo =
{
   "Yarrow",
   sizeof(YarrowContext),
   (PrngAlgoInit) yarrowInit,
   (PrngAlgoSeed) yarrowSeed,
   (PrngAlgoAddEntropy) yarrowAddEntropy,
   (PrngAlgoRead) yarrowRead,
   (PrngAlgoDeinit) yarrowDeinit
};


/**
 * @brief Initialize PRNG context
 * @param[in] context Pointer to the PRNG context to initialize
 * @return Error code
 **/

error_t yarrowInit(YarrowContext *context)
{
   //Clear PRNG state
   osMemset(context, 0, sizeof(YarrowContext));

   //Create a mutex to prevent simultaneous access to the PRNG state
   if(!osCreateMutex(&context->mutex))
   {
      //Failed to create mutex
      return ERROR_OUT_OF_RESOURCES;
   }

   //Initialize hash contexts
   sha256Init(&context->fastPool);
   sha256Init(&context->slowPool);

   //The PRNG is not ready to generate random data
   context->ready = FALSE;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Seed the PRNG state
 * @param[in] context Pointer to the PRNG context
 * @param[in] input Pointer to the input data
 * @param[in] length Length of the input data
 * @return Error code
 **/

error_t yarrowSeed(YarrowContext *context, const uint8_t *input, size_t length)
{
   //Check parameters
   if(length < sizeof(context->key))
      return ERROR_INVALID_PARAMETER;

   //Add entropy to the fast pool
   sha256Update(&context->fastPool, input, length);
   //Reseed from the fast pool
   yarrowFastReseed(context);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Add entropy to the PRNG state
 * @param[in] context Pointer to the PRNG context
 * @param[in] source Entropy source identifier
 * @param[in] input Pointer to the input data
 * @param[in] length Length of the input data
 * @param[in] entropy Actual number of bits of entropy
 * @return Error code
 **/

error_t yarrowAddEntropy(YarrowContext *context, uint_t source,
   const uint8_t *input, size_t length, size_t entropy)
{
   uint_t i;
   uint_t k;

   //Check parameters
   if(source >= YARROW_N)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //Entropy from samples are collected into two pools
   if(context->currentPool[source] == YARROW_FAST_POOL_ID)
   {
      //Each pool contains running hash of all inputs since last reseed
      sha256Update(&context->fastPool, input, length);
      //Estimate the amount of entropy we have collected thus far
      context->fastPoolEntropy[source] += entropy;

      //Reseed when any source estimate reaches 100 bits
      if(context->fastPoolEntropy[source] >= YARROW_FAST_THRESHOLD)
      {
         yarrowFastReseed(context);
      }

      //The samples from each source alternate between the two pools
      context->currentPool[source] = YARROW_SLOW_POOL_ID;
   }
   else
   {
      //Each pool contains running hash of all inputs since last reseed
      sha256Update(&context->slowPool, input, length);
      //Estimate the amount of entropy we have collected thus far
      context->slowPoolEntropy[source] += entropy;

      //Prevent overflows while adding up the entropy estimate
      if(context->slowPoolEntropy[source] >= YARROW_SLOW_THRESHOLD)
      {
         context->slowPoolEntropy[source] = YARROW_SLOW_THRESHOLD;
      }

      //At least two different sources must be over 160 bits in the slow
      //pool before the slow pool reseeds
      for(k = 0, i = 0; i < YARROW_N; i++)
      {
         //Check whether the current source has hit the threshold
         if(context->slowPoolEntropy[i] >= YARROW_SLOW_THRESHOLD)
         {
            k++;
         }
      }

      //Reseed from the slow pool?
      if(k >= YARROW_K)
      {
         yarrowSlowReseed(context);
      }

      //The samples from each source alternate between the two pools
      context->currentPool[source] = YARROW_FAST_POOL_ID;
   }

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Read random data
 * @param[in] context Pointer to the PRNG context
 * @param[out] output Buffer where to store the output data
 * @param[in] length Desired length in bytes
 * @return Error code
 **/

error_t yarrowRead(YarrowContext *context, uint8_t *output, size_t length)
{
   size_t n;
   uint8_t buffer[AES_BLOCK_SIZE];

   //Make sure that the PRNG has been properly seeded
   if(!context->ready)
      return ERROR_PRNG_NOT_READY;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //Generate random data in a block-by-block fashion
   while(length > 0)
   {
      //Number of bytes to process at a time
      n = MIN(length, AES_BLOCK_SIZE);

      //Generate a random block
      yarrowGenerateBlock(context, buffer);
      //Copy data to the output buffer
      osMemcpy(output, buffer, n);

      //We keep track of how many blocks we have output
      context->blockCount++;

      //Next block
      output += n;
      length -= n;
   }

   //Apply generator gate?
   if(context->blockCount >= YARROW_PG)
   {
      //Erase AES context
      aesDeinit(&context->cipherContext);

      //Generate some random bytes
      yarrowGenerateBlock(context, context->key);
      //Use them as the new key
      aesInit(&context->cipherContext, context->key, sizeof(context->key));

      //Reset block counter
      context->blockCount = 0;
   }

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Generate a random block of data
 * @param[in] context Pointer to the PRNG context
 * @param[out] output Buffer where to store the output block
 **/

void yarrowGenerateBlock(YarrowContext *context, uint8_t *output)
{
   int_t i;

   //Encrypt counter block
   aesEncryptBlock(&context->cipherContext, context->counter, output);

   //Increment counter value
   for(i = AES_BLOCK_SIZE - 1; i >= 0; i--)
   {
      //Increment the current byte and propagate the carry if necessary
      if(++(context->counter[i]) != 0)
      {
         break;
      }
   }
}


/**
 * @brief Reseed from the fast pool
 * @param[in] context Pointer to the PRNG context
 **/

void yarrowFastReseed(YarrowContext *context)
{
   size_t i;

   //Erase AES context
   if(context->ready)
   {
      aesDeinit(&context->cipherContext);
   }

   //Reseeding from the fast pool use the current key and the hash of all
   //inputs to the fast pool since the last reseed, to generate a new key
   sha256Update(&context->fastPool, context->key, sizeof(context->key));
   sha256Final(&context->fastPool, context->key);

   //Set the new key
   aesInit(&context->cipherContext, context->key, sizeof(context->key));

   //Define the new value of the counter
   osMemset(context->counter, 0, sizeof(context->counter));
   aesEncryptBlock(&context->cipherContext, context->counter, context->counter);

   //Reset the hash context
   sha256Init(&context->fastPool);

   //The entropy estimates for the fast pool are all reset to zero
   for(i = 0; i < YARROW_N; i++)
   {
      context->fastPoolEntropy[i] = 0;
   }

   //The PRNG is ready to generate random data
   context->ready = TRUE;
}


/**
 * @brief Reseed from the slow pool
 * @param[in] context Pointer to the PRNG context
 **/

void yarrowSlowReseed(YarrowContext *context)
{
   size_t i;

   //Erase AES context
   if(context->ready)
   {
      aesDeinit(&context->cipherContext);
   }

   //Compute the hash of all inputs to the fast pool
   sha256Final(&context->fastPool, NULL);

   //Reseeding from the slow pool use the current key, the hash of all inputs to the
   //fast pool and the hash of all inputs to the slow pool, to generate a new key
   sha256Update(&context->slowPool, context->key, sizeof(context->key));
   sha256Update(&context->slowPool, context->fastPool.digest, SHA256_DIGEST_SIZE);
   sha256Final(&context->slowPool, context->key);

   //Set the new key
   aesInit(&context->cipherContext, context->key, sizeof(context->key));

   //Define the new value of the counter
   osMemset(context->counter, 0, sizeof(context->counter));
   aesEncryptBlock(&context->cipherContext, context->counter, context->counter);

   //Reset the hash contexts
   sha256Init(&context->fastPool);
   sha256Init(&context->slowPool);

   //The entropy estimates for both pools are reset to zero
   for(i = 0; i < YARROW_N; i++)
   {
      context->fastPoolEntropy[i] = 0;
      context->slowPoolEntropy[i] = 0;
   }

   //The PRNG is ready to generate random data
   context->ready = TRUE;
}


/**
 * @brief Release PRNG context
 * @param[in] context Pointer to the PRNG context
 **/

void yarrowDeinit(YarrowContext *context)
{
   //Erase AES context
   if(context->ready)
   {
      aesDeinit(&context->cipherContext);
   }

   //Free previously allocated resources
   osDeleteMutex(&context->mutex);

   //Clear PRNG state
   osMemset(context, 0, sizeof(YarrowContext));
}

#endif

/**
 * @file mkv5x_crypto_hash.c
 * @brief Kinetis KV5x hash hardware accelerator
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
#include "fsl_device_registers.h"
#include "fsl_mmcau.h"
#include "core/crypto.h"
#include "hardware/mkv5x/mkv5x_crypto.h"
#include "hardware/mkv5x/mkv5x_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MKV5X_CRYPTO_HASH_SUPPORT == ENABLED)
#if (MD5_SUPPORT == ENABLED)

/**
 * @brief Update the MD5 context with a portion of the message being hashed
 * @param[in] context Pointer to the MD5 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void md5Update(Md5Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //Update hash value
         MMCAU_MD5_HashN(data, 1, context->h);

         //Update the MD5 context
         context->totalSize += 64;
         //Advance the data pointer
         data = (uint8_t *) data + 64;
         //Remaining bytes to process
         length -= 64;
      }
      else
      {
         //The buffer can hold at most 64 bytes
         n = MIN(length, 64 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the MD5 context
         context->size += n;
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            MMCAU_MD5_HashN(context->buffer, 1, context->h);
            //Empty the buffer
            context->size = 0;
         }
      }
   }

   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the MD5 context
 **/

void md5ProcessBlock(Md5Context *context)
{
   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);
   //Accelerate MD5 inner compression loop
   MMCAU_MD5_HashN(context->buffer, 1, context->h);
   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);
}

#endif
#if (SHA1_SUPPORT == ENABLED)

/**
 * @brief Update the SHA-1 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-1 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha1Update(Sha1Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //Update hash value
         MMCAU_SHA1_HashN(data, 1, context->h);

         //Update the SHA-1 context
         context->totalSize += 64;
         //Advance the data pointer
         data = (uint8_t *) data + 64;
         //Remaining bytes to process
         length -= 64;
      }
      else
      {
         //The buffer can hold at most 64 bytes
         n = MIN(length, 64 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-1 context
         context->size += n;
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            MMCAU_SHA1_HashN(context->buffer, 1, context->h);
            //Empty the buffer
            context->size = 0;
         }
      }
   }

   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SHA-1 context
 **/

void sha1ProcessBlock(Sha1Context *context)
{
   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);
   //Accelerate SHA-1 inner compression loop
   MMCAU_SHA1_HashN(context->buffer, 1, context->h);
   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);
}

#endif
#if (SHA256_SUPPORT == ENABLED)

/**
 * @brief Update the SHA-256 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha256Update(Sha256Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //Update hash value
         MMCAU_SHA256_HashN(data, 1, context->h);

         //Update the SHA-256 context
         context->totalSize += 64;
         //Advance the data pointer
         data = (uint8_t *) data + 64;
         //Remaining bytes to process
         length -= 64;
      }
      else
      {
         //The buffer can hold at most 64 bytes
         n = MIN(length, 64 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-256 context
         context->size += n;
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            MMCAU_SHA256_HashN(context->buffer, 1, context->h);
            //Empty the buffer
            context->size = 0;
         }
      }
   }

   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SHA-256 context
 **/

void sha256ProcessBlock(Sha256Context *context)
{
   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);
   //Accelerate SHA-256 inner compression loop
   MMCAU_SHA256_HashN(context->buffer, 1, context->h);
   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);
}

#endif
#endif

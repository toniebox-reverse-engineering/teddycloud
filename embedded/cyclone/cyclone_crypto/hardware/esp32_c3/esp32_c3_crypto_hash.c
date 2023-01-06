/**
 * @file esp32_c3_crypto_hash.c
 * @brief ESP32-C3 hash hardware accelerator
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
#include "esp_crypto_lock.h"
#include "hal/sha_types.h"
#include "soc/hwcrypto_reg.h"
#include "driver/periph_ctrl.h"
#include "core/crypto.h"
#include "hardware/esp32_c3/esp32_c3_crypto.h"
#include "hardware/esp32_c3/esp32_c3_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (ESP32_C3_CRYPTO_HASH_SUPPORT == ENABLED)

//Padding string
static const uint8_t padding[64] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/**
 * @brief SHA module initialization
 **/

void esp32c3ShaInit(void)
{
}


/**
 * @brief Update hash value
 * @param[in] algo Hash algorithm
 * @param[in] data Pointer to the input buffer
 * @param[in] length Length of the input buffer
 * @param[in,out] h Hash value
 **/

void hashProcessData(uint32_t algo, const uint8_t *data, size_t length,
   uint32_t *h)
{
   uint32_t temp;
   size_t blockSize;

   //Get block size
   blockSize = (algo <= SHA_MODE_SHA256) ? 64 : 128;

   //Acquire exclusive access to the SHA module
   esp_crypto_sha_aes_lock_acquire();
   //Enable SHA module
   periph_module_enable(PERIPH_SHA_MODULE);

   //Select the relevant hash algorithm
   REG_WRITE(SHA_MODE_REG, algo);

   //Restore initial hash value
   REG_WRITE(SHA_H_BASE, h[0]);
   REG_WRITE(SHA_H_BASE + 4, h[1]);
   REG_WRITE(SHA_H_BASE + 8, h[2]);
   REG_WRITE(SHA_H_BASE + 12, h[3]);
   REG_WRITE(SHA_H_BASE + 16, h[4]);

   //SHA-224 or SHA-256 algorithm?
   if(algo >= SHA_MODE_SHA224)
   {
      REG_WRITE(SHA_H_BASE + 20, h[5]);
      REG_WRITE(SHA_H_BASE + 24, h[6]);
      REG_WRITE(SHA_H_BASE + 28, h[7]);
   }

   //Input data are processed in a block-by-block fashion
   while(length >= blockSize)
   {
      //Write the block to be processed in the data registers
      temp = LOAD32LE(data);
      REG_WRITE(SHA_TEXT_BASE, temp);
      temp = LOAD32LE(data + 4);
      REG_WRITE(SHA_TEXT_BASE + 4, temp);
      temp = LOAD32LE(data + 8);
      REG_WRITE(SHA_TEXT_BASE + 8, temp);
      temp = LOAD32LE(data + 12);
      REG_WRITE(SHA_TEXT_BASE + 12, temp);
      temp = LOAD32LE(data + 16);
      REG_WRITE(SHA_TEXT_BASE + 16, temp);
      temp = LOAD32LE(data + 20);
      REG_WRITE(SHA_TEXT_BASE + 20, temp);
      temp = LOAD32LE(data + 24);
      REG_WRITE(SHA_TEXT_BASE + 24, temp);
      temp = LOAD32LE(data + 28);
      REG_WRITE(SHA_TEXT_BASE + 28, temp);
      temp = LOAD32LE(data + 32);
      REG_WRITE(SHA_TEXT_BASE + 32, temp);
      temp = LOAD32LE(data + 36);
      REG_WRITE(SHA_TEXT_BASE + 36, temp);
      temp = LOAD32LE(data + 40);
      REG_WRITE(SHA_TEXT_BASE + 40, temp);
      temp = LOAD32LE(data + 44);
      REG_WRITE(SHA_TEXT_BASE + 44, temp);
      temp = LOAD32LE(data + 48);
      REG_WRITE(SHA_TEXT_BASE + 48, temp);
      temp = LOAD32LE(data + 52);
      REG_WRITE(SHA_TEXT_BASE + 52, temp);
      temp = LOAD32LE(data + 56);
      REG_WRITE(SHA_TEXT_BASE + 56, temp);
      temp = LOAD32LE(data + 60);
      REG_WRITE(SHA_TEXT_BASE + 60, temp);

      //Start the SHA accelerator
      REG_WRITE(SHA_CONTINUE_REG, 1);

      //Wait for the operation to complete
      while(REG_READ(SHA_BUSY_REG) != 0)
      {
      }

      //Advance data pointer
      data += blockSize;
      length -= blockSize;
   }

   //Save intermediate hash value
   h[0] = REG_READ(SHA_H_BASE);
   h[1] = REG_READ(SHA_H_BASE + 4);
   h[2] = REG_READ(SHA_H_BASE + 8);
   h[3] = REG_READ(SHA_H_BASE + 12);
   h[4] = REG_READ(SHA_H_BASE + 16);

   //SHA-224 or SHA-256 algorithm?
   if(algo >= SHA_MODE_SHA224)
   {
      h[5] = REG_READ(SHA_H_BASE + 20);
      h[6] = REG_READ(SHA_H_BASE + 24);
      h[7] = REG_READ(SHA_H_BASE + 28);
   }

   //Disable SHA module
   periph_module_disable(PERIPH_SHA_MODULE);
   //Release exclusive access to the SHA module
   esp_crypto_sha_aes_lock_release();
}


#if (SHA1_SUPPORT == ENABLED)

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

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //The length must be a multiple of 64 bytes
         n = length - (length % 64);

         //Update hash value
         hashProcessData(SHA_MODE_SHA1, data, n, context->h);

         //Update the SHA-1 context
         context->totalSize += n;
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
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            hashProcessData(SHA_MODE_SHA1, context->buffer, context->size,
               context->h);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Finish the SHA-1 message digest
 * @param[in] context Pointer to the SHA-1 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha1Final(Sha1Context *context, uint8_t *digest)
{
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(context->size < 56)
   {
      paddingSize = 56 - context->size;
   }
   else
   {
      paddingSize = 64 + 56 - context->size;
   }

   //Append padding
   sha1Update(context, padding, paddingSize);

   //Append the length of the original message
   context->w[14] = htobe32((uint32_t) (totalSize >> 32));
   context->w[15] = htobe32((uint32_t) totalSize);

   //Calculate the message digest
   hashProcessData(SHA_MODE_SHA1, context->buffer, 64, context->h);

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

#endif
#if (SHA256_SUPPORT == ENABLED)

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

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //The length must be a multiple of 64 bytes
         n = length - (length % 64);

         //Update hash value
         hashProcessData(SHA_MODE_SHA256, data, n, context->h);

         //Update the SHA-256 context
         context->totalSize += n;
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
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            hashProcessData(SHA_MODE_SHA256, context->buffer, context->size,
               context->h);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Finish the SHA-256 message digest
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha256Final(Sha256Context *context, uint8_t *digest)
{
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(context->size < 56)
   {
      paddingSize = 56 - context->size;
   }
   else
   {
      paddingSize = 64 + 56 - context->size;
   }

   //Append padding
   sha256Update(context, padding, paddingSize);

   //Append the length of the original message
   context->w[14] = htobe32((uint32_t) (totalSize >> 32));
   context->w[15] = htobe32((uint32_t) totalSize);

   //Calculate the message digest
   hashProcessData(SHA_MODE_SHA256, context->buffer, 64, context->h);

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

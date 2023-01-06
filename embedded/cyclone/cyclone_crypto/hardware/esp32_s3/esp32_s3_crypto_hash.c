/**
 * @file esp32_s3_crypto_hash.c
 * @brief ESP32-S3 hash hardware accelerator
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
#include "hardware/esp32_s3/esp32_s3_crypto.h"
#include "hardware/esp32_s3/esp32_s3_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (ESP32_S3_CRYPTO_HASH_SUPPORT == ENABLED)

//Padding string
static const uint8_t padding[128] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/**
 * @brief SHA module initialization
 **/

void esp32s3ShaInit(void)
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

   //SHA-224, SHA-256, SHA-384 or SHA-512 algorithm?
   if(algo >= SHA_MODE_SHA224)
   {
      REG_WRITE(SHA_H_BASE + 20, h[5]);
      REG_WRITE(SHA_H_BASE + 24, h[6]);
      REG_WRITE(SHA_H_BASE + 28, h[7]);
   }

   //SHA-384 or SHA-512 algorithm?
   if(algo >= SHA_MODE_SHA384)
   {
      REG_WRITE(SHA_H_BASE + 32, h[8]);
      REG_WRITE(SHA_H_BASE + 36, h[9]);
      REG_WRITE(SHA_H_BASE + 40, h[10]);
      REG_WRITE(SHA_H_BASE + 44, h[11]);
      REG_WRITE(SHA_H_BASE + 48, h[12]);
      REG_WRITE(SHA_H_BASE + 52, h[13]);
      REG_WRITE(SHA_H_BASE + 56, h[14]);
      REG_WRITE(SHA_H_BASE + 60, h[15]);
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

      //128-bit data block?
      if(algo >= SHA_MODE_SHA384)
      {
         temp = LOAD32LE(data + 64);
         REG_WRITE(SHA_TEXT_BASE + 64, temp);
         temp = LOAD32LE(data + 68);
         REG_WRITE(SHA_TEXT_BASE + 68, temp);
         temp = LOAD32LE(data + 72);
         REG_WRITE(SHA_TEXT_BASE + 72, temp);
         temp = LOAD32LE(data + 76);
         REG_WRITE(SHA_TEXT_BASE + 76, temp);
         temp = LOAD32LE(data + 80);
         REG_WRITE(SHA_TEXT_BASE + 80, temp);
         temp = LOAD32LE(data + 84);
         REG_WRITE(SHA_TEXT_BASE + 84, temp);
         temp = LOAD32LE(data + 88);
         REG_WRITE(SHA_TEXT_BASE + 88, temp);
         temp = LOAD32LE(data + 92);
         REG_WRITE(SHA_TEXT_BASE + 92, temp);
         temp = LOAD32LE(data + 96);
         REG_WRITE(SHA_TEXT_BASE + 96, temp);
         temp = LOAD32LE(data + 100);
         REG_WRITE(SHA_TEXT_BASE + 100, temp);
         temp = LOAD32LE(data + 104);
         REG_WRITE(SHA_TEXT_BASE + 104, temp);
         temp = LOAD32LE(data + 108);
         REG_WRITE(SHA_TEXT_BASE + 108, temp);
         temp = LOAD32LE(data + 112);
         REG_WRITE(SHA_TEXT_BASE + 112, temp);
         temp = LOAD32LE(data + 116);
         REG_WRITE(SHA_TEXT_BASE + 116, temp);
         temp = LOAD32LE(data + 120);
         REG_WRITE(SHA_TEXT_BASE + 120, temp);
         temp = LOAD32LE(data + 124);
         REG_WRITE(SHA_TEXT_BASE + 124, temp);
      }

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

   //SHA-224, SHA-256, SHA-384 or SHA-512 algorithm?
   if(algo >= SHA_MODE_SHA224)
   {
      h[5] = REG_READ(SHA_H_BASE + 20);
      h[6] = REG_READ(SHA_H_BASE + 24);
      h[7] = REG_READ(SHA_H_BASE + 28);
   }

   //SHA-384 or SHA-512 algorithm?
   if(algo >= SHA_MODE_SHA384)
   {
      h[8] = REG_READ(SHA_H_BASE + 32);
      h[9] = REG_READ(SHA_H_BASE + 36);
      h[10] = REG_READ(SHA_H_BASE + 40);
      h[11] = REG_READ(SHA_H_BASE + 44);
      h[12] = REG_READ(SHA_H_BASE + 48);
      h[13] = REG_READ(SHA_H_BASE + 52);
      h[14] = REG_READ(SHA_H_BASE + 56);
      h[15] = REG_READ(SHA_H_BASE + 60);
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
#if (SHA384_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-384 message digest context
 * @param[in] context Pointer to the SHA-384 context to initialize
 **/

void sha384Init(Sha384Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0xCBBB9D5DC1059ED8);
   context->h[1] = BETOH64(0x629A292A367CD507);
   context->h[2] = BETOH64(0x9159015A3070DD17);
   context->h[3] = BETOH64(0x152FECD8F70E5939);
   context->h[4] = BETOH64(0x67332667FFC00B31);
   context->h[5] = BETOH64(0x8EB44A8768581511);
   context->h[6] = BETOH64(0xDB0C2E0D64F98FA7);
   context->h[7] = BETOH64(0x47B5481DBEFA4FA4);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Finish the SHA-384 message digest (no padding added)
 * @param[in] context Pointer to the SHA-384 context
 * @param[out] digest Calculated digest
 **/

void sha384FinalRaw(Sha384Context *context, uint8_t *digest)
{
   //Copy the resulting digest
   osMemcpy(digest, context->digest, SHA384_DIGEST_SIZE);
}

#endif
#if (SHA512_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-512 message digest context
 * @param[in] context Pointer to the SHA-512 context to initialize
 **/

void sha512Init(Sha512Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0x6A09E667F3BCC908);
   context->h[1] = BETOH64(0xBB67AE8584CAA73B);
   context->h[2] = BETOH64(0x3C6EF372FE94F82B);
   context->h[3] = BETOH64(0xA54FF53A5F1D36F1);
   context->h[4] = BETOH64(0x510E527FADE682D1);
   context->h[5] = BETOH64(0x9B05688C2B3E6C1F);
   context->h[6] = BETOH64(0x1F83D9ABFB41BD6B);
   context->h[7] = BETOH64(0x5BE0CD19137E2179);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the SHA-512 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-512 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha512Update(Sha512Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 128)
      {
         //The length must be a multiple of 128 bytes
         n = length - (length % 128);

         //Update hash value
         hashProcessData(SHA_MODE_SHA512, data, n, (uint32_t *) context->h);

         //Update the SHA-512 context
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 128 bytes
         n = MIN(length, 128 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-512 context
         context->size += n;
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 128)
         {
            //Update hash value
            hashProcessData(SHA_MODE_SHA512, context->buffer, context->size,
               (uint32_t *) context->h);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Finish the SHA-512 message digest
 * @param[in] context Pointer to the SHA-512 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha512Final(Sha512Context *context, uint8_t *digest)
{
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 112 modulo 128
   if(context->size < 112)
   {
      paddingSize = 112 - context->size;
   }
   else
   {
      paddingSize = 128 + 112 - context->size;
   }

   //Append padding
   sha512Update(context, padding, paddingSize);

   //Append the length of the original message
   context->w[14] = 0;
   context->w[15] = htobe64(totalSize);

   //Calculate the message digest
   hashProcessData(SHA_MODE_SHA512, context->buffer, 128,
      (uint32_t *) context->h);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA512_DIGEST_SIZE);
   }
}

#endif
#if (SHA512_224_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-512/224 message digest context
 * @param[in] context Pointer to the SHA-512/224 context to initialize
 **/

void sha512_224Init(Sha512_224Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0x8C3D37C819544DA2);
   context->h[1] = BETOH64(0x73E1996689DCD4D6);
   context->h[2] = BETOH64(0x1DFAB7AE32FF9C82);
   context->h[3] = BETOH64(0x679DD514582F9FCF);
   context->h[4] = BETOH64(0x0F6D2B697BD44DA8);
   context->h[5] = BETOH64(0x77E36F7304C48942);
   context->h[6] = BETOH64(0x3F9D85A86A1D36C8);
   context->h[7] = BETOH64(0x1112E6AD91D692A1);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}

#endif
#if (SHA512_384_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-512/256 message digest context
 * @param[in] context Pointer to the SHA-512/256 context to initialize
 **/

void sha512_256Init(Sha512_256Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0x22312194FC2BF72C);
   context->h[1] = BETOH64(0x9F555FA3C84C64C2);
   context->h[2] = BETOH64(0x2393B86B6F53B151);
   context->h[3] = BETOH64(0x963877195940EABD);
   context->h[4] = BETOH64(0x96283EE2A88EFFE3);
   context->h[5] = BETOH64(0xBE5E1E2553863992);
   context->h[6] = BETOH64(0x2B0199FC2C85B8AA);
   context->h[7] = BETOH64(0x0EB72DDC81C52CA2);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}

#endif
#endif

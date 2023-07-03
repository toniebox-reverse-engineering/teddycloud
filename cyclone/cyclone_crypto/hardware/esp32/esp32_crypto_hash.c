/**
 * @file esp32_crypto_hash.c
 * @brief ESP32 hash hardware accelerator
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
#include "hal/sha_types.h"
#include "soc/hwcrypto_reg.h"
#include "soc/dport_access.h"
#include "driver/periph_ctrl.h"
#include "core/crypto.h"
#include "hardware/esp32/esp32_crypto.h"
#include "hardware/esp32/esp32_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (ESP32_CRYPTO_HASH_SUPPORT == ENABLED)


/**
 * @brief SHA module initialization
 **/

void esp32ShaInit(void)
{
   //Enable SHA module
   periph_module_enable(PERIPH_SHA_MODULE);
}


/**
 * @brief Process data block
 * @param[in] algo Hash algorithm
 * @param[in] data Pointer to the data block
 * @param[in,out] first First message block
 **/

void hashProcessDataBlock(uint32_t algo, const uint8_t *data, bool_t *first)
{
   uint32_t temp;

   //Write the block to be processed in the data registers
   temp = LOAD32BE(data);
   DPORT_REG_WRITE(SHA_TEXT_BASE, temp);
   temp = LOAD32BE(data + 4);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 4, temp);
   temp = LOAD32BE(data + 8);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 8, temp);
   temp = LOAD32BE(data + 12);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 12, temp);
   temp = LOAD32BE(data + 16);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 16, temp);
   temp = LOAD32BE(data + 20);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 20, temp);
   temp = LOAD32BE(data + 24);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 24, temp);
   temp = LOAD32BE(data + 28);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 28, temp);
   temp = LOAD32BE(data + 32);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 32, temp);
   temp = LOAD32BE(data + 36);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 36, temp);
   temp = LOAD32BE(data + 40);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 40, temp);
   temp = LOAD32BE(data + 44);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 44, temp);
   temp = LOAD32BE(data + 48);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 48, temp);
   temp = LOAD32BE(data + 52);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 52, temp);
   temp = LOAD32BE(data + 56);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 56, temp);
   temp = LOAD32BE(data + 60);
   DPORT_REG_WRITE(SHA_TEXT_BASE + 60, temp);

   //128-bit data block?
   if(algo == SHA2_384 || algo == SHA2_512)
   {
      temp = LOAD32BE(data + 64);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 64, temp);
      temp = LOAD32BE(data + 68);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 68, temp);
      temp = LOAD32BE(data + 72);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 72, temp);
      temp = LOAD32BE(data + 76);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 76, temp);
      temp = LOAD32BE(data + 80);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 80, temp);
      temp = LOAD32BE(data + 84);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 84, temp);
      temp = LOAD32BE(data + 88);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 88, temp);
      temp = LOAD32BE(data + 92);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 92, temp);
      temp = LOAD32BE(data + 96);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 96, temp);
      temp = LOAD32BE(data + 100);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 100, temp);
      temp = LOAD32BE(data + 104);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 104, temp);
      temp = LOAD32BE(data + 108);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 108, temp);
      temp = LOAD32BE(data + 112);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 112, temp);
      temp = LOAD32BE(data + 116);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 116, temp);
      temp = LOAD32BE(data + 120);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 120, temp);
      temp = LOAD32BE(data + 124);
      DPORT_REG_WRITE(SHA_TEXT_BASE + 124, temp);
   }

   //SHA-1, SHA-256, SHA-384 and SHA-512 algorithms use different control
   //registers
   if(algo == SHA1)
   {
      //Start SHA-1 operation
      if(*first)
      {
         DPORT_REG_WRITE(SHA_1_START_REG, 1);
      }
      else
      {
         DPORT_REG_WRITE(SHA_1_CONTINUE_REG, 1);
      }

      //Wait for the operation to complete
      while(DPORT_REG_READ(SHA_1_BUSY_REG) != 0)
      {
      }
   }
   else if(algo == SHA2_256)
   {
      //Start SHA-256 operation
      if(*first)
      {
         DPORT_REG_WRITE(SHA_256_START_REG, 1);
      }
      else
      {
         DPORT_REG_WRITE(SHA_256_CONTINUE_REG, 1);
      }

      //Wait for the operation to complete
      while(DPORT_REG_READ(SHA_256_BUSY_REG) != 0)
      {
      }
   }
   else if(algo == SHA2_384)
   {
      //Start SHA-384 operation
      if(*first)
      {
         DPORT_REG_WRITE(SHA_384_START_REG, 1);
      }
      else
      {
         DPORT_REG_WRITE(SHA_384_CONTINUE_REG, 1);
      }

      //Wait for the operation to complete
      while(DPORT_REG_READ(SHA_384_BUSY_REG) != 0)
      {
      }
   }
   else
   {
      //Start SHA-512 operation
      if(*first)
      {
         DPORT_REG_WRITE(SHA_512_START_REG, 1);
      }
      else
      {
         DPORT_REG_WRITE(SHA_512_CONTINUE_REG, 1);
      }

      //Wait for the operation to complete
      while(DPORT_REG_READ(SHA_512_BUSY_REG) != 0)
      {
      }
   }

   //Process subsequent message blocks
   *first = FALSE;
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
   bool_t first;
   size_t n;
   uint32_t temp;
   uint8_t buffer[64];

   //Acquire exclusive access to the SHA module
   osAcquireMutex(&esp32CryptoMutex);

   //Process the first message block
   first = TRUE;

   //Digest the message
   for(n = length; n >= 64; n -= 64)
   {
      //Update hash value
      hashProcessDataBlock(SHA1, data, &first);
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
      hashProcessDataBlock(SHA1, buffer, &first);
      osMemset(buffer, 0, 64);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 56);

   //Process the final block
   hashProcessDataBlock(SHA1, buffer, &first);

   //Compute SHA-1 digest
   DPORT_REG_WRITE(SHA_1_LOAD_REG, 1);

   //Wait for the operation to complete
   while(DPORT_REG_READ(SHA_1_BUSY_REG) != 0)
   {
   }

   //Save the resulting hash value
   DPORT_INTERRUPT_DISABLE();
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE);
   STORE32BE(temp, digest);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 4);
   STORE32BE(temp, digest + 4);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 8);
   STORE32BE(temp, digest + 8);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 12);
   STORE32BE(temp, digest + 12);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 16);
   STORE32BE(temp, digest + 16);
   DPORT_INTERRUPT_RESTORE();

   //Release exclusive access to the SHA module
   osReleaseMutex(&esp32CryptoMutex);

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
   bool_t first;
   size_t n;
   uint32_t temp;
   uint8_t buffer[64];

   //Acquire exclusive access to the SHA module
   osAcquireMutex(&esp32CryptoMutex);

   //Process the first message block
   first = TRUE;

   //Digest the message
   for(n = length; n >= 64; n -= 64)
   {
      //Update hash value
      hashProcessDataBlock(SHA2_256, data, &first);
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
      hashProcessDataBlock(SHA2_256, buffer, &first);
      osMemset(buffer, 0, 64);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 56);

   //Process the final block
   hashProcessDataBlock(SHA2_256, buffer, &first);

   //Compute SHA-256 digest
   DPORT_REG_WRITE(SHA_256_LOAD_REG, 1);

   //Wait for the operation to complete
   while(DPORT_REG_READ(SHA_256_BUSY_REG) != 0)
   {
   }

   //Save the resulting hash value
   DPORT_INTERRUPT_DISABLE();
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE);
   STORE32BE(temp, digest);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 4);
   STORE32BE(temp, digest + 4);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 8);
   STORE32BE(temp, digest + 8);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 12);
   STORE32BE(temp, digest + 12);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 16);
   STORE32BE(temp, digest + 16);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 20);
   STORE32BE(temp, digest + 20);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 24);
   STORE32BE(temp, digest + 24);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 28);
   STORE32BE(temp, digest + 28);
   DPORT_INTERRUPT_RESTORE();

   //Release exclusive access to the SHA module
   osReleaseMutex(&esp32CryptoMutex);

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
   bool_t first;
   size_t n;
   uint32_t temp;
   uint8_t buffer[128];

   //Acquire exclusive access to the SHA module
   osAcquireMutex(&esp32CryptoMutex);

   //Process the first message block
   first = TRUE;

   //Digest the message
   for(n = length; n >= 128; n -= 128)
   {
      //Update hash value
      hashProcessDataBlock(SHA2_384, data, &first);
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
      hashProcessDataBlock(SHA2_384, buffer, &first);
      osMemset(buffer, 0, 128);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 120);

   //Process the final block
   hashProcessDataBlock(SHA2_384, buffer, &first);

   //Compute SHA-384 digest
   DPORT_REG_WRITE(SHA_384_LOAD_REG, 1);

   //Wait for the operation to complete
   while(DPORT_REG_READ(SHA_384_BUSY_REG) != 0)
   {
   }

   //Save the resulting hash value
   DPORT_INTERRUPT_DISABLE();
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE);
   STORE32BE(temp, digest);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 4);
   STORE32BE(temp, digest + 4);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 8);
   STORE32BE(temp, digest + 8);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 12);
   STORE32BE(temp, digest + 12);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 16);
   STORE32BE(temp, digest + 16);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 20);
   STORE32BE(temp, digest + 20);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 24);
   STORE32BE(temp, digest + 24);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 28);
   STORE32BE(temp, digest + 28);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 32);
   STORE32BE(temp, digest + 32);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 36);
   STORE32BE(temp, digest + 36);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 40);
   STORE32BE(temp, digest + 40);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 44);
   STORE32BE(temp, digest + 44);
   DPORT_INTERRUPT_RESTORE();

   //Release exclusive access to the SHA module
   osReleaseMutex(&esp32CryptoMutex);

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
   bool_t first;
   size_t n;
   uint32_t temp;
   uint8_t buffer[128];

   //Acquire exclusive access to the SHA module
   osAcquireMutex(&esp32CryptoMutex);

   //Process the first message block
   first = TRUE;

   //Digest the message
   for(n = length; n >= 128; n -= 128)
   {
      //Update hash value
      hashProcessDataBlock(SHA2_512, data, &first);
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
      hashProcessDataBlock(SHA2_512, buffer, &first);
      osMemset(buffer, 0, 128);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 120);

   //Process the final block
   hashProcessDataBlock(SHA2_512, buffer, &first);

   //Compute SHA-512 digest
   DPORT_REG_WRITE(SHA_512_LOAD_REG, 1);

   //Wait for the operation to complete
   while(DPORT_REG_READ(SHA_512_BUSY_REG) != 0)
   {
   }

   //Save the resulting hash value
   DPORT_INTERRUPT_DISABLE();
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE);
   STORE32BE(temp, digest);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 4);
   STORE32BE(temp, digest + 4);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 8);
   STORE32BE(temp, digest + 8);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 12);
   STORE32BE(temp, digest + 12);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 16);
   STORE32BE(temp, digest + 16);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 20);
   STORE32BE(temp, digest + 20);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 24);
   STORE32BE(temp, digest + 24);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 28);
   STORE32BE(temp, digest + 28);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 32);
   STORE32BE(temp, digest + 32);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 36);
   STORE32BE(temp, digest + 36);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 40);
   STORE32BE(temp, digest + 40);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 44);
   STORE32BE(temp, digest + 44);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 48);
   STORE32BE(temp, digest + 48);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 52);
   STORE32BE(temp, digest + 52);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 56);
   STORE32BE(temp, digest + 56);
   temp = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 60);
   STORE32BE(temp, digest + 60);
   DPORT_INTERRUPT_RESTORE();

   //Release exclusive access to the SHA module
   osReleaseMutex(&esp32CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#endif

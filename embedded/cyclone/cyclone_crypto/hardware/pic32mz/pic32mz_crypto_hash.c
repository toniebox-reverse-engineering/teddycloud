/**
 * @file pic32mz_crypto_hash.c
 * @brief PIC32MZ hash hardware accelerator
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
#include <p32xxxx.h>
#include <sys/kmem.h>
#include "core/crypto.h"
#include "hardware/pic32mz/pic32mz_crypto.h"
#include "hardware/pic32mz/pic32mz_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (PIC32MZ_CRYPTO_HASH_SUPPORT == ENABLED)

//Buffer descriptor
volatile Pic32mzCryptoBufferDesc hashBufferDesc
   __attribute__((coherent, aligned(8)));

//Security association
volatile Pic32mzCryptoSecurityAssoc hashSecurityAssoc
   __attribute__((coherent, aligned(8)));

//Input buffer
uint8_t hashInput[PIC32MZ_CRYPTO_BUFFER_SIZE]
   __attribute__((coherent, aligned(4)));

//Output buffer
uint8_t hashOutput[PIC32MZ_CRYPTO_BUFFER_SIZE]
   __attribute__((coherent, aligned(4)));

//MD5 value for an empty message
const uint8_t md5EmptyDigest[] =
{
   0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04,
   0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E
};

//SHA-1 value for an empty message
const uint8_t sha1EmptyDigest[] =
{
   0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D,
   0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90,
   0xAF, 0xD8, 0x07, 0x09
};

//SHA-256 value for an empty message
const uint8_t sha256EmptyDigest[] =
{
   0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
   0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
   0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
   0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55
};


/**
 * @brief Digest a message using the specified hash algorithm
 * @param[in] algo Hash algorithm
 * @param[in] data Pointer to the input message
 * @param[in] length Length of the input message, in bytes
 **/

void hashProcessData(uint32_t algo, const uint8_t *data, size_t length)
{
   size_t i;
   size_t n;

   //Acquire exclusive access to the crypto engine
   osAcquireMutex(&pic32mzCryptoMutex);

   //Reset the crypto engine
   CECON |= _CECON_SWRST_MASK;
   //Wait for the reset to complete
   while((CECON & _CECON_SWRST_MASK) != 0)
   {
   }

   //Clear descriptors
   memset((void *) &hashBufferDesc, 0, sizeof(Pic32mzCryptoBufferDesc));
   memset((void *) &hashSecurityAssoc, 0, sizeof(Pic32mzCryptoSecurityAssoc));

   //Set up buffer descriptor
   hashBufferDesc.SA_ADDR = KVA_TO_PA(&hashSecurityAssoc);
   hashBufferDesc.SRCADDR = KVA_TO_PA(hashInput);
   hashBufferDesc.NXTPTR = KVA_TO_PA(&hashBufferDesc);
   hashBufferDesc.UPDPTR = KVA_TO_PA(hashOutput);
   hashBufferDesc.MSG_LEN = length;

   //Set up security association
   hashSecurityAssoc.SA_CTRL = SA_CTRL_LNC | SA_CTRL_LOADIV | SA_CTRL_FB |
      algo;

   //Set the number of cycles that the DMA would wait before refetching the
   //descriptor control word if the previous descriptor fetched was disabled
   CEPOLLCON = 10;

   //Set the address from which the DMA will start fetching buffer descriptors
   CEBDPADDR = KVA_TO_PA(&hashBufferDesc);

   //Enable DMA engine
   CECON = _CECON_SWAPOEN_MASK | _CECON_SWAPEN_MASK | _CECON_BDPCHST_MASK |
      _CECON_BDPPLEN_MASK | _CECON_DMAEN_MASK;

   //Digest input message
   for(i = 0; i < length; i += n)
   {
      //Limit the number of data to process at a time
      n = MIN(length - i, sizeof(hashInput));
      //Copy input data
      osMemcpy(hashInput, data, n);

      //Set buffer length
      hashBufferDesc.BD_CTRL = BD_CTRL_SA_FETCH_EN | ((n + 3) & ~3UL);

      //First buffer descriptor?
      if(i == 0)
      {
         //Fetch security association from the SA pointer
         hashBufferDesc.BD_CTRL |= BD_CTRL_SA_FETCH_EN;
      }

      //Last buffer descriptor?
      if((i + n) == length)
      {
         //This BD is the last in the frame
         hashBufferDesc.BD_CTRL |= BD_CTRL_LIFM;
      }

      //Give the ownership of the descriptor to the hardware
      hashBufferDesc.BD_CTRL |= BD_CTRL_DESC_EN;

      //Wait for the processing to complete
      while((hashBufferDesc.BD_CTRL & BD_CTRL_DESC_EN) != 0)
      {
      }

      //Advance data pointer
      data += n;
   }

   //Release exclusive access to the crypto engine
   osReleaseMutex(&pic32mzCryptoMutex);
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
   //Empty message?
   if(length == 0)
   {
      //Return the MD5 digest value for an empty message
      osMemcpy(digest, md5EmptyDigest, MD5_DIGEST_SIZE);
   }
   else
   {
      //Digest the message using MD5
      hashProcessData(SA_CTRL_ALGO_MD5, data, length);
      //Copy the resulting digest value
      osMemcpy(digest, hashOutput, MD5_DIGEST_SIZE);
   }

   //Successful processing
   return NO_ERROR;
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
   //Empty message?
   if(length == 0)
   {
      //Return the SHA-1 digest value for an empty message
      osMemcpy(digest, sha1EmptyDigest, SHA1_DIGEST_SIZE);
   }
   else
   {
      //Digest the message using SHA-1
      hashProcessData(SA_CTRL_ALGO_SHA1, data, length);
      //Copy the resulting digest value
      osMemcpy(digest, hashOutput, SHA1_DIGEST_SIZE);
   }

   //Successful processing
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
   //Empty message?
   if(length == 0)
   {
      //Return the SHA-256 digest value for an empty message
      osMemcpy(digest, sha256EmptyDigest, SHA256_DIGEST_SIZE);
   }
   else
   {
      //Digest the message using SHA-256
      hashProcessData(SA_CTRL_ALGO_SHA256, data, length);
      //Copy the resulting digest value
      osMemcpy(digest, hashOutput, SHA256_DIGEST_SIZE);
   }

   //Successful processing
   return NO_ERROR;
}

#endif
#endif

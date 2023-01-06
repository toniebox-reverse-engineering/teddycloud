/**
 * @file kmac.c
 * @brief KMAC (Keccak Message Authentication Code)
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
 * The Keccak Message Authentication Code (KMAC) algorithm is a PRF and keyed
 * hash function based on Keccak. KMAC has two variants, KMAC128 and KMAC256,
 * built from cSHAKE128 and cSHAKE256, respectively
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "mac/kmac.h"

//Check crypto library configuration
#if (KMAC_SUPPORT == ENABLED)

//KMAC128 object identifier (2.16.840.1.101.3.4.2.19)
const uint8_t kmac128Oid[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x13};
//KMAC256 object identifier (2.16.840.1.101.3.4.2.20)
const uint8_t kmac256Oid[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x14};


/**
 * @brief Compute KMAC message authentication code
 * @param[in] strength Number of bits of security (128 for KMAC128 and
 *   256 for KMAC256)
 * @param[in] key Pointer to the secret key (K)
 * @param[in] keyLen Length of the secret key
 * @param[in] data Pointer to the input message (X)
 * @param[in] dataLen Length of the input data
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @param[out] mac Calculated MAC value
 * @param[in] macLen Expected length of the MAC (L)
 * @return Error code
 **/

error_t kmacCompute(uint_t strength, const void *key, size_t keyLen,
   const void *data, size_t dataLen, const char_t *custom, size_t customLen,
   uint8_t *mac, size_t macLen)
{
   error_t error;
   KmacContext *context;

   //Allocate a memory buffer to hold the KMAC context
   context = cryptoAllocMem(sizeof(KmacContext));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the KMAC context
      error = kmacInit(context, strength, key, keyLen, custom, customLen);

      //Check status code
      if(!error)
      {
         //Digest the message
         kmacUpdate(context, data, dataLen);
         //Finalize the KMAC computation
         error = kmacFinal(context, mac, macLen);
      }

      //Free previously allocated memory
      cryptoFreeMem(context);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Initialize KMAC calculation
 * @param[in] context Pointer to the KMAC context to initialize
 * @param[in] strength Number of bits of security (128 for KMAC128 and
 *   256 for KMAC256)
 * @param[in] key Pointer to the secret key (K)
 * @param[in] keyLen Length of the secret key
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @return Error code
 **/

error_t kmacInit(KmacContext *context, uint_t strength, const void *key,
   size_t keyLen, const char_t *custom, size_t customLen)
{
   error_t error;
   size_t i;
   size_t n;
   size_t rate;
   uint8_t buffer[sizeof(size_t) + 1];

   //Make sure the KMAC context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the supplied key is valid
   if(key == NULL && keyLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize cSHAKE context
   error = cshakeInit(&context->cshakeContext, strength, "KMAC", 4, custom,
      customLen);
   //Any error to report?
   if(error)
      return error;

   //The rate of the underlying Keccak sponge function is 168 for KMAC128
   //and 136 for KMAC256
   rate = context->cshakeContext.keccakContext.blockSize;

   //Absorb the string representation of the rate
   cshakeLeftEncode(rate, buffer, &n);
   cshakeAbsorb(&context->cshakeContext, buffer, n);
   i = n;

   //Absorb the string representation of K
   cshakeLeftEncode(keyLen * 8, buffer, &n);
   cshakeAbsorb(&context->cshakeContext, buffer, n);
   cshakeAbsorb(&context->cshakeContext, key, keyLen);
   i += n + keyLen;

   //The padding string consists of bytes set to zero
   buffer[0] = 0;

   //Pad the result with zeros until it is a byte string whose length in
   //bytes is a multiple of the rate
   while((i % rate) != 0)
   {
      //Absorb the padding string
      cshakeAbsorb(&context->cshakeContext, buffer, 1);
      i++;
   }

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Update the KMAC context with a portion of the message being hashed
 * @param[in] context Pointer to the KMAC context
 * @param[in] data Pointer to the input data
 * @param[in] dataLen Length of the buffer
 **/

void kmacUpdate(KmacContext *context, const void *data, size_t dataLen)
{
   //Absorb the input data
   cshakeAbsorb(&context->cshakeContext, data, dataLen);
}


/**
 * @brief Finish the KMAC calculation
 * @param[in] context Pointer to the KMAC context
 * @param[out] mac Calculated MAC value
 * @param[in] macLen Expected length of the MAC (L)
 * @return Error code
 **/

error_t kmacFinal(KmacContext *context, uint8_t *mac, size_t macLen)
{
   size_t n;
   uint8_t buffer[sizeof(size_t) + 1];

   //Make sure the KMAC context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //When the requested output length is zero, KMAC returns the empty string
   //as the output
   if(mac == NULL && macLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Absorb the string representation of L
   kmacRightEncode(macLen * 8, buffer, &n);
   cshakeAbsorb(&context->cshakeContext, buffer, n);

   //Finish absorbing phase
   cshakeFinal(&context->cshakeContext);
   //Extract data from the squeezing phase
   cshakeSqueeze(&context->cshakeContext, mac, macLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Encode integer as byte string
 * @param[in] value Value of the integer to be encoded
 * @param[out] buffer Buffer where to store the byte string representation
 * @param[out] length Length of the resulting byte string
 **/

void kmacRightEncode(size_t value, uint8_t *buffer, size_t *length)
{
   size_t i;
   size_t n;
   size_t temp;

   //Get the value of the integer to be encoded
   temp = value;

   //Let n be the smallest positive integer for which 2^(8*n) > x
   for(n = 1; n < sizeof(size_t) && (temp >> 8) != 0; n++)
   {
      temp >>= 8;
   }

   //Encode O(1) || ... || O(n)
   for(i = 0; i < n; i++)
   {
      buffer[i] = value >> ((n - i - 1) * 8);
   }

   //Encode O(n+1)
   buffer[i] = n;

   //Return the length of the byte string representation
   *length = n + 1;
}

#endif

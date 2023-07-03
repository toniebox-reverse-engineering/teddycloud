/**
 * @file cshake.c
 * @brief cSHAKE128 and cSHAKE256 (customizable SHAKE function)
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
 * cSHAKE is a customizable variant of the SHAKE function. Refer to
 * NIST SP 800-185 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "xof/cshake.h"

//Check crypto library configuration
#if (CSHAKE_SUPPORT == ENABLED)


/**
 * @brief Digest a message using cSHAKE128 or cSHAKE256
 * @param[in] strength Number of bits of security (128 for cSHAKE128 and
 *   256 for cSHAKE256)
 * @param[in] input Pointer to the input data (X)
 * @param[in] inputLen Length of the input data
 * @param[in] name Function name (N)
 * @param[in] nameLen Length of the function name
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @param[out] output Pointer to the output data
 * @param[in] outputLen Expected length of the output data (L)
 * @return Error code
 **/

error_t cshakeCompute(uint_t strength, const void *input, size_t inputLen,
   const char_t *name, size_t nameLen, const char_t *custom, size_t customLen,
   uint8_t *output, size_t outputLen)
{
   error_t error;
   CshakeContext *context;

   //Allocate a memory buffer to hold the cSHAKE context
   context = cryptoAllocMem(sizeof(CshakeContext));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the cSHAKE context
      error = cshakeInit(context, strength, name, nameLen, custom, customLen);

      //Check status code
      if(!error)
      {
         //Absorb input data
         cshakeAbsorb(context, input, inputLen);
         //Finish absorbing phase
         cshakeFinal(context);
         //Extract data from the squeezing phase
         cshakeSqueeze(context, output, outputLen);
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
 * @brief Initialize cSHAKE context
 * @param[in] context Pointer to the cSHAKE context to initialize
 * @param[in] strength Number of bits of security (128 for cSHAKE128 and
 *   256 for cSHAKE256)
 * @param[in] name Function name (N)
 * @param[in] nameLen Length of the function name
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @return Error code
 **/

error_t cshakeInit(CshakeContext *context, uint_t strength, const char_t *name,
   size_t nameLen, const char_t *custom, size_t customLen)
{
   error_t error;
   size_t i;
   size_t n;
   size_t rate;
   uint8_t buffer[sizeof(size_t) + 1];

   //Make sure the cSHAKE context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //cSHAKE128 and cSHAKE256 provides respectively 128 and 256 bits of security
   if(strength != 128 && strength != 256)
      return ERROR_INVALID_PARAMETER;

   //The function name N is optional
   if(name == NULL && nameLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The customization string S is optional
   if(custom == NULL && customLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Save the length of N and S
   context->nameLen = nameLen;
   context->customLen = customLen;

   //Initialize Keccak context
   error = keccakInit(&context->keccakContext, 2 * strength);
   //Any error to report?
   if(error)
      return error;

   //The rate of the underlying Keccak sponge function is 168 for cSHAKE128
   //and 136 for cSHAKE256
   rate = context->keccakContext.blockSize;

   //When N and S are both empty strings, cSHAKE is equivalent to SHAKE
   if(nameLen != 0 || customLen != 0)
   {
      //Absorb the string representation of the rate
      cshakeLeftEncode(rate, buffer, &n);
      cshakeAbsorb(context, buffer, n);
      i = n;

      //Absorb the string representation of N
      cshakeLeftEncode(nameLen * 8, buffer, &n);
      cshakeAbsorb(context, buffer, n);
      cshakeAbsorb(context, name, nameLen);
      i += n + nameLen;

      //Absorb the string representation of S
      cshakeLeftEncode(customLen * 8, buffer, &n);
      cshakeAbsorb(context, buffer, n);
      cshakeAbsorb(context, custom, customLen);
      i += n + customLen;

      //The padding string consists of bytes set to zero
      buffer[0] = 0;

      //Pad the result with zeros until it is a byte string whose length in
      //bytes is a multiple of the rate
      while((i % rate) != 0)
      {
         //Absorb the padding string
         cshakeAbsorb(context, buffer, 1);
         i++;
      }
   }

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Absorb data
 * @param[in] context Pointer to the cSHAKE context
 * @param[in] input Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void cshakeAbsorb(CshakeContext *context, const void *input, size_t length)
{
   //Absorb the input data
   keccakAbsorb(&context->keccakContext, input, length);
}


/**
 * @brief Finish absorbing phase
 * @param[in] context Pointer to the cSHAKE context
 **/

void cshakeFinal(CshakeContext *context)
{
   uint8_t pad;

   //When N and S are both empty strings, cSHAKE is equivalent to SHAKE
   if(context->nameLen == 0 && context->customLen == 0)
   {
      //The padding byte is 0x1F for SHAKE
      pad = KECCAK_SHAKE_PAD;
   }
   else
   {
      //The padding byte is 0x04 for cSHAKE
      pad = KECCAK_CSHAKE_PAD;
   }

   //Finish absorbing phase
   keccakFinal(&context->keccakContext, pad);
}


/**
 * @brief Extract data from the squeezing phase
 * @param[in] context Pointer to the cSHAKE context
 * @param[out] output Output string
 * @param[in] length Desired output length, in bytes
 **/

void cshakeSqueeze(CshakeContext *context, uint8_t *output, size_t length)
{
   //Extract data from the squeezing phase
   keccakSqueeze(&context->keccakContext, output, length);
}


/**
 * @brief Encode integer as byte string
 * @param[in] value Value of the integer to be encoded
 * @param[out] buffer Buffer where to store the byte string representation
 * @param[out] length Length of the resulting byte string
 **/

void cshakeLeftEncode(size_t value, uint8_t *buffer, size_t *length)
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

   //Encode O(0)
   buffer[0] = n;

   //Encode O(1) || ... || O(n)
   for(i = 1; i <= n; i++)
   {
      buffer[i] = value >> ((n - i) * 8);
   }

   //Return the length of the byte string representation
   *length = n + 1;
}

#endif

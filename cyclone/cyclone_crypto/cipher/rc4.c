/**
 * @file rc4.c
 * @brief RC4 encryption algorithm
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
#include "cipher/rc4.h"

//Check crypto library configuration
#if (RC4_SUPPORT == ENABLED)

//Common interface for encryption algorithms
const CipherAlgo rc4CipherAlgo =
{
   "RC4",
   sizeof(Rc4Context),
   CIPHER_ALGO_TYPE_STREAM,
   0,
   (CipherAlgoInit) rc4Init,
   (CipherAlgoEncryptStream) rc4Cipher,
   (CipherAlgoDecryptStream) rc4Cipher,
   NULL,
   NULL,
   (CipherAlgoDeinit) rc4Deinit
};


/**
 * @brief Initialize an RC4 context using the supplied key
 * @param[in] context Pointer to the RC4 context to initialize
 * @param[in] key Pointer to the key
 * @param[in] length Length of the key
 * @return Error code
 **/

error_t rc4Init(Rc4Context *context, const uint8_t *key, size_t length)
{
   uint_t i;
   uint_t j;
   uint8_t temp;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear context
   context->i = 0;
   context->j = 0;

   //Initialize the S array with identity permutation
   for(i = 0; i < 256; i++)
   {
      context->s[i] = i;
   }

   //S is then processed for 256 iterations
   for(i = 0, j = 0; i < 256; i++)
   {
      //Randomize the permutations using the supplied key
      j = (j + context->s[i] + key[i % length]) % 256;

      //Swap the values of S[i] and S[j]
      temp = context->s[i];
      context->s[i] = context->s[j];
      context->s[j] = temp;
   }

   //RC4 context successfully initialized
   return NO_ERROR;
}


/**
 * @brief Encrypt/decrypt data with the RC4 algorithm
 * @param[in] context Pointer to the RC4 context
 * @param[in] input Pointer to the data to encrypt/decrypt
 * @param[in] output Pointer to the resulting data
 * @param[in] length Length of the input data
 **/

void rc4Cipher(Rc4Context *context, const uint8_t *input, uint8_t *output,
   size_t length)
{
   uint8_t temp;

   //Restore context
   uint_t i = context->i;
   uint_t j = context->j;
   uint8_t *s = context->s;

   //Encryption loop
   while(length > 0)
   {
      //Adjust indices
      i = (i + 1) % 256;
      j = (j + s[i]) % 256;

      //Swap the values of S[i] and S[j]
      temp = s[i];
      s[i] = s[j];
      s[j] = temp;

      //Valid input and output?
      if(input != NULL && output != NULL)
      {
         //XOR the input data with the RC4 stream
         *output = *input ^ s[(s[i] + s[j]) % 256];

         //Increment data pointers
         input++;
         output++;
      }

      //Remaining bytes to process
      length--;
   }

   //Save context
   context->i = i;
   context->j = j;
}


/**
 * @brief Release RC4 context
 * @param[in] context Pointer to the RC4 context
 **/

void rc4Deinit(Rc4Context *context)
{
   //Clear RC4 context
   osMemset(context, 0, sizeof(Rc4Context));
}

#endif

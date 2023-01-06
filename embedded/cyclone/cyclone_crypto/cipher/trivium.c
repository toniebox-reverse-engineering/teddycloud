/**
 * @file trivium.c
 * @brief Trivium stream cipher
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
#include "cipher/trivium.h"

//Check crypto library configuration
#if (TRIVIUM_SUPPORT == ENABLED)

//Get a given bit of the internal state
#define TRIVIUM_GET_BIT(s, n) ((s[(n - 1) / 8] >> ((n - 1) % 8)) & 1)

//Set a given bit of the internal state
#define TRIVIUM_SET_BIT(s, n, v) s[(n - 1) / 8] = \
   (s[(n - 1) / 8] & ~(1 << ((n - 1) % 8))) | (v) << ((n - 1) % 8)


/**
 * @brief Initialize Trivium context using the supplied key and IV
 * @param[in] context Pointer to the Trivium context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key (10 bytes)
 * @param[in] iv Pointer to the initialization vector
 * @param[in] ivLen Length of the initialization vector (10 bytes)
 * @return Error code
 **/

error_t triviumInit(TriviumContext *context, const uint8_t *key,
   size_t keyLen, const uint8_t *iv, size_t ivLen)
{
   uint_t i;

   //Check parameters
   if(context == NULL || key == NULL || iv == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the key and IV
   if(keyLen != 10 && ivLen != 10)
      return ERROR_INVALID_PARAMETER;

   //Clear the 288-bit internal state
   osMemset(context->s, 0, 36);

   //Let (s1, s2, ..., s93) = (K1, ..., K80, 0, ..., 0)
   for(i = 0; i < 10; i++)
   {
      context->s[i] = reverseInt8(key[9 - i]);
   }

   //Load the 80-bit initialization vector
   for(i = 0; i < 10; i++)
   {
      context->s[12 + i] = reverseInt8(iv[9 - i]);
   }

   //Let (s94, s95, ..., s177) = (IV1, ..., IV80, 0, ..., 0)
   for(i = 11; i < 22; i++)
   {
      context->s[i] = (context->s[i + 1] << 5) | (context->s[i] >> 3);
   }

   //Let (s178, s279, ..., s288) = (0, ..., 0, 1, 1, 1)
   TRIVIUM_SET_BIT(context->s, 286, 1);
   TRIVIUM_SET_BIT(context->s, 287, 1);
   TRIVIUM_SET_BIT(context->s, 288, 1);

   //The state is rotated over 4 full cycles, without generating key stream bit
   for(i = 0; i < (4 * 288); i++)
   {
      triviumGenerateBit(context);
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt/decrypt data with the Trivium algorithm
 * @param[in] context Pointer to the Trivium context
 * @param[in] input Pointer to the data to encrypt/decrypt (optional)
 * @param[in] output Pointer to the resulting data (optional)
 * @param[in] length Number of bytes to be processed
 **/

void triviumCipher(TriviumContext *context, const uint8_t *input,
   uint8_t *output, size_t length)
{
   size_t i;
   uint8_t ks;

   //Encryption loop
   for(i = 0; i < length; i++)
   {
      //Generate one byte of key stream
      ks = triviumGenerateByte(context);

      //Valid output pointer?
      if(output != NULL)
      {
         //Valid input pointer?
         if(input != NULL)
         {
            //XOR the input data with the keystream
            output[i] = input[i] ^ ks;
         }
         else
         {
            //Output the keystream
            output[i] = ks;
         }
      }
   }
}


/**
 * @brief Generate one bit of key stream
 * @param[in] context Pointer to the Trivium context
 * @return Key stream bit
 **/

uint8_t triviumGenerateBit(TriviumContext *context)
{
   uint_t i;
   uint8_t t1;
   uint8_t t2;
   uint8_t t3;
   uint8_t z;

   //Let t1 = s66 + s93
   t1 = TRIVIUM_GET_BIT(context->s, 66);
   t1 ^= TRIVIUM_GET_BIT(context->s, 93);

   //Let t2 = s162 + s177
   t2 = TRIVIUM_GET_BIT(context->s, 162);
   t2 ^= TRIVIUM_GET_BIT(context->s, 177);

   //Let t3 = s243 + s288
   t3 = TRIVIUM_GET_BIT(context->s, 243);
   t3 ^= TRIVIUM_GET_BIT(context->s, 288);

   //Generate a key stream bit z
   z = t1 ^ t2 ^ t3;

   //Let t1 = t1 + s91.s92 + s171
   t1 ^= TRIVIUM_GET_BIT(context->s, 91) & TRIVIUM_GET_BIT(context->s, 92);
   t1 ^= TRIVIUM_GET_BIT(context->s, 171);

   //Let t2 = t2 + s175.s176 + s264
   t2 ^= TRIVIUM_GET_BIT(context->s, 175) & TRIVIUM_GET_BIT(context->s, 176);
   t2 ^= TRIVIUM_GET_BIT(context->s, 264);

   //Let t3 = t3 + s286.s287 + s69
   t3 ^= TRIVIUM_GET_BIT(context->s, 286) & TRIVIUM_GET_BIT(context->s, 287);
   t3 ^= TRIVIUM_GET_BIT(context->s, 69);

   //Rotate the internal state
   for(i = 35; i > 0; i--)
   {
      context->s[i] = (context->s[i] << 1) | (context->s[i - 1] >> 7);
   }

   context->s[0] = context->s[0] << 1;

   //Let s1 = t3
   TRIVIUM_SET_BIT(context->s, 1, t3);
   //Let s94 = t1
   TRIVIUM_SET_BIT(context->s, 94, t1);
   //Let s178 = t2
   TRIVIUM_SET_BIT(context->s, 178, t2);

   //Return one bit of key stream
   return z;
}


/**
 * @brief Generate one byte of key stream
 * @param[in] context Pointer to the Trivium context
 * @return Key stream byte
 **/

uint8_t triviumGenerateByte(TriviumContext *context)
{
   uint_t i;
   uint8_t ks;

   //Initialize value
   ks = 0;

   //Generate 8 bits of key stream
   for(i = 0; i < 8; i++)
   {
      ks |= triviumGenerateBit(context) << i;
   }

   //Return one byte of key stream
   return ks;
}


/**
 * @brief Release Trivium context
 * @param[in] context Pointer to the Trivium context
 **/

void triviumDeinit(TriviumContext *context)
{
   //Clear Trivium context
   osMemset(context, 0, sizeof(TriviumContext));
}

#endif

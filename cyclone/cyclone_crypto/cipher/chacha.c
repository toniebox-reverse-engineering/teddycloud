/**
 * @file chacha.c
 * @brief ChaCha encryption algorithm
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
#include "cipher/chacha.h"

//Check crypto library configuration
#if (CHACHA_SUPPORT == ENABLED)

//ChaCha quarter-round function
#define QUARTER_ROUND(a, b, c, d) \
{ \
   a += b; \
   d ^= a; \
   d = ROL32(d, 16); \
   c += d; \
   b ^= c; \
   b = ROL32(b, 12); \
   a += b; \
   d ^= a; \
   d = ROL32(d, 8); \
   c += d; \
   b ^= c; \
   b = ROL32(b, 7); \
}


/**
 * @brief Initialize ChaCha context using the supplied key and nonce
 * @param[in] context Pointer to the ChaCha context to initialize
 * @param[in] nr Number of rounds to be applied (8, 12 or 20)
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key, in bytes (16 or 32)
 * @param[in] nonce Pointer to the nonce
 * @param[in] nonceLen Length of the nonce, in bytes (8 or 12)
 * @return Error code
 **/

error_t chachaInit(ChachaContext *context, uint_t nr, const uint8_t *key,
   size_t keyLen, const uint8_t *nonce, size_t nonceLen)
{
   uint32_t *w;

   //Check parameters
   if(context == NULL || key == NULL || nonce == NULL)
      return ERROR_INVALID_PARAMETER;

   //The number of rounds must be 8, 12 or 20
   if(nr != 8 && nr != 12 && nr != 20)
      return ERROR_INVALID_PARAMETER;

   //Save the number of rounds to be applied
   context->nr = nr;

   //Point to the state
   w = context->state;

   //Check the length of the key
   if(keyLen == 16)
   {
      //The first four input words are constants
      w[0] = 0x61707865;
      w[1] = 0x3120646E;
      w[2] = 0x79622D36;
      w[3] = 0x6B206574;

      //Input words 4 through 7 are taken from the 128-bit key, by reading
      //the bytes in little-endian order, in 4-byte chunks
      w[4] = LOAD32LE(key);
      w[5] = LOAD32LE(key + 4);
      w[6] = LOAD32LE(key + 8);
      w[7] = LOAD32LE(key + 12);

      //Input words 8 through 11 are taken from the 128-bit key, again by
      //reading the bytes in little-endian order, in 4-byte chunks
      w[8] = LOAD32LE(key);
      w[9] = LOAD32LE(key + 4);
      w[10] = LOAD32LE(key + 8);
      w[11] = LOAD32LE(key + 12);
   }
   else if(keyLen == 32)
   {
      //The first four input words are constants
      w[0] = 0x61707865;
      w[1] = 0x3320646E;
      w[2] = 0x79622D32;
      w[3] = 0x6B206574;

      //Input words 4 through 11 are taken from the 256-bit key, by reading
      //the bytes in little-endian order, in 4-byte chunks
      w[4] = LOAD32LE(key);
      w[5] = LOAD32LE(key + 4);
      w[6] = LOAD32LE(key + 8);
      w[7] = LOAD32LE(key + 12);
      w[8] = LOAD32LE(key + 16);
      w[9] = LOAD32LE(key + 20);
      w[10] = LOAD32LE(key + 24);
      w[11] = LOAD32LE(key + 28);
   }
   else
   {
      //Invalid key length
      return ERROR_INVALID_PARAMETER;
   }

   //Check the length of the nonce
   if(nonceLen == 8)
   {
      //Input words 12 and 13 are a block counter, with word 12
      //overflowing into word 13
      w[12] = 0;
      w[13] = 0;

      //Input words 14 and 15 are taken from an 64-bit nonce, by reading
      //the bytes in little-endian order, in 4-byte chunks
      w[14] = LOAD32LE(nonce);
      w[15] = LOAD32LE(nonce + 4);
   }
   else if(nonceLen == 12)
   {
      //Input word 12 is a block counter
      w[12] = 0;

      //Input words 13 to 15 are taken from an 96-bit nonce, by reading
      //the bytes in little-endian order, in 4-byte chunks
      w[13] = LOAD32LE(nonce);
      w[14] = LOAD32LE(nonce + 4);
      w[15] = LOAD32LE(nonce + 8);
   }
   else
   {
      //Invalid nonce length
      return ERROR_INVALID_PARAMETER;
   }

   //The keystream block is empty
   context->pos = 0;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt/decrypt data with the ChaCha algorithm
 * @param[in] context Pointer to the ChaCha context
 * @param[in] input Pointer to the data to encrypt/decrypt (optional)
 * @param[in] output Pointer to the resulting data (optional)
 * @param[in] length Number of bytes to be processed
 **/

void chachaCipher(ChachaContext *context, const uint8_t *input,
   uint8_t *output, size_t length)
{
   uint_t i;
   uint_t n;
   uint8_t *k;

   //Encryption loop
   while(length > 0)
   {
      //Check whether a new keystream block must be generated
      if(context->pos == 0 || context->pos >= 64)
      {
         //ChaCha successively calls the ChaCha block function, with the same key
         //and nonce, and with successively increasing block counter parameters
         chachaProcessBlock(context);

         //Increment block counter
         context->state[12]++;

         //Propagate the carry if necessary
         if(context->state[12] == 0)
         {
            context->state[13]++;
         }

         //Rewind to the beginning of the keystream block
         context->pos = 0;
      }

      //Compute the number of bytes to encrypt/decrypt at a time
      n = MIN(length, 64 - context->pos);

      //Valid output pointer?
      if(output != NULL)
      {
         //Point to the keystream
         k = (uint8_t *) context->block + context->pos;

         //Valid input pointer?
         if(input != NULL)
         {
            //XOR the input data with the keystream
            for(i = 0; i < n; i++)
            {
               output[i] = input[i] ^ k[i];
            }

            //Advance input pointer
            input += n;
         }
         else
         {
            //Output the keystream
            for(i = 0; i < n; i++)
            {
               output[i] = k[i];
            }
         }

         //Advance output pointer
         output += n;
      }

      //Current position in the keystream block
      context->pos += n;
      //Remaining bytes to process
      length -= n;
   }
}


/**
 * @brief Generate a keystream block
 * @param[in] context Pointer to the ChaCha context
 **/

void chachaProcessBlock(ChachaContext *context)
{
   uint_t i;
   uint32_t *w;

   //Point to the working state
   w = (uint32_t *) context->block;

   //Copy the state to the working state
   for(i = 0; i < 16; i++)
   {
      w[i] = context->state[i];
   }

   //ChaCha runs 8, 12 or 20 rounds, alternating between column rounds and
   //diagonal rounds
   for(i = 0; i < context->nr; i += 2)
   {
      //The column rounds apply the quarter-round function to the four
      //columns, from left to right
      QUARTER_ROUND(w[0], w[4], w[8], w[12]);
      QUARTER_ROUND(w[1], w[5], w[9], w[13]);
      QUARTER_ROUND(w[2], w[6], w[10], w[14]);
      QUARTER_ROUND(w[3], w[7], w[11], w[15]);

      //The diagonal rounds apply the quarter-round function to the top-left,
      //bottom-right diagonal, followed by the pattern shifted one place to
      //the right, for three more quarter-rounds
      QUARTER_ROUND(w[0], w[5], w[10], w[15]);
      QUARTER_ROUND(w[1], w[6], w[11], w[12]);
      QUARTER_ROUND(w[2], w[7], w[8], w[13]);
      QUARTER_ROUND(w[3], w[4], w[9], w[14]);
   }

   //Add the original input words to the output words
   for(i = 0; i < 16; i++)
   {
      w[i] += context->state[i];
   }

   //Serialize the result by sequencing the words one-by-one in little-endian
   //order
   for(i = 0; i < 16; i++)
   {
      w[i] = htole32(w[i]);
   }
}


/**
 * @brief Release ChaCha context
 * @param[in] context Pointer to the ChaCha context
 **/

void chachaDeinit(ChachaContext *context)
{
   //Clear ChaCha context
   osMemset(context, 0, sizeof(ChachaContext));
}

#endif

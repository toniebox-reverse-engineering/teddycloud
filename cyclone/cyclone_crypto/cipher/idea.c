/**
 * @file idea.c
 * @brief IDEA encryption algorithm
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
#include "cipher/idea.h"
#include "debug.h"

//Check crypto library configuration
#if (IDEA_SUPPORT == ENABLED)

//Common interface for encryption algorithms
const CipherAlgo ideaCipherAlgo =
{
   "IDEA",
   sizeof(IdeaContext),
   CIPHER_ALGO_TYPE_BLOCK,
   IDEA_BLOCK_SIZE,
   (CipherAlgoInit) ideaInit,
   NULL,
   NULL,
   (CipherAlgoEncryptBlock) ideaEncryptBlock,
   (CipherAlgoDecryptBlock) ideaDecryptBlock,
   (CipherAlgoDeinit) ideaDeinit
};


/**
 * @brief Modular multiplication
 * @param[in] a First operand
 * @param[in] b Second operand
 * @return Resulting value
 **/

static uint16_t ideaMul(uint16_t a, uint16_t b)
{
   uint32_t c;

   //Perform multiplication modulo 2^16 - 1
   c = a * b;

   if(c != 0)
   {
      c = ((ROL32(c, 16) - c) >> 16) + 1;
   }
   else
   {
      c = 1 - a - b;
   }

   //Return the result
   return c & 0xFFFF;
}


/**
 * @brief Compute modular inverse
 * @param[in] a Operand
 * @return Resulting value
 **/

static uint16_t ideaInv(uint16_t a)
{
   uint32_t b;
   uint32_t q;
   uint32_t r;
   int32_t t;
   int32_t u;
   int32_t v;

   //Compute the multiplicative inverse modulo 2^16 - 1
   b = 0x10001;
   u = 0;
   v = 1;

   while(a > 0)
   {
      q = b / a;
      r = b % a;

      b = a;
      a = r;

      t = v;
      v = u - q * v;
      u = t;
   }

   if(u < 0)
   {
      u += 0x10001;
   }

   //Return the result
   return u;
}


/**
 * @brief Initialize a IDEA context using the supplied key
 * @param[in] context Pointer to the IDEA context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t ideaInit(IdeaContext *context, const uint8_t *key, size_t keyLen)
{
   uint_t i;
   uint16_t *ek;
   uint16_t *dk;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid key length?
   if(keyLen != 16)
      return ERROR_INVALID_KEY_LENGTH;

   //Point to the encryption and decryption subkeys
   ek = context->ek;
   dk = context->dk;

   //First, the 128-bit key is partitioned into eight 16-bit sub-blocks
   for(i = 0; i < 8; i++)
   {
      ek[i] = LOAD16BE(key + i * 2);
   }

   //Expand encryption subkeys
   for(i = 8; i < 52; i++)
   {
      if((i % 8) == 6)
      {
         ek[i] = (ek[i - 7] << 9) | (ek[i - 14] >> 7);
      }
      else if((i % 8) == 7)
      {
         ek[i] = (ek[i - 15] << 9) | (ek[i - 14] >> 7);
      }
      else
      {
         ek[i] = (ek[i - 7] << 9) | (ek[i - 6] >> 7);
      }
   }

   //Generate subkeys for decryption
   for(i = 0; i < 52; i += 6)
   {
      dk[i] = ideaInv(ek[48 - i]);

      if(i == 0 || i == 48)
      {
         dk[i + 1] = -ek[49 - i];
         dk[i + 2] = -ek[50 - i];
      }
      else
      {
         dk[i + 1] = -ek[50 - i];
         dk[i + 2] = -ek[49 - i];
      }

      dk[i + 3] = ideaInv(ek[51 - i]);

      if(i < 48)
      {
         dk[i + 4] = ek[46 - i];
         dk[i + 5] = ek[47 - i];
      }
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 8-byte block using IDEA algorithm
 * @param[in] context Pointer to the IDEA context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void ideaEncryptBlock(IdeaContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint16_t e;
   uint16_t f;
   uint16_t *k;

   //The plaintext is divided into four 16-bit registers
   uint16_t a = LOAD16BE(input + 0);
   uint16_t b = LOAD16BE(input + 2);
   uint16_t c = LOAD16BE(input + 4);
   uint16_t d = LOAD16BE(input + 6);

   //Point to the key schedule
   k = context->ek;

   //The process consists of eight identical encryption steps
   for(i = 0; i < 8; i++)
   {
      //Apply a round
      a = ideaMul(a, k[0]);
      b += k[1];
      c += k[2];
      d = ideaMul(d, k[3]);

      e = a ^ c;
      f = b ^ d;

      e = ideaMul(e, k[4]);
      f += e;
      f = ideaMul(f, k[5]);
      e += f;

      a ^= f;
      d ^= e;
      e ^= b;
      f ^= c;

      b = f;
      c = e;

      //Advance current location in key schedule
      k += 6;
   }

   //The four 16-bit values produced at the end of the 8th encryption
   //round are combined with the last four of the 52 key sub-blocks
   a = ideaMul(a, k[0]);
   c += k[1];
   b += k[2];
   d = ideaMul(d, k[3]);

   //The resulting value is the ciphertext
   STORE16BE(a, output + 0);
   STORE16BE(c, output + 2);
   STORE16BE(b, output + 4);
   STORE16BE(d, output + 6);
}


/**
 * @brief Decrypt a 8-byte block using IDEA algorithm
 * @param[in] context Pointer to the IDEA context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void ideaDecryptBlock(IdeaContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint16_t e;
   uint16_t f;
   uint16_t *k;

   //The ciphertext is divided into four 16-bit registers
   uint16_t a = LOAD16BE(input + 0);
   uint16_t b = LOAD16BE(input + 2);
   uint16_t c = LOAD16BE(input + 4);
   uint16_t d = LOAD16BE(input + 6);

   //Point to the key schedule
   k = context->dk;

   //The computational process used for decryption of the ciphertext is
   //essentially the same as that used for encryption of the plaintext
   for(i = 0; i < 8; i++)
   {
      //Apply a round
      a = ideaMul(a, k[0]);
      b += k[1];
      c += k[2];
      d = ideaMul(d, k[3]);

      e = a ^ c;
      f = b ^ d;

      e = ideaMul(e, k[4]);
      f += e;
      f = ideaMul(f, k[5]);
      e += f;

      a ^= f;
      d ^= e;
      e ^= b;
      f ^= c;

      b = f;
      c = e;

      //Advance current location in key schedule
      k += 6;
   }

   //The four 16-bit values produced at the end of the 8th encryption
   //round are combined with the last four of the 52 key sub-blocks
   a = ideaMul(a, k[0]);
   c += k[1];
   b += k[2];
   d = ideaMul(d, k[3]);

   //The resulting value is the plaintext
   STORE16BE(a, output + 0);
   STORE16BE(c, output + 2);
   STORE16BE(b, output + 4);
   STORE16BE(d, output + 6);
}


/**
 * @brief Release IDEA context
 * @param[in] context Pointer to the IDEA context
 **/

void ideaDeinit(IdeaContext *context)
{
   //Clear IDEA context
   osMemset(context, 0, sizeof(IdeaContext));
}

#endif

/**
 * @file xts.c
 * @brief XEX-based tweaked-codebook mode with ciphertext stealing (XTS)
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
 * XTS is a tweakable block cipher designed for encryption of sector-based
 * storage. Refer to IEEE Std 1619 and SP 800-38E for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher_modes/xts.h"
#include "debug.h"

//Check crypto library configuration
#if (XTS_SUPPORT == ENABLED)


/**
 * @brief Initialize XTS context
 * @param[in] context Pointer to the XTS context
 * @param[in] cipherAlgo Cipher algorithm
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t xtsInit(XtsContext *context, const CipherAlgo *cipherAlgo,
   const void *key, size_t keyLen)
{
   error_t error;
   const uint8_t *k1;
   const uint8_t *k2;

   //XTS supports only symmetric block ciphers whose block size is 128 bits
   if(cipherAlgo->type != CIPHER_ALGO_TYPE_BLOCK || cipherAlgo->blockSize != 16)
      return ERROR_INVALID_PARAMETER;

   //Invalid key length?
   if(keyLen != 32 && keyLen != 64)
      return ERROR_INVALID_PARAMETER;

   //Cipher algorithm used to perform XTS encryption/decryption
   context->cipherAlgo = cipherAlgo;

   //The key is parsed as a concatenation of 2 fields of equal size called K1 and K2
   k1 = (uint8_t *) key;
   k2 = (uint8_t *) key + (keyLen / 2);

   //Initialize first cipher context using K1
   error = cipherAlgo->init(&context->cipherContext1, k1, keyLen / 2);
   //Any error to report?
   if(error)
      return error;

   //Initialize second cipher context using K2
   error = cipherAlgo->init(&context->cipherContext2, k2, keyLen / 2);
   //Any error to report?
   if(error)
      return error;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Encrypt a data unit using XTS
 * @param[in] context Pointer to the XTS context
 * @param[in] i Value of the 128-bit tweak
 * @param[in] p Pointer to the data unit to be encrypted (plaintext)
 * @param[out] c Pointer to the resulting data unit (ciphertext)
 * @param[in] length Length of the data unit, in bytes
 * @return Error code
 **/

error_t xtsEncrypt(XtsContext *context, const uint8_t *i, const uint8_t *p,
   uint8_t *c, size_t length)
{
   uint8_t t[16];
   uint8_t x[16];

   //The data unit size shall be at least 128 bits
   if(length < 16)
      return ERROR_INVALID_PARAMETER;

   //Encrypt the tweak using K2
   context->cipherAlgo->encryptBlock(&context->cipherContext2, i, t);

   //XTS mode operates in a block-by-block fashion
   while(length >= 16)
   {
      //Merge the tweak into the input block
      xtsXorBlock(x, p, t);
      //Encrypt the block using K1
      context->cipherAlgo->encryptBlock(&context->cipherContext1, x, x);
      //Merge the tweak into the output block
      xtsXorBlock(c, x, t);

      //Multiply T by x in GF(2^128)
      xtsMul(t, t);

      //Next block
      p += 16;
      c += 16;
      length -= 16;
   }

   //Any partial block?
   if(length > 0)
   {
      //Copy the final ciphertext bytes
      osMemcpy(c, c - 16, length);
      //Copy the final plaintext bytes
      osMemcpy(x, p, length);
      //Steal ciphertext to complete the block
      osMemcpy(x + length, c + length - 16, 16 - length);

      //Merge the tweak into the input block
      xtsXorBlock(x, x, t);
      //Encrypt the final block using K1
      context->cipherAlgo->encryptBlock(&context->cipherContext1, x, x);
      //Merge the tweak into the output block
      xtsXorBlock(c - 16, x, t);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Decrypt a data unit using XTS
 * @param[in] context Pointer to the XTS context
 * @param[in] i Value of the 128-bit tweak
 * @param[in] c Pointer to the data unit to be decrypted (ciphertext)
 * @param[out] p Pointer to the resulting data unit (plaintext)
 * @param[in] length Length of the data unit, in bytes
 * @return Error code
 **/

error_t xtsDecrypt(XtsContext *context, const uint8_t *i, const uint8_t *c,
   uint8_t *p, size_t length)
{
   uint8_t t[16];
   uint8_t x[16];

   //The data unit size shall be at least 128 bits
   if(length < 16)
      return ERROR_INVALID_PARAMETER;

   //Encrypt the tweak using K2
   context->cipherAlgo->encryptBlock(&context->cipherContext2, i, t);

   //XTS mode operates in a block-by-block fashion
   while(length >= 32)
   {
      //Merge the tweak into the input block
      xtsXorBlock(x, c, t);
      //Decrypt the block using K1
      context->cipherAlgo->decryptBlock(&context->cipherContext1, x, x);
      //Merge the tweak into the output block
      xtsXorBlock(p, x, t);

      //Multiply T by x in GF(2^128)
      xtsMul(t, t);

      //Next block
      c += 16;
      p += 16;
      length -= 16;
   }

   //Any partial block?
   if(length > 16)
   {
      uint8_t tt[16];

      //Multiply T by x in GF(2^128)
      xtsMul(tt, t);

      //Merge the tweak into the input block
      xtsXorBlock(x, c, tt);
      //Decrypt the next-to-last block using K1
      context->cipherAlgo->decryptBlock(&context->cipherContext1, x, x);
      //Merge the tweak into the output block
      xtsXorBlock(p, x, tt);

      //Retrieve the length of the final block
      length -= 16;

      //Copy the final plaintext bytes
      osMemcpy(p + 16, p, length);
      //Copy the final ciphertext bytes
      osMemcpy(x, c + 16, length);
      //Steal ciphertext to complete the block
      osMemcpy(x + length, p + length, 16 - length);
   }
   else
   {
      //The last block contains exactly 128 bits
      osMemcpy(x, c, 16);
   }

   //Merge the tweak into the input block
   xtsXorBlock(x, x, t);
   //Decrypt the final block using K1
   context->cipherAlgo->decryptBlock(&context->cipherContext1, x, x);
   //Merge the tweak into the output block
   xtsXorBlock(p, x, t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Multiplication by x in GF(2^128)
 * @param[out] x Pointer to the output block
 * @param[out] a Pointer to the input block
 **/

void xtsMul(uint8_t *x, const uint8_t *a)
{
   size_t i;
   uint8_t c;

   //Save the value of the most significant bit
   c = a[15] >> 7;

   //The multiplication of a polynomial by x in GF(2^128) corresponds to a
   //shift of indices
   for(i = 15; i > 0; i--)
   {
      x[i] = (a[i] << 1) | (a[i - 1] >> 7);
   }

   //Shift the first byte of the block
   x[0] = a[0] << 1;

   //If the highest term of the result is equal to one, then perform reduction
   x[0] ^= 0x87 & ~(c - 1);
}


/**
 * @brief XOR operation
 * @param[out] x Block resulting from the XOR operation
 * @param[in] a First input block
 * @param[in] b Second input block
 **/

void xtsXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b)
{
   size_t i;

   //Perform XOR operation
   for(i = 0; i < 16; i++)
   {
      x[i] = a[i] ^ b[i];
   }
}

#endif

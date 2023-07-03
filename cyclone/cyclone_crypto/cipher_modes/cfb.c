/**
 * @file cfb.c
 * @brief Cipher Feedback (CFB) mode
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
 * The Cipher Feedback (CFB) mode is a confidentiality mode that features the
 * feedback of successive ciphertext segments into the input blocks of the
 * forward cipher to generate output blocks that are exclusive-ORed with the
 * plaintext to produce the ciphertext, and vice versa. The CFB mode requires
 * an IV as the initial input block. The IV need not be secret, but it must be
 * unpredictable. Refer to SP 800-38A for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher_modes/cfb.h"
#include "debug.h"

//Check crypto library configuration
#if (CFB_SUPPORT == ENABLED)


/**
 * @brief CFB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

__weak_func error_t cfbEncrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   size_t i;
   size_t n;
   uint8_t o[16];

   //The parameter must be a multiple of 8
   if((s % 8) != 0)
      return ERROR_INVALID_PARAMETER;

   //Determine the size, in bytes, of the plaintext and ciphertext segments
   s = s / 8;

   //Check the resulting value
   if(s < 1 || s > cipher->blockSize)
      return ERROR_INVALID_PARAMETER;

   //Process each plaintext segment
   while(length > 0)
   {
      //Compute the number of bytes to process at a time
      n = MIN(length, s);

      //Compute O(j) = CIPH(I(j))
      cipher->encryptBlock(context, iv, o);

      //Compute C(j) = P(j) XOR MSB(O(j))
      for(i = 0; i < n; i++)
      {
         c[i] = p[i] ^ o[i];
      }

      //Compute I(j+1) = LSB(I(j)) | C(j)
      osMemmove(iv, iv + s, cipher->blockSize - s);
      osMemcpy(iv + cipher->blockSize - s, c, s);

      //Next block
      p += n;
      c += n;
      length -= n;
   }

   //Successful encryption
   return NO_ERROR;
}


/**
 * @brief CFB decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

__weak_func error_t cfbDecrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *c, uint8_t *p, size_t length)
{
   size_t i;
   size_t n;
   uint8_t o[16];

   //The parameter must be a multiple of 8
   if((s % 8) != 0)
      return ERROR_INVALID_PARAMETER;

   //Determine the size, in bytes, of the plaintext and ciphertext segments
   s = s / 8;

   //Check the resulting value
   if(s < 1 || s > cipher->blockSize)
      return ERROR_INVALID_PARAMETER;

   //Process each ciphertext segment
   while(length > 0)
   {
      //Compute the number of bytes to process at a time
      n = MIN(length, s);

      //Compute O(j) = CIPH(I(j))
      cipher->encryptBlock(context, iv, o);

      //Compute I(j+1) = LSB(I(j)) | C(j)
      osMemmove(iv, iv + s, cipher->blockSize - s);
      osMemcpy(iv + cipher->blockSize - s, c, s);

      //Compute P(j) = C(j) XOR MSB(O(j))
      for(i = 0; i < n; i++)
      {
         p[i] = c[i] ^ o[i];
      }

      //Next block
      c += n;
      p += n;
      length -= n;
   }

   //Successful encryption
   return NO_ERROR;
}

#endif

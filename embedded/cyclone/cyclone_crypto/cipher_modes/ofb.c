/**
 * @file ofb.c
 * @brief Output Feedback (OFB) mode
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
 * The Output Feedback (OFB) mode is a confidentiality mode that features the
 * iteration of the forward cipher on an IV to generate a sequence of output
 * blocks that are exclusive-ORed with the plaintext to produce the ciphertext,
 * and vice versa. The OFB mode requires that the IV is a nonce, i.e., the IV
 * must be unique for each execution of the mode under the given key.
 * Refer to SP 800-38A for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher_modes/ofb.h"
#include "debug.h"

//Check crypto library configuration
#if (OFB_SUPPORT == ENABLED)


/**
 * @brief OFB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

__weak_func error_t ofbEncrypt(const CipherAlgo *cipher, void *context, uint_t s,
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

      //Compute I(j+1) = LSB(I(j)) | O(j)
      osMemmove(iv, iv + s, cipher->blockSize - s);
      osMemcpy(iv + cipher->blockSize - s, o, s);

      //Next block
      p += n;
      c += n;
      length -= n;
   }

   //Successful encryption
   return NO_ERROR;
}


/**
 * @brief OFB decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

error_t ofbDecrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *c, uint8_t *p, size_t length)
{
   //Decryption is the same the as encryption with P and C interchanged
   return ofbEncrypt(cipher, context, s, iv, c, p, length);
}

#endif

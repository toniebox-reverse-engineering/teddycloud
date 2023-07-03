/**
 * @file cbc.c
 * @brief Cipher Block Chaining (CBC) mode
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
 * The Cipher Block Chaining (CBC) mode is a confidentiality mode whose
 * encryption process features the combining of the plaintext blocks with
 * the previous ciphertext blocks. The CBC mode requires an IV to combine
 * with the first plaintext block. Refer to SP 800-38A for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher_modes/cbc.h"
#include "debug.h"

//Check crypto library configuration
#if (CBC_SUPPORT == ENABLED)


/**
 * @brief CBC encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

__weak_func error_t cbcEncrypt(const CipherAlgo *cipher, void *context,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   size_t i;

   //CBC mode operates in a block-by-block fashion
   while(length >= cipher->blockSize)
   {
      //XOR input block with IV contents
      for(i = 0; i < cipher->blockSize; i++)
      {
         c[i] = p[i] ^ iv[i];
      }

      //Encrypt the current block based upon the output of the previous
      //encryption
      cipher->encryptBlock(context, c, c);

      //Update IV with output block contents
      osMemcpy(iv, c, cipher->blockSize);

      //Next block
      p += cipher->blockSize;
      c += cipher->blockSize;
      length -= cipher->blockSize;
   }

   //The plaintext must be a multiple of the block size
   if(length != 0)
      return ERROR_INVALID_LENGTH;

   //Successful encryption
   return NO_ERROR;
}


/**
 * @brief CBC decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

__weak_func error_t cbcDecrypt(const CipherAlgo *cipher, void *context,
   uint8_t *iv, const uint8_t *c, uint8_t *p, size_t length)
{
   size_t i;
   uint8_t t[16];

   //CBC mode operates in a block-by-block fashion
   while(length >= cipher->blockSize)
   {
      //Save input block
      osMemcpy(t, c, cipher->blockSize);

      //Decrypt the current block
      cipher->decryptBlock(context, c, p);

      //XOR output block with IV contents
      for(i = 0; i < cipher->blockSize; i++)
      {
         p[i] ^= iv[i];
      }

      //Update IV with input block contents
      osMemcpy(iv, t, cipher->blockSize);

      //Next block
      c += cipher->blockSize;
      p += cipher->blockSize;
      length -= cipher->blockSize;
   }

   //The ciphertext must be a multiple of the block size
   if(length != 0)
      return ERROR_INVALID_LENGTH;

   //Successful encryption
   return NO_ERROR;
}

#endif

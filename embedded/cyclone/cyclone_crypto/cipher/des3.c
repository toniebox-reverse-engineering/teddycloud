/**
 * @file des3.c
 * @brief Triple DES (Triple Data Encryption Algorithm)
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
 * Triple DES is an encryption algorithm designed to encipher and decipher blocks
 * of 64 bits under control of a 192-bit key. Refer to FIPS 46-3 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher/des3.h"
#include "cipher/des.h"

//Check crypto library configuration
#if (DES3_SUPPORT == ENABLED)

//Common interface for encryption algorithms
const CipherAlgo des3CipherAlgo =
{
   "3DES",
   sizeof(Des3Context),
   CIPHER_ALGO_TYPE_BLOCK,
   DES3_BLOCK_SIZE,
   (CipherAlgoInit) des3Init,
   NULL,
   NULL,
   (CipherAlgoEncryptBlock) des3EncryptBlock,
   (CipherAlgoDecryptBlock) des3DecryptBlock,
   (CipherAlgoDeinit) des3Deinit
};


/**
 * @brief Initialize a Triple DES context using the supplied key
 * @param[in] context Pointer to the Triple DES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

__weak_func error_t des3Init(Des3Context *context, const uint8_t *key,
   size_t keyLen)
{
   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check key length
   if(keyLen == 8)
   {
      //This option provides backward compatibility with DES, because the
      //first and second DES operations cancel out
      desInit(&context->k1, key, 8);
      desInit(&context->k2, key, 8);
      desInit(&context->k3, key, 8);
   }
   else if(keyLen == 16)
   {
      //If the key length is 128 bits including parity, the first 8 bytes of the
      //encoding represent the key used for the two outer DES operations, and
      //the second 8 bytes represent the key used for the inner DES operation
      desInit(&context->k1, key, 8);
      desInit(&context->k2, key + 8, 8);
      desInit(&context->k3, key, 8);
   }
   else if(keyLen == 24)
   {
      //If the key length is 192 bits including parity, then 3 independent DES
      //keys are represented, in the order in which they are used for encryption
      desInit(&context->k1, key, 8);
      desInit(&context->k2, key + 8, 8);
      desInit(&context->k3, key + 16, 8);
   }
   else
   {
      //The length of the key is not valid
      return ERROR_INVALID_KEY_LENGTH;
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

__weak_func void des3EncryptBlock(Des3Context *context, const uint8_t *input,
   uint8_t *output)
{
   //The first pass is a DES encryption
   desEncryptBlock(&context->k1, input, output);
   //The second pass is a DES decryption of the first ciphertext result
   desDecryptBlock(&context->k2, output, output);
   //The third pass is a DES encryption of the second pass result
   desEncryptBlock(&context->k3, output, output);
}


/**
 * @brief Decrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

__weak_func void des3DecryptBlock(Des3Context *context, const uint8_t *input,
   uint8_t *output)
{
   //The first pass is a DES decryption
   desDecryptBlock(&context->k3, input, output);
   //The second pass is a DES encryption of the first pass result
   desEncryptBlock(&context->k2, output, output);
   //The third pass is a DES decryption of the second ciphertext result
   desDecryptBlock(&context->k1, output, output);
}


/**
 * @brief Release Triple DES context
 * @param[in] context Pointer to the Triple DES context
 **/

__weak_func void des3Deinit(Des3Context *context)
{
   //Clear Triple DES context
   osMemset(context, 0, sizeof(Des3Context));
}

#endif

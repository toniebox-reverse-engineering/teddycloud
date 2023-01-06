/**
 * @file saml11_crypto_cipher.c
 * @brief SAML11 cipher hardware accelerator
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
#include "sam.h"
#include "core/crypto.h"
#include "hardware/saml11/saml11_crypto.h"
#include "hardware/saml11/saml11_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (SAML11_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief Key expansion
 * @param[in] context Pointer to the AES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t aesInit(AesContext *context, const uint8_t *key, size_t keyLen)
{
   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //192 and 256-bit keys are not supported
   if(keyLen != 16)
      return ERROR_INVALID_KEY_LENGTH;

   //10 rounds are required for 128-bit key
   context->nr = 10;

   //Copy the original key
   context->ek[0] = LOAD32LE(key);
   context->ek[1] = LOAD32LE(key + 4);
   context->ek[2] = LOAD32LE(key + 8);
   context->ek[3] = LOAD32LE(key + 12);

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void aesEncryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   uint32_t p[4];
   uint32_t c[4];

   //The pointer to the plaintext must be 32-bit aligned
   osMemcpy(p, input, sizeof(p));

   //Acquire exclusive access to the CRYA module
   osAcquireMutex(&saml11CryptoMutex);
   //Perform AES-128 encryption
   crya_aes_encrypt((uint8_t *) context->ek, 4, (uint8_t *) p, (uint8_t *) c);
   //Release exclusive access to the CRYA module
   osReleaseMutex(&saml11CryptoMutex);

   //Copy the resulting ciphertext
   osMemcpy(output, c, sizeof(c));
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   uint32_t p[4];
   uint32_t c[4];

   //The pointer to the ciphertext must be 32-bit aligned
   osMemcpy(c, input, sizeof(c));

   //Acquire exclusive access to the CRYA module
   osAcquireMutex(&saml11CryptoMutex);
   //Perform AES-128 decryption
   crya_aes_decrypt((uint8_t *) context->ek, 4, (uint8_t *) c, (uint8_t *) p);
   //Release exclusive access to the CRYA module
   osReleaseMutex(&saml11CryptoMutex);

   //Copy the resulting plaintext
   osMemcpy(output, p, sizeof(p));
}


#if (GCM_SUPPORT == ENABLED)

/**
 * @brief Initialize GCM context
 * @param[in] context Pointer to the GCM context
 * @param[in] cipherAlgo Cipher algorithm
 * @param[in] cipherContext Pointer to the cipher algorithm context
 * @return Error code
 **/

error_t gcmInit(GcmContext *context, const CipherAlgo *cipherAlgo,
   void *cipherContext)
{
   uint32_t h[4];

   //The CRYPTO module only supports AES cipher algorithm
   if(cipherAlgo != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Save cipher algorithm context
   context->cipherAlgo = cipherAlgo;
   context->cipherContext = cipherContext;

   //Let H = 0
   h[0] = 0;
   h[1] = 0;
   h[2] = 0;
   h[3] = 0;

   //Generate the hash subkey H
   aesEncryptBlock(context->cipherContext, (uint8_t *) h, (uint8_t *) h);

   //Save the resulting value
   context->m[0][0] = h[0];
   context->m[0][1] = h[1];
   context->m[0][2] = h[2];
   context->m[0][3] = h[3];

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Multiplication operation in GF(2^128)
 * @param[in] context Pointer to the GCM context
 * @param[in, out] x 16-byte block to be multiplied by H
 **/

void gcmMul(GcmContext *context, uint8_t *x)
{
   uint32_t a[4];
   uint32_t r[4];

   //The pointer to the input block must be 32-bit aligned
   osMemcpy(a, x, sizeof(a));

   //Acquire exclusive access to the CRYA module
   osAcquireMutex(&saml11CryptoMutex);
   //Perform GF(2^128) multiplication
   crya_gf_mult128(a, context->m[0], r);
   //Release exclusive access to the CRYA module
   osReleaseMutex(&saml11CryptoMutex);

   //Copy the resulting block
   osMemcpy(x, r, sizeof(r));
}

#endif
#endif

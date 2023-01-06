/**
 * @file mkv5x_crypto_cipher.c
 * @brief Kinetis KV5x cipher hardware accelerator
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
#include "fsl_device_registers.h"
#include "fsl_mmcau.h"
#include "core/crypto.h"
#include "hardware/mkv5x/mkv5x_crypto.h"
#include "hardware/mkv5x/mkv5x_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MKV5X_CRYPTO_CIPHER_SUPPORT == ENABLED)
#if (DES_SUPPORT == ENABLED)

/**
 * @brief Initialize a DES context using the supplied key
 * @param[in] context Pointer to the DES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key (must be set to 8)
 * @return Error code
 **/

error_t desInit(DesContext *context, const uint8_t *key, size_t keyLen)
{
   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid key length?
   if(keyLen != 8)
      return ERROR_INVALID_KEY_LENGTH;

   //Copy the key
   osMemcpy(context->ks, key, keyLen);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Encrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void desEncryptBlock(DesContext *context, const uint8_t *input, uint8_t *output)
{
   uint8_t temp[DES_BLOCK_SIZE];

   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);
   //Perform DES encryption
   MMCAU_DES_EncryptEcb(input, (const uint8_t *) context->ks, temp);
   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);

   //Copy the resulting ciphertext
   osMemcpy(output, temp, DES_BLOCK_SIZE);
}


/**
 * @brief Decrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void desDecryptBlock(DesContext *context, const uint8_t *input, uint8_t *output)
{
   uint8_t temp[DES_BLOCK_SIZE];

   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);
   //Perform DES decryption
   MMCAU_DES_DecryptEcb(input, (const uint8_t *) context->ks, temp);
   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);

   //Copy the resulting plaintext
   osMemcpy(output, temp, DES_BLOCK_SIZE);
}

#endif
#if (DES3_SUPPORT == ENABLED)

/**
 * @brief Encrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void des3EncryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   uint8_t temp[DES_BLOCK_SIZE];

   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);

   //The first pass is a DES encryption
   MMCAU_DES_EncryptEcb(input, (const uint8_t *) context->k1.ks, temp);
   //The second pass is a DES decryption of the first ciphertext result
   MMCAU_DES_DecryptEcb(temp, (const uint8_t *) context->k2.ks, output);
   //The third pass is a DES encryption of the second pass result
   MMCAU_DES_EncryptEcb(output, (const uint8_t *) context->k3.ks, temp);

   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);

   //Copy the resulting ciphertext
   osMemcpy(output, temp, DES_BLOCK_SIZE);
}


/**
 * @brief Decrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void des3DecryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   uint8_t temp[DES_BLOCK_SIZE];

   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);

   //The first pass is a DES decryption
   MMCAU_DES_DecryptEcb(input, (const uint8_t *) context->k3.ks, temp);
   //The second pass is a DES encryption of the first pass result
   MMCAU_DES_EncryptEcb(temp, (const uint8_t *) context->k2.ks, output);
   //The third pass is a DES decryption of the second ciphertext result
   MMCAU_DES_DecryptEcb(output, (const uint8_t *) context->k1.ks, temp);

   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);

   //Copy the resulting plaintext
   osMemcpy(output, temp, DES_BLOCK_SIZE);
}

#endif
#if (AES_SUPPORT == ENABLED)

/**
 * @brief Key expansion
 * @param[in] context Pointer to the AES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t aesInit(AesContext *context, const uint8_t *key, size_t keyLen)
{
   status_t status;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the key
   if(keyLen == 16)
   {
      //10 rounds are required for 128-bit key
      context->nr = 10;
   }
   else if(keyLen == 24)
   {
      //12 rounds are required for 192-bit key
      context->nr = 12;
   }
   else if(keyLen == 32)
   {
      //14 rounds are required for 256-bit key
      context->nr = 14;
   }
   else
   {
      //Report an error
      return ERROR_INVALID_KEY_LENGTH;
   }

   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);
   //Perform AES key expansion
   status = MMCAU_AES_SetKey(key, keyLen, (uint8_t *) context->ek);
   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Encrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void aesEncryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   uint8_t temp[AES_BLOCK_SIZE];

   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);

   //Perform AES encryption
   MMCAU_AES_EncryptEcb(input, (const uint8_t *) context->ek, context->nr,
      temp);

   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);

   //Copy the resulting ciphertext
   osMemcpy(output, temp, AES_BLOCK_SIZE);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   uint8_t temp[AES_BLOCK_SIZE];

   //Acquire exclusive access to the MMCAU module
   osAcquireMutex(&mkv5xCryptoMutex);

   //Perform AES decryption
   MMCAU_AES_DecryptEcb(input, (const uint8_t *) context->ek, context->nr,
      temp);

   //Release exclusive access to the MMCAU module
   osReleaseMutex(&mkv5xCryptoMutex);

   //Copy the resulting plaintext
   osMemcpy(output, temp, AES_BLOCK_SIZE);
}

#endif
#endif

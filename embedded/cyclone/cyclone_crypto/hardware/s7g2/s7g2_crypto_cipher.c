/**
 * @file s7g2_crypto_cipher.c
 * @brief Synergy S7G2 cipher hardware accelerator
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
#include "hw_sce_private.h"
#include "hw_sce_tdes_private.h"
#include "hw_sce_aes_private.h"
#include "core/crypto.h"
#include "hardware/s7g2/s7g2_crypto.h"
#include "hardware/s7g2/s7g2_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (S7G2_CRYPTO_CIPHER_SUPPORT == ENABLED)
#if (DES3_SUPPORT == ENABLED)


/**
 * @brief Initialize a Triple DES context using the supplied key
 * @param[in] context Pointer to the Triple DES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t des3Init(Des3Context *context, const uint8_t *key, size_t keyLen)
{
   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check key length
   if(keyLen == 8)
   {
      //This option provides backward compatibility with DES, because the
      //first and second DES operations cancel out
      context->k1.ks[0] = LOAD32LE(key + 0);
      context->k1.ks[1] = LOAD32LE(key + 4);
      context->k1.ks[2] = LOAD32LE(key + 0);
      context->k1.ks[3] = LOAD32LE(key + 4);
      context->k1.ks[4] = LOAD32LE(key + 0);
      context->k1.ks[5] = LOAD32LE(key + 4);
   }
   else if(keyLen == 16)
   {
      //If the key length is 128 bits including parity, the first 8 bytes of the
      //encoding represent the key used for the two outer DES operations, and
      //the second 8 bytes represent the key used for the inner DES operation
      context->k1.ks[0] = LOAD32LE(key + 0);
      context->k1.ks[1] = LOAD32LE(key + 4);
      context->k1.ks[2] = LOAD32LE(key + 8);
      context->k1.ks[3] = LOAD32LE(key + 12);
      context->k1.ks[4] = LOAD32LE(key + 0);
      context->k1.ks[5] = LOAD32LE(key + 4);
   }
   else if(keyLen == 24)
   {
      //If the key length is 192 bits including parity, then 3 independent DES
      //keys are represented, in the order in which they are used for encryption
      context->k1.ks[0] = LOAD32LE(key + 0);
      context->k1.ks[1] = LOAD32LE(key + 4);
      context->k1.ks[2] = LOAD32LE(key + 8);
      context->k1.ks[3] = LOAD32LE(key + 12);
      context->k1.ks[4] = LOAD32LE(key + 16);
      context->k1.ks[5] = LOAD32LE(key + 20);
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

void des3EncryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   ssp_err_t status;

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&s7g2CryptoMutex);

   //Perform Triple DES encryption
   status = HW_SCE_TDES_192EcbEncrypt(context->k1.ks, DES3_BLOCK_SIZE / 4,
      (const uint32_t *) input, (uint32_t *) output);

   //Check status code
   if(status != SSP_SUCCESS)
   {
      osMemset(output, 0, DES3_BLOCK_SIZE);
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s7g2CryptoMutex);
}


/**
 * @brief Decrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void des3DecryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   ssp_err_t status;

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&s7g2CryptoMutex);

   //Perform Triple DES decryption
   status = HW_SCE_TDES_192EcbDecrypt(context->k1.ks, DES3_BLOCK_SIZE / 4,
      (const uint32_t *) input, (uint32_t *) output);

   //Check status code
   if(status != SSP_SUCCESS)
   {
      osMemset(output, 0, DES3_BLOCK_SIZE);
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s7g2CryptoMutex);
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
   ssp_err_t status;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   status = SSP_SUCCESS;

   //Check the length of the key
   if(keyLen == 16)
   {
      //10 rounds are required for 128-bit key
      context->nr = 10;
      //Copy the key
      osMemcpy(context->ek, key, keyLen);
   }
   else if(keyLen == 24)
   {
      //12 rounds are required for 192-bit key
      context->nr = 12;
      //Copy the key
      osMemcpy(context->ek, key, keyLen);
   }
   else if(keyLen == 32)
   {
      //14 rounds are required for 256-bit key
      context->nr = 14;
      //Copy the key
      osMemcpy(context->ek, key, keyLen);
   }
   else
   {
      //192-bit keys are not supported
      status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Return status code
   return (status == SSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Encrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void aesEncryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   ssp_err_t status;

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&s7g2CryptoMutex);

   //Check the length of the key
   if(context->nr == 10)
   {
      //Perform AES encryption (128-bit key)
      status = HW_SCE_AES_128EcbEncrypt(context->ek, AES_BLOCK_SIZE / 4,
         (const uint32_t *) input, (uint32_t *) output);
   }
   else if(context->nr == 12)
   {
      //Perform AES encryption (192-bit key)
      status = HW_SCE_AES_192EcbEncrypt(context->ek, AES_BLOCK_SIZE / 4,
         (const uint32_t *) input, (uint32_t *) output);
   }
   else if(context->nr == 14)
   {
      //Perform AES encryption (256-bit key)
      status = HW_SCE_AES_256EcbEncrypt(context->ek, AES_BLOCK_SIZE / 4,
         (const uint32_t *) input, (uint32_t *) output);
   }
   else
   {
      //Invalid key length
      status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status != SSP_SUCCESS)
   {
      osMemset(output, 0, AES_BLOCK_SIZE);
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s7g2CryptoMutex);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   ssp_err_t status;

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&s7g2CryptoMutex);

   //Check the length of the key
   if(context->nr == 10)
   {
      //Perform AES decryption (128-bit key)
      status = HW_SCE_AES_128EcbDecrypt(context->ek, AES_BLOCK_SIZE / 4,
         (const uint32_t *) input, (uint32_t *) output);
   }
   else if(context->nr == 12)
   {
      //Perform AES decryption (192-bit key)
      status = HW_SCE_AES_192EcbDecrypt(context->ek, AES_BLOCK_SIZE / 4,
         (const uint32_t *) input, (uint32_t *) output);
   }
   else if(context->nr == 14)
   {
      //Perform AES decryption (256-bit key)
      status = HW_SCE_AES_256EcbDecrypt(context->ek, AES_BLOCK_SIZE / 4,
         (const uint32_t *) input, (uint32_t *) output);
   }
   else
   {
      //Invalid key length
      status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status != SSP_SUCCESS)
   {
      osMemset(output, 0, AES_BLOCK_SIZE);
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s7g2CryptoMutex);
}

#endif
#if (ECB_SUPPORT == ENABLED)

/**
 * @brief ECB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t ecbEncrypt(const CipherAlgo *cipher, void *context,
   const uint8_t *p, uint8_t *c, size_t length)
{
   ssp_err_t status;

   //Initialize status code
   status = SSP_SUCCESS;

#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         Des3Context *des3Context;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Acquire exclusive access to the SCE7 module
         osAcquireMutex(&s7g2CryptoMutex);

         //Perform 3DES-ECB encryption
         status = HW_SCE_TDES_192EcbEncrypt(des3Context->k1.ks, length / 4,
            (const uint32_t *) p, (uint32_t *) c);

         //Release exclusive access to the SCE7 module
         osReleaseMutex(&s7g2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the SCE7 module
         osAcquireMutex(&s7g2CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-ECB encryption (128-bit key)
            status = HW_SCE_AES_128EcbEncrypt(aesContext->ek, length / 4,
               (const uint32_t *) p, (uint32_t *) c);
         }
         else if(aesContext->nr == 12)
         {
            //Perform AES-ECB encryption (192-bit key)
            status = HW_SCE_AES_192EcbEncrypt(aesContext->ek, length / 4,
               (const uint32_t *) p, (uint32_t *) c);
         }
         else if(aesContext->nr == 14)
         {
            //Perform AES-ECB encryption (256-bit key)
            status = HW_SCE_AES_256EcbEncrypt(aesContext->ek, length / 4,
               (const uint32_t *) p, (uint32_t *) c);
         }
         else
         {
            //Invalid key length
            status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }

         //Release exclusive access to the SCE7 module
         osReleaseMutex(&s7g2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //ECB mode operates in a block-by-block fashion
      while(length >= cipher->blockSize)
      {
         //Encrypt current block
         cipher->encryptBlock(context, p, c);

         //Next block
         p += cipher->blockSize;
         c += cipher->blockSize;
         length -= cipher->blockSize;
      }

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }

   //Return status code
   return (status == SSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief ECB decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

error_t ecbDecrypt(const CipherAlgo *cipher, void *context,
   const uint8_t *c, uint8_t *p, size_t length)
{
   ssp_err_t status;

   //Initialize status code
   status = SSP_SUCCESS;

#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         Des3Context *des3Context;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Acquire exclusive access to the SCE7 module
         osAcquireMutex(&s7g2CryptoMutex);

         //Perform 3DES-ECB decryption
         status = HW_SCE_TDES_192EcbDecrypt(des3Context->k1.ks, length / 4,
            (const uint32_t *) p, (uint32_t *) c);

         //Release exclusive access to the SCE7 module
         osReleaseMutex(&s7g2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the SCE7 module
         osAcquireMutex(&s7g2CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-ECB decryption (128-bit key)
            status = HW_SCE_AES_128EcbDecrypt(aesContext->ek, length / 4,
               (const uint32_t *) c, (uint32_t *) p);
         }
         else if(aesContext->nr == 12)
         {
            //Perform AES-ECB decryption (192-bit key)
            status = HW_SCE_AES_192EcbDecrypt(aesContext->ek, length / 4,
               (const uint32_t *) c, (uint32_t *) p);
         }
         else if(aesContext->nr == 14)
         {
            //Perform AES-ECB decryption (256-bit key)
            status = HW_SCE_AES_256EcbDecrypt(aesContext->ek, length / 4,
               (const uint32_t *) c, (uint32_t *) p);
         }
         else
         {
            //Invalid key length
            status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }

         //Release exclusive access to the SCE7 module
         osReleaseMutex(&s7g2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //ECB mode operates in a block-by-block fashion
      while(length >= cipher->blockSize)
      {
         //Decrypt current block
         cipher->decryptBlock(context, c, p);

         //Next block
         c += cipher->blockSize;
         p += cipher->blockSize;
         length -= cipher->blockSize;
      }

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }

   //Return status code
   return (status == SSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
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

error_t cbcEncrypt(const CipherAlgo *cipher, void *context,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   ssp_err_t status;

   //Initialize status code
   status = SSP_SUCCESS;

#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         Des3Context *des3Context;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Acquire exclusive access to the SCE7 module
         osAcquireMutex(&s7g2CryptoMutex);

         //Perform 3DES-CBC encryption
         status = HW_SCE_TDES_192CbcEncrypt(des3Context->k1.ks,
            (const uint32_t *) iv, length / 4, (const uint32_t *) p,
            (uint32_t *) c, (uint32_t *) iv);

         //Release exclusive access to the SCE7 module
         osReleaseMutex(&s7g2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the SCE7 module
         osAcquireMutex(&s7g2CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-CBC encryption (128-bit key)
            status = HW_SCE_AES_128CbcEncrypt(aesContext->ek,
               (const uint32_t *) iv, length / 4, (const uint32_t *) p,
               (uint32_t *) c, (uint32_t *) iv);
         }
         else if(aesContext->nr == 12)
         {
            //Perform AES-CBC encryption (192-bit key)
            status = HW_SCE_AES_192CbcEncrypt(aesContext->ek,
               (const uint32_t *) iv, length / 4, (const uint32_t *) p,
               (uint32_t *) c, (uint32_t *) iv);
         }
         else if(aesContext->nr == 14)
         {
            //Perform AES-CBC encryption (256-bit key)
            status = HW_SCE_AES_256CbcEncrypt(aesContext->ek,
               (const uint32_t *) iv, length / 4, (const uint32_t *) p,
               (uint32_t *) c, (uint32_t *) iv);
         }
         else
         {
            //Invalid key length
            status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }

         //Release exclusive access to the SCE7 module
         osReleaseMutex(&s7g2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
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

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }

   //Return status code
   return (status == SSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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

error_t cbcDecrypt(const CipherAlgo *cipher, void *context,
   uint8_t *iv, const uint8_t *c, uint8_t *p, size_t length)
{
   ssp_err_t status;

   //Initialize status code
   status = SSP_SUCCESS;

#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         Des3Context *des3Context;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Acquire exclusive access to the SCE7 module
         osAcquireMutex(&s7g2CryptoMutex);

         //Perform 3DES-CBC decryption
         status = HW_SCE_TDES_192CbcDecrypt(des3Context->k1.ks,
            (const uint32_t *) iv, length / 4, (const uint32_t *) c,
            (uint32_t *) p, (uint32_t *) iv);

         //Release exclusive access to the SCE7 module
         osReleaseMutex(&s7g2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the SCE7 module
         osAcquireMutex(&s7g2CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-CBC decryption (128-bit key)
            status = HW_SCE_AES_128CbcDecrypt(aesContext->ek,
               (const uint32_t *) iv, length / 4, (const uint32_t *) c,
               (uint32_t *) p, (uint32_t *) iv);
         }
         else if(aesContext->nr == 12)
         {
            //Perform AES-CBC decryption (192-bit key)
            status = HW_SCE_AES_192CbcDecrypt(aesContext->ek,
               (const uint32_t *) iv, length / 4, (const uint32_t *) c,
               (uint32_t *) p, (uint32_t *) iv);
         }
         else if(aesContext->nr == 14)
         {
            //Perform AES-CBC decryption (256-bit key)
            status = HW_SCE_AES_256CbcDecrypt(aesContext->ek,
               (const uint32_t *) iv, length / 4, (const uint32_t *) c,
               (uint32_t *) p, (uint32_t *) iv);
         }
         else
         {
            //Invalid key length
            status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }

         //Release exclusive access to the SCE7 module
         osReleaseMutex(&s7g2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
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

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         status = SSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }

   //Return status code
   return (status == SSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#if (CTR_SUPPORT == ENABLED)

/**
 * @brief CTR encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] m Size in bits of the specific part of the block to be incremented
 * @param[in,out] t Initial counter block
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t ctrEncrypt(const CipherAlgo *cipher, void *context, uint_t m,
   uint8_t *t, const uint8_t *p, uint8_t *c, size_t length)
{
   ssp_err_t status;

   //Initialize status code
   status = SSP_SUCCESS;

#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(m == (DES3_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length == 0)
         {
            //No data to process
         }
         else if((length % DES3_BLOCK_SIZE) == 0)
         {
            Des3Context *des3Context;

            //Point to the Triple DES context
            des3Context = (Des3Context *) context;

            //Acquire exclusive access to the SCE7 module
            osAcquireMutex(&s7g2CryptoMutex);

            //Perform 3DES-CTR encryption
            status = HW_SCE_TDES_192CtrEncrypt(des3Context->k1.ks,
               (const uint32_t *) t, length / 4, (const uint32_t *) p,
               (uint32_t *) c, (uint32_t *) t);

            //Release exclusive access to the SCE7 module
            osReleaseMutex(&s7g2CryptoMutex);
         }
         else
         {
            //The length of the payload must be a multiple of the block size
            status = SSP_ERR_CRYPTO_INVALID_SIZE;
         }
      }
      else
      {
         //The value of the parameter is not valid
         status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(m == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length == 0)
         {
            //No data to process
         }
         else if((length % AES_BLOCK_SIZE) == 0)
         {
            AesContext *aesContext;

            //Point to the AES context
            aesContext = (AesContext *) context;

            //Acquire exclusive access to the SCE7 module
            osAcquireMutex(&s7g2CryptoMutex);

            //Check the length of the key
            if(aesContext->nr == 10)
            {
               //Perform AES-CTR encryption (128-bit key)
               status = HW_SCE_AES_128CtrEncrypt(aesContext->ek,
                  (const uint32_t *) t, length / 4, (const uint32_t *) p,
                  (uint32_t *) c, (uint32_t *) t);
            }
            else if(aesContext->nr == 12)
            {
               //Perform AES-CTR encryption (192-bit key)
               status = HW_SCE_AES_192CtrEncrypt(aesContext->ek,
                  (const uint32_t *) t, length / 4, (const uint32_t *) p,
                  (uint32_t *) c, (uint32_t *) t);
            }
            else if(aesContext->nr == 14)
            {
               //Perform AES-CTR encryption (256-bit key)
               status = HW_SCE_AES_256CtrEncrypt(aesContext->ek,
                  (const uint32_t *) t, length / 4, (const uint32_t *) p,
                  (uint32_t *) c, (uint32_t *) t);
            }
            else
            {
               //Invalid key length
               status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
            }

            //Release exclusive access to the SCE7 module
            osReleaseMutex(&s7g2CryptoMutex);
         }
         else
         {
            //The length of the payload must be a multiple of the block size
            status = SSP_ERR_CRYPTO_INVALID_SIZE;
         }
      }
      else
      {
         //The value of the parameter is not valid
         status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //Check the value of the parameter
      if((m % 8) == 0 && m <= (cipher->blockSize * 8))
      {
         size_t i;
         size_t n;
         uint16_t temp;
         uint8_t o[16];

         //Determine the size, in bytes, of the specific part of the block
         //to be incremented
         m = m / 8;

         //Process plaintext
         while(length > 0)
         {
            //CTR mode operates in a block-by-block fashion
            n = MIN(length, cipher->blockSize);

            //Compute O(j) = CIPH(T(j))
            cipher->encryptBlock(context, t, o);

            //Compute C(j) = P(j) XOR T(j)
            for(i = 0; i < n; i++)
            {
               c[i] = p[i] ^ o[i];
            }

            //Standard incrementing function
            for(temp = 1, i = 1; i <= m; i++)
            {
               //Increment the current byte and propagate the carry
               temp += t[cipher->blockSize - i];
               t[cipher->blockSize - i] = temp & 0xFF;
               temp >>= 8;
            }

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
      else
      {
         //The value of the parameter is not valid
         status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }

   //Return status code
   return (status == SSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#if (GCM_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)

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

   //The SCE7 module only supports AES cipher algorithm
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
 * @brief Authenticated encryption using GCM
 * @param[in] context Pointer to the GCM context
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @param[out] t Authentication tag
 * @param[in] tLen Length of the authentication tag
 * @return Error code
 **/

error_t gcmEncrypt(GcmContext *context, const uint8_t *iv,
   size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *p,
   uint8_t *c, size_t length, uint8_t *t, size_t tLen)
{
   size_t k;
   size_t n;
   uint64_t m;
   uint32_t b[4];
   uint32_t j[4];
   uint32_t s[4];
   AesContext *aesContext;

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The length of the IV shall meet SP 800-38D requirements
   if(ivLen < 1)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Point to the AES context
   aesContext = (AesContext *) context->cipherContext;

   //Check the length of the key
   if(aesContext->nr != 10 && aesContext->nr != 12 && aesContext->nr != 14)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&s7g2CryptoMutex);

   //Check whether the length of the IV is 96 bits
   if(ivLen == 12)
   {
      //When the length of the IV is 96 bits, the padding string is appended
      //to the IV to form the pre-counter block
      j[0] = LOAD32LE(iv);
      j[1] = LOAD32LE(iv + 4);
      j[2] = LOAD32LE(iv + 8);
      j[3] = BETOH32(1);
   }
   else
   {
      //Initialize GHASH calculation
      j[0] = 0;
      j[1] = 0;
      j[2] = 0;
      j[3] = 0;

      //Length of the IV
      n = ivLen;

      //Process the initialization vector
      if(n >= 16)
      {
         //Ensure the size of the incoming data to be processed is a multiple
         //of 16 bytes
         k = n & ~15UL;

         //Apply GHASH function
         HW_SCE_AES_Ghash(context->m[0], j, k / 4, (const uint32_t *) iv, j);

         //Advance data pointer
         iv += k;
         n -= k;
      }

      //Process the final block of the initialization vector
      if(n > 0)
      {
         //Copy partial block
         osMemset(b, 0, 16);
         osMemcpy(b, iv, n);

         //Apply GHASH function
         HW_SCE_AES_Ghash(context->m[0], j, 4, b, j);
      }

      //The string is appended with 64 additional 0 bits, followed by the
      //64-bit representation of the length of the IV
      b[0] = 0;
      b[1] = 0;
      m = ivLen * 8;
      b[2] = htobe32(m >> 32);
      b[3] = htobe32(m);

      //The GHASH function is applied to the resulting string to form the
      //pre-counter block
      HW_SCE_AES_Ghash(context->m[0], j, 4, b, j);
   }

   //Compute CIPH(J(0))
   if(aesContext->nr == 10)
   {
      HW_SCE_AES_128EcbEncrypt(aesContext->ek, 4, j, b);
   }
   else if(aesContext->nr == 12)
   {
      HW_SCE_AES_192EcbEncrypt(aesContext->ek, 4, j, b);
   }
   else
   {
      HW_SCE_AES_256EcbEncrypt(aesContext->ek, 4, j, b);
   }

   //Save MSB(CIPH(J(0)))
   osMemcpy(t, (const uint8_t *) b, tLen);

   //Increment the right-most 32 bits of the counter block. The remaining
   //left-most 96 bits remain unchanged
   j[3] =  htobe32(betoh32(j[3]) + 1);

   //Initialize GHASH calculation
   s[0] = 0;
   s[1] = 0;
   s[2] = 0;
   s[3] = 0;

   //Length of the AAD
   n = aLen;

   //Process AAD
   if(n >= 16)
   {
      //Ensure the size of the incoming data to be processed is a multiple
      //of 16 bytes
      k = n & ~15UL;

      //Apply GHASH function
      HW_SCE_AES_Ghash(context->m[0], s, k / 4, (const uint32_t *) a, s);

      //Advance data pointer
      a += k;
      n -= k;
   }

   //Process the final block of AAD
   if(n > 0)
   {
      //Copy partial block
      osMemset(b, 0, 16);
      osMemcpy(b, a, n);

      //Apply GHASH function
      HW_SCE_AES_Ghash(context->m[0], s, 4, b, s);
   }

   //Length of the plaintext
   n = length;

   //Process plaintext
   if(n >= 16)
   {
      //Ensure the size of the incoming data to be processed is a multiple
      //of 16 bytes
      k = n & ~15UL;

      //Encrypt plaintext
      if(aesContext->nr == 10)
      {
         HW_SCE_AES_128GctrEncrypt(aesContext->ek, j, k / 4,
            (const uint32_t *) p, (uint32_t *) c, j);
      }
      else if(aesContext->nr == 12)
      {
         HW_SCE_AES_192GctrEncrypt(aesContext->ek, j, k / 4,
            (const uint32_t *) p, (uint32_t *) c, j);
      }
      else
      {
         HW_SCE_AES_256GctrEncrypt(aesContext->ek, j, k / 4,
            (const uint32_t *) p, (uint32_t *) c, j);
      }

      //Apply GHASH function
      HW_SCE_AES_Ghash(context->m[0], s, k / 4, (const uint32_t *) c, s);

      //Advance data pointer
      p += k;
      c += k;
      n -= k;
   }

   //Process the final block of plaintext
   if(n > 0)
   {
      //Copy partial block
      osMemset(b, 0, 16);
      osMemcpy(b, p, n);

      //Encrypt plaintext
      if(aesContext->nr == 10)
      {
         HW_SCE_AES_128GctrEncrypt(aesContext->ek, j, 4, b, b, j);
      }
      else if(aesContext->nr == 12)
      {
         HW_SCE_AES_192GctrEncrypt(aesContext->ek, j, 4, b, b, j);
      }
      else
      {
         HW_SCE_AES_256GctrEncrypt(aesContext->ek, j, 4, b, b, j);
      }

      //Pad the final ciphertext block with zeroes
      osMemset((uint8_t *) b + n, 0, 16 - n);

      //Apply GHASH function
      HW_SCE_AES_Ghash(context->m[0], s, 4, b, s);

      //Copy partial block
      osMemcpy(c, b, n);
   }

   //Append the 64-bit representation of the length of the AAD and the
   //ciphertext
   m = aLen * 8;
   b[0] = htobe32(m >> 32);
   b[1] = htobe32(m);
   m = length * 8;
   b[2] = htobe32(m >> 32);
   b[3] = htobe32(m);

   //The GHASH function is applied to the result to produce a single output
   //block S
   HW_SCE_AES_Ghash(context->m[0], s, 4, b, s);

   //Let T = MSB(GCTR(J(0), S)
   gcmXorBlock(t, t, (const uint8_t *) s, tLen);

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s7g2CryptoMutex);

   //Successful encryption
   return NO_ERROR;
}


/**
 * @brief Authenticated decryption using GCM
 * @param[in] context Pointer to the GCM context
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @param[in] t Authentication tag
 * @param[in] tLen Length of the authentication tag
 * @return Error code
 **/

error_t gcmDecrypt(GcmContext *context, const uint8_t *iv,
   size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *c,
   uint8_t *p, size_t length, const uint8_t *t, size_t tLen)
{
   uint8_t mask;
   size_t k;
   size_t n;
   uint64_t m;
   uint8_t r[16];
   uint32_t b[4];
   uint32_t j[4];
   uint32_t s[4];
   AesContext *aesContext;

   ///Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The length of the IV shall meet SP 800-38D requirements
   if(ivLen < 1)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Point to the AES context
   aesContext = (AesContext *) context->cipherContext;

   //Check the length of the key
   if(aesContext->nr != 10 && aesContext->nr != 12 && aesContext->nr != 14)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&s7g2CryptoMutex);

   //Check whether the length of the IV is 96 bits
   if(ivLen == 12)
   {
      //When the length of the IV is 96 bits, the padding string is appended
      //to the IV to form the pre-counter block
      j[0] = LOAD32LE(iv);
      j[1] = LOAD32LE(iv + 4);
      j[2] = LOAD32LE(iv + 8);
      j[3] = BETOH32(1);
   }
   else
   {
      //Initialize GHASH calculation
      j[0] = 0;
      j[1] = 0;
      j[2] = 0;
      j[3] = 0;

      //Length of the IV
      n = ivLen;

      //Process the initialization vector
      if(n >= 16)
      {
         //Ensure the size of the incoming data to be processed is a multiple
         //of 16 bytes
         k = n & ~15UL;

         //Apply GHASH function
         HW_SCE_AES_Ghash(context->m[0], j, k / 4, (const uint32_t *) iv, j);

         //Advance data pointer
         iv += k;
         n -= k;
      }

      //Process the final block of the initialization vector
      if(n > 0)
      {
         //Copy partial block
         osMemset(b, 0, 16);
         osMemcpy(b, iv, n);

         //Apply GHASH function
         HW_SCE_AES_Ghash(context->m[0], j, 4, b, j);
      }

      //The string is appended with 64 additional 0 bits, followed by the
      //64-bit representation of the length of the IV
      b[0] = 0;
      b[1] = 0;
      m = ivLen * 8;
      b[2] = htobe32(m >> 32);
      b[3] = htobe32(m);

      //The GHASH function is applied to the resulting string to form the
      //pre-counter block
      HW_SCE_AES_Ghash(context->m[0], j, 4, b, j);
   }

   //Compute CIPH(J(0))
   if(aesContext->nr == 10)
   {
      HW_SCE_AES_128EcbEncrypt(aesContext->ek, 4, j, b);
   }
   else if(aesContext->nr == 12)
   {
      HW_SCE_AES_192EcbEncrypt(aesContext->ek, 4, j, b);
   }
   else
   {
      HW_SCE_AES_256EcbEncrypt(aesContext->ek, 4, j, b);
   }

   //Save MSB(CIPH(J(0)))
   osMemcpy(r, (const uint8_t *) b, tLen);

   //Increment the right-most 32 bits of the counter block. The remaining
   //left-most 96 bits remain unchanged
   j[3] =  htobe32(betoh32(j[3]) + 1);

   //Initialize GHASH calculation
   s[0] = 0;
   s[1] = 0;
   s[2] = 0;
   s[3] = 0;

   //Length of the AAD
   n = aLen;

   //Process AAD
   if(n >= 16)
   {
      //Ensure the size of the incoming data to be processed is a multiple
      //of 16 bytes
      k = n & ~15UL;

      //Apply GHASH function
      HW_SCE_AES_Ghash(context->m[0], s, k / 4, (const uint32_t *) a, s);

      //Advance data pointer
      a += k;
      n -= k;
   }

   //Process the final block of AAD
   if(n > 0)
   {
      //Copy partial block
      osMemset(b, 0, 16);
      osMemcpy(b, a, n);

      //Apply GHASH function
      HW_SCE_AES_Ghash(context->m[0], s, 4, b, s);
   }

   //Length of the ciphertext
   n = length;

   //Process ciphertext
   if(n >= 16)
   {
      //Ensure the size of the incoming data to be processed is a multiple
      //of 16 bytes
      k = n & ~15UL;

      //Apply GHASH function
      HW_SCE_AES_Ghash(context->m[0], s, k / 4, (const uint32_t *) c, s);

      //Decrypt ciphertext
      if(aesContext->nr == 10)
      {
         HW_SCE_AES_128GctrEncrypt(aesContext->ek, j, k / 4,
            (const uint32_t *) c, (uint32_t *) p, j);
      }
      else if(aesContext->nr == 12)
      {
         HW_SCE_AES_192GctrEncrypt(aesContext->ek, j, k / 4,
            (const uint32_t *) c, (uint32_t *) p, j);
      }
      else
      {
         HW_SCE_AES_256GctrEncrypt(aesContext->ek, j, k / 4,
            (const uint32_t *) c, (uint32_t *) p, j);
      }

      //Advance data pointer
      c += k;
      p += k;
      n -= k;
   }

   //Process the final block of ciphertext
   if(n > 0)
   {
      //Copy partial block
      osMemset(b, 0, 16);
      osMemcpy(b, c, n);

      //Apply GHASH function
      HW_SCE_AES_Ghash(context->m[0], s, 4, b, s);

      //Decrypt ciphertext
      if(aesContext->nr == 10)
      {
         HW_SCE_AES_128GctrEncrypt(aesContext->ek, j, 4, b, b, j);
      }
      else if(aesContext->nr == 12)
      {
         HW_SCE_AES_192GctrEncrypt(aesContext->ek, j, 4, b, b, j);
      }
      else
      {
         HW_SCE_AES_256GctrEncrypt(aesContext->ek, j, 4, b, b, j);
      }

      //Copy partial block
      osMemcpy(p, b, n);
   }

   //Append the 64-bit representation of the length of the AAD and the
   //ciphertext
   m = aLen * 8;
   b[0] = htobe32(m >> 32);
   b[1] = htobe32(m);
   m = length * 8;
   b[2] = htobe32(m >> 32);
   b[3] = htobe32(m);

   //The GHASH function is applied to the result to produce a single output
   //block S
   HW_SCE_AES_Ghash(context->m[0], s, 4, b, s);

   //Let R = MSB(GCTR(J(0), S))
   gcmXorBlock(r, r, (const uint8_t *) s, tLen);

   //The calculated tag is bitwise compared to the received tag. The message
   //is authenticated if and only if the tags match
   for(mask = 0, n = 0; n < tLen; n++)
   {
      mask |= r[n] ^ t[n];
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s7g2CryptoMutex);

   //Return status code
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif

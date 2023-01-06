/**
 * @file ra2_crypto_cipher.c
 * @brief RA2 cipher hardware accelerator
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
#include "hw_sce_aes_private.h"
#include "core/crypto.h"
#include "hardware/ra2/ra2_crypto.h"
#include "hardware/ra2/ra2_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "debug.h"

//Check crypto library configuration
#if (RA2_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief Key expansion
 * @param[in] context Pointer to the AES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t aesInit(AesContext *context, const uint8_t *key, size_t keyLen)
{
   fsp_err_t status;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   status = FSP_SUCCESS;

   //Check the length of the key
   if(keyLen == 16)
   {
      //10 rounds are required for 128-bit key
      context->nr = 10;
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
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Encrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void aesEncryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   fsp_err_t status;

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra2CryptoMutex);

   //Check the length of the key
   if(context->nr == 10)
   {
      //Perform AES encryption (128-bit key)
      status = HW_SCE_AES_128EcbEncrypt(context->ek, AES_BLOCK_SIZE / 4,
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
      //192-bit keys are not supported
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status != FSP_SUCCESS)
   {
      osMemset(output, 0, AES_BLOCK_SIZE);
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra2CryptoMutex);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   fsp_err_t status;

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra2CryptoMutex);

   //Check the length of the key
   if(context->nr == 10)
   {
      //Perform AES decryption (128-bit key)
      status = HW_SCE_AES_128EcbDecrypt(context->ek, AES_BLOCK_SIZE / 4,
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
      //192-bit keys are not supported
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status != FSP_SUCCESS)
   {
      osMemset(output, 0, AES_BLOCK_SIZE);
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra2CryptoMutex);
}


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
   fsp_err_t status;

   //Initialize status code
   status = FSP_SUCCESS;

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

         //Acquire exclusive access to the SCE module
         osAcquireMutex(&ra2CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-ECB encryption (128-bit key)
            status = HW_SCE_AES_128EcbEncrypt(aesContext->ek, length / 4,
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
            //192-bit keys are not supported
            status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }

         //Release exclusive access to the SCE module
         osReleaseMutex(&ra2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = FSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
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
         status = FSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   fsp_err_t status;

   //Initialize status code
   status = FSP_SUCCESS;

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

         //Acquire exclusive access to the SCE module
         osAcquireMutex(&ra2CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-ECB decryption (128-bit key)
            status = HW_SCE_AES_128EcbDecrypt(aesContext->ek, length / 4,
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
            //192-bit keys are not supported
            status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }

         //Release exclusive access to the SCE module
         osReleaseMutex(&ra2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = FSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
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
         status = FSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   fsp_err_t status;

   //Initialize status code
   status = FSP_SUCCESS;

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

         //Acquire exclusive access to the SCE module
         osAcquireMutex(&ra2CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-CBC encryption (128-bit key)
            status = HW_SCE_AES_128CbcEncrypt(aesContext->ek,
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
            //192-bit keys are not supported
            status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }

         //Release exclusive access to the SCE module
         osReleaseMutex(&ra2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = FSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
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
         status = FSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   fsp_err_t status;

   //Initialize status code
   status = FSP_SUCCESS;

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

         //Acquire exclusive access to the SCE module
         osAcquireMutex(&ra2CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-CBC decryption (128-bit key)
            status = HW_SCE_AES_128CbcDecrypt(aesContext->ek,
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
            //192-bit keys are not supported
            status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }

         //Release exclusive access to the SCE module
         osReleaseMutex(&ra2CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = FSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }
   else
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
         status = FSP_ERR_CRYPTO_INVALID_SIZE;
      }
   }

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   fsp_err_t status;

   //Initialize status code
   status = FSP_SUCCESS;

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

            //Acquire exclusive access to the SCE module
            osAcquireMutex(&ra2CryptoMutex);

            //Check the length of the key
            if(aesContext->nr == 10)
            {
               //Perform AES-CTR encryption (128-bit key)
               status = HW_SCE_AES_128CtrEncrypt(aesContext->ek,
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
               //192-bit keys are not supported
               status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
            }

            //Release exclusive access to the SCE module
            osReleaseMutex(&ra2CryptoMutex);
         }
         else
         {
            //The length of the payload must be a multiple of the block size
            status = FSP_ERR_CRYPTO_INVALID_SIZE;
         }
      }
      else
      {
         //The value of the parameter is not valid
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }
   else
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
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif

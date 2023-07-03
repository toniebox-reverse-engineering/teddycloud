/**
 * @file lpc55xx_crypto_cipher.c
 * @brief LPC5500 cipher hardware accelerator
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
#include "fsl_hashcrypt.h"
#include "core/crypto.h"
#include "hardware/lpc55xx/lpc55xx_crypto.h"
#include "hardware/lpc55xx/lpc55xx_crypto_cipher.h"
#include "cipher/aes.h"
#include "debug.h"

//Check crypto library configuration
#if (LPC55XX_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief Load AES key
 * @param[in] context AES algorithm context
 * @param[in] handle AES handle
 * @return status code
 **/

status_t aesLoadKey(AesContext *context, hashcrypt_handle_t *handle)
{
   size_t keySize;
   status_t status;

   //Initialize status code
   status = kStatus_Success;

   //Retrieve the length of the key
   if(context->nr == 10)
   {
      //10 rounds are required for 128-bit key
      keySize = 16;
   }
   else if(context->nr == 12)
   {
      //12 rounds are required for 192-bit key
      keySize = 24;
   }
   else if(context->nr == 14)
   {
      //14 rounds are required for 256-bit key
      keySize = 32;
   }
   else
   {
      //Invalid key length
      status = kStatus_Fail;
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Select key type
      handle->keyType = kHASHCRYPT_UserKey;

      //Set AES key
      status = HASHCRYPT_AES_SetKey(HASHCRYPT, handle,
         (const uint8_t *) context->ek, keySize);
   }

   //Return status code
   return status;
}


/**
 * @brief Encrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void aesEncryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   hashcrypt_handle_t handle;

   //Acquire exclusive access to the HASHCRYPT module
   osAcquireMutex(&lpc55xxCryptoMutex);

   //Load AES key
   aesLoadKey(context, &handle);

   //Perform AES encryption
   HASHCRYPT_AES_EncryptEcb(HASHCRYPT, &handle, input, output, AES_BLOCK_SIZE);

   //Release exclusive access to the HASHCRYPT module
   osReleaseMutex(&lpc55xxCryptoMutex);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   hashcrypt_handle_t handle;

   //Acquire exclusive access to the HASHCRYPT module
   osAcquireMutex(&lpc55xxCryptoMutex);

   //Load AES key
   aesLoadKey(context, &handle);

   //Perform AES decryption
   HASHCRYPT_AES_DecryptEcb(HASHCRYPT, &handle, input, output, AES_BLOCK_SIZE);

   //Release exclusive access to the HASHCRYPT module
   osReleaseMutex(&lpc55xxCryptoMutex);
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
   status_t status;

   //Initialize status code
   status = kStatus_Success;

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
         hashcrypt_handle_t handle;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the HASHCRYPT module
         osAcquireMutex(&lpc55xxCryptoMutex);

         //Load AES key
         status = aesLoadKey(context, &handle);

         //Check status code
         if(status == kStatus_Success)
         {
            //Perform AES-ECB encryption
            status = HASHCRYPT_AES_EncryptEcb(HASHCRYPT, &handle, p, c,
               length);
         }

         //Release exclusive access to the HASHCRYPT module
         osReleaseMutex(&lpc55xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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
         status = kStatus_InvalidArgument;
      }
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;

   //Initialize status code
   status = kStatus_Success;

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
         hashcrypt_handle_t handle;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the HASHCRYPT module
         osAcquireMutex(&lpc55xxCryptoMutex);

         //Load AES key
         status = aesLoadKey(context, &handle);

         //Check status code
         if(status == kStatus_Success)
         {
            //Perform AES-ECB decryption
            status = HASHCRYPT_AES_DecryptEcb(HASHCRYPT, &handle, c, p,
               length);
         }

         //Release exclusive access to the HASHCRYPT module
         osReleaseMutex(&lpc55xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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
         status = kStatus_InvalidArgument;
      }
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;

   //Initialize status code
   status = kStatus_Success;

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
         hashcrypt_handle_t handle;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the HASHCRYPT module
         osAcquireMutex(&lpc55xxCryptoMutex);

         //Load AES key
         status = aesLoadKey(context, &handle);

         //Check status code
         if(status == kStatus_Success)
         {
            //Perform AES-CBC encryption
            status = HASHCRYPT_AES_EncryptCbc(HASHCRYPT, &handle, p, c,
               length, iv);
         }

         //Release exclusive access to the HASHCRYPT module
         osReleaseMutex(&lpc55xxCryptoMutex);

         //Check status code
         if(status == kStatus_Success)
         {
            //Update the value of the initialization vector
            osMemcpy(iv, c + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
         }
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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
         status = kStatus_InvalidArgument;
      }
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;

   //Initialize status code
   status = kStatus_Success;

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
         hashcrypt_handle_t handle;
         uint8_t block[AES_BLOCK_SIZE];

         //Point to the AES context
         aesContext = (AesContext *) context;
         
         //Save the last input block
         osMemcpy(block, c + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

         //Acquire exclusive access to the HASHCRYPT module
         osAcquireMutex(&lpc55xxCryptoMutex);

         //Load AES key
         status = aesLoadKey(context, &handle);

         //Check status code
         if(status == kStatus_Success)
         {
            //Perform AES-CBC decryption
            status = HASHCRYPT_AES_DecryptCbc(HASHCRYPT, &handle, c, p,
               length, iv);
         }

         //Release exclusive access to the HASHCRYPT module
         osReleaseMutex(&lpc55xxCryptoMutex);

         //Check status code
         if(status == kStatus_Success)
         {
            //Update the value of the initialization vector
            osMemcpy(iv, block, AES_BLOCK_SIZE);
         }
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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
         status = kStatus_InvalidArgument;
      }
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;

   //Initialize status code
   status = kStatus_Success;

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
            hashcrypt_handle_t handle;

            //Point to the AES context
            aesContext = (AesContext *) context;

            //Acquire exclusive access to the HASHCRYPT module
            osAcquireMutex(&lpc55xxCryptoMutex);

            //Load AES key
            status = aesLoadKey(context, &handle);

            //Check status code
            if(status == kStatus_Success)
            {
               //Perform AES-CTR encryption
               status = HASHCRYPT_AES_CryptCtr(HASHCRYPT, &handle, p, c,
                  length, t, NULL, NULL);
            }

            //Release exclusive access to the HASHCRYPT module
            osReleaseMutex(&lpc55xxCryptoMutex);
         }
         else
         {
            //The length of the payload must be a multiple of the block size
            status = kStatus_InvalidArgument;
         }
      }
      else
      {
         //The value of the parameter is not valid
         status = kStatus_InvalidArgument;
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
         status = kStatus_InvalidArgument;
      }
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif

/**
 * @file mimxrt1160_crypto_cipher.c
 * @brief i.MX RT1160 cipher hardware accelerator
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
#include "fsl_caam.h"
#include "core/crypto.h"
#include "hardware/mimxrt1160/mimxrt1160_crypto.h"
#include "hardware/mimxrt1160/mimxrt1160_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1160_CRYPTO_CIPHER_SUPPORT == ENABLED)

//IAR EWARM compiler?
#if defined(__ICCARM__)

//CAAM input buffer
#pragma data_alignment = 16
uint8_t caamBufferIn[MIMXRT1160_CAAM_BUFFER_SIZE];

//CAAM output buffer
#pragma data_alignment = 16
uint8_t caamBufferOut[MIMXRT1160_CAAM_BUFFER_SIZE];

//CAAM initialization vector
#pragma data_alignment = 16
uint8_t caamInitVector[16];

//ARM or GCC compiler?
#else

//CAAM input buffer
uint8_t caamBufferIn[MIMXRT1160_CAAM_BUFFER_SIZE]
   __attribute__((aligned(16)));

//CAAM output buffer
uint8_t caamBufferOut[MIMXRT1160_CAAM_BUFFER_SIZE]
   __attribute__((aligned(16)));

//CAAM initialization vector
uint8_t caamInitVector[16]
   __attribute__((aligned(16)));

#endif

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

   //Copy the 64-bit key
   context->ks[0] = LOAD32LE(key);
   context->ks[1] = LOAD32LE(key + 4);

   //No error to report
   return NO_ERROR;
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
   status_t status;

   //Initialize status code
   status = kStatus_Success;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         size_t i;
         size_t n;
         DesContext *desContext;
         caam_handle_t caamHandle;

         //Point to the DES context
         desContext = (DesContext *) context;

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1160CryptoMutex);

         //Perform DES-ECB encryption
         for(i = 0; i < length && status == kStatus_Success; i += n)
         {
            //Limit the number of data to process at a time
            n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
            //Copy the plaintext to the buffer
            osMemcpy(caamBufferIn, p + i, n);

            //Encrypt data
            status = CAAM_DES_EncryptEcb(CAAM, &caamHandle, caamBufferIn,
               caamBufferOut, n, (const uint8_t *) desContext->ks);

            //Check status code
            if(status == kStatus_Success)
            {
               //Copy the resulting ciphertext
               osMemcpy(c + i, caamBufferOut, n);
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
      }
   }
   else
#endif
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
         size_t i;
         size_t n;
         Des3Context *des3Context;
         caam_handle_t caamHandle;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1160CryptoMutex);

         //Perform 3DES-CBC encryption
         for(i = 0; i < length && status == kStatus_Success; i += n)
         {
            //Limit the number of data to process at a time
            n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
            //Copy the plaintext to the buffer
            osMemcpy(caamBufferIn, p + i, n);

            //Encrypt data
            status = CAAM_DES3_EncryptEcb(CAAM, &caamHandle, caamBufferIn,
               caamBufferOut, n, (const uint8_t *) des3Context->k1.ks,
               (const uint8_t *) des3Context->k2.ks,
               (const uint8_t *) des3Context->k3.ks);

            //Check status code
            if(status == kStatus_Success)
            {
               //Copy the resulting ciphertext
               osMemcpy(c + i, caamBufferOut, n);
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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
         size_t i;
         size_t n;
         size_t keySize;
         AesContext *aesContext;
         caam_handle_t caamHandle;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Retrieve the length of the key
         if(aesContext->nr == 10)
         {
            //10 rounds are required for 128-bit key
            keySize = 16;
         }
         else if(aesContext->nr == 12)
         {
            //12 rounds are required for 192-bit key
            keySize = 24;
         }
         else if(aesContext->nr == 14)
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
            //Set CAAM job ring
            caamHandle.jobRing = kCAAM_JobRing0;

            //Acquire exclusive access to the CAAM module
            osAcquireMutex(&mimxrt1160CryptoMutex);

            //Perform AES-ECB encryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
               //Copy the plaintext to the buffer
               osMemcpy(caamBufferIn, p + i, n);

               //Encrypt data
               status = CAAM_AES_EncryptEcb(CAAM, &caamHandle, caamBufferIn,
                  caamBufferOut, n, (const uint8_t *) aesContext->ek, keySize);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting ciphertext
                  osMemcpy(c + i, caamBufferOut, n);
               }
            }

            //Release exclusive access to the CAAM module
            osReleaseMutex(&mimxrt1160CryptoMutex);
         }
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         size_t i;
         size_t n;
         DesContext *desContext;
         caam_handle_t caamHandle;

         //Point to the DES context
         desContext = (DesContext *) context;

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1160CryptoMutex);

         //Perform DES-ECB decryption
         for(i = 0; i < length && status == kStatus_Success; i += n)
         {
            //Limit the number of data to process at a time
            n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
            //Copy the ciphertext to the buffer
            osMemcpy(caamBufferIn, c + i, n);

            //Decrypt data
            status = CAAM_DES_DecryptEcb(CAAM, &caamHandle, caamBufferIn,
               caamBufferOut, n, (const uint8_t *) desContext->ks);

            //Check status code
            if(status == kStatus_Success)
            {
               //Copy the resulting plaintext
               osMemcpy(p + i, caamBufferOut, n);
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
      }
   }
   else
#endif
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
         size_t i;
         size_t n;
         Des3Context *des3Context;
         caam_handle_t caamHandle;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1160CryptoMutex);

         //Perform 3DES-ECB decryption
         for(i = 0; i < length && status == kStatus_Success; i += n)
         {
            //Limit the number of data to process at a time
            n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
            //Copy the ciphertext to the buffer
            osMemcpy(caamBufferIn, c + i, n);

            //Decrypt data
            status = CAAM_DES3_DecryptEcb(CAAM, &caamHandle, caamBufferIn,
               caamBufferOut, n, (const uint8_t *) des3Context->k1.ks,
               (const uint8_t *) des3Context->k2.ks,
               (const uint8_t *) des3Context->k3.ks);

            //Check status code
            if(status == kStatus_Success)
            {
               //Copy the resulting plaintext
               osMemcpy(p + i, caamBufferOut, n);
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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
         size_t i;
         size_t n;
         size_t keySize;
         AesContext *aesContext;
         caam_handle_t caamHandle;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Retrieve the length of the key
         if(aesContext->nr == 10)
         {
            //10 rounds are required for 128-bit key
            keySize = 16;
         }
         else if(aesContext->nr == 12)
         {
            //12 rounds are required for 192-bit key
            keySize = 24;
         }
         else if(aesContext->nr == 14)
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
            //Set CAAM job ring
            caamHandle.jobRing = kCAAM_JobRing0;

            //Acquire exclusive access to the CAAM module
            osAcquireMutex(&mimxrt1160CryptoMutex);

            //Perform AES-ECB decryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
               //Copy the ciphertext to the buffer
               osMemcpy(caamBufferIn, c + i, n);

               //Decrypt data
               status = CAAM_AES_DecryptEcb(CAAM, &caamHandle, caamBufferIn,
                  caamBufferOut, n, (const uint8_t *) aesContext->ek, keySize);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting plaintext
                  osMemcpy(p + i, caamBufferOut, n);
               }
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         size_t i;
         size_t n;
         DesContext *desContext;
         caam_handle_t caamHandle;

         //Point to the DES context
         desContext = (DesContext *) context;

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1160CryptoMutex);

         //Perform DES-CBC encryption
         for(i = 0; i < length && status == kStatus_Success; i += n)
         {
            //Limit the number of data to process at a time
            n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
            //Copy the plaintext to the buffer
            osMemcpy(caamBufferIn, p + i, n);

            //Encrypt data
            status = CAAM_DES_EncryptCbc(CAAM, &caamHandle, caamBufferIn,
               caamBufferOut, n, iv, (const uint8_t *) desContext->ks);

            //Check status code
            if(status == kStatus_Success)
            {
               //Copy the resulting ciphertext
               osMemcpy(c + i, caamBufferOut, n);
               //Update the value of the initialization vector
               osMemcpy(iv, caamBufferOut + n - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
      }
   }
   else
#endif
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
         size_t i;
         size_t n;
         Des3Context *des3Context;
         caam_handle_t caamHandle;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1160CryptoMutex);

         //Perform 3DES-CBC encryption
         for(i = 0; i < length && status == kStatus_Success; i += n)
         {
            //Limit the number of data to process at a time
            n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
            //Copy the plaintext to the buffer
            osMemcpy(caamBufferIn, p + i, n);

            //Encrypt data
            status = CAAM_DES3_EncryptCbc(CAAM, &caamHandle, caamBufferIn,
               caamBufferOut, n, iv, (const uint8_t *) des3Context->k1.ks,
               (const uint8_t *) des3Context->k2.ks,
               (const uint8_t *) des3Context->k3.ks);

            //Check status code
            if(status == kStatus_Success)
            {
               //Copy the resulting ciphertext
               osMemcpy(c + i, caamBufferOut, n);
               //Update the value of the initialization vector
               osMemcpy(iv, caamBufferOut + n - DES3_BLOCK_SIZE, DES3_BLOCK_SIZE);
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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
         size_t i;
         size_t n;
         size_t keySize;
         AesContext *aesContext;
         caam_handle_t caamHandle;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Retrieve the length of the key
         if(aesContext->nr == 10)
         {
            //10 rounds are required for 128-bit key
            keySize = 16;
         }
         else if(aesContext->nr == 12)
         {
            //12 rounds are required for 192-bit key
            keySize = 24;
         }
         else if(aesContext->nr == 14)
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
            //Set CAAM job ring
            caamHandle.jobRing = kCAAM_JobRing0;

            //Acquire exclusive access to the CAAM module
            osAcquireMutex(&mimxrt1160CryptoMutex);

            //Perform AES-CBC encryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
               //Copy the plaintext to the buffer
               osMemcpy(caamBufferIn, p + i, n);

               //Encrypt data
               status = CAAM_AES_EncryptCbc(CAAM, &caamHandle, caamBufferIn,
                  caamBufferOut, n, iv, (const uint8_t *) aesContext->ek, keySize);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting ciphertext
                  osMemcpy(c + i, caamBufferOut, n);
                  //Update the value of the initialization vector
                  osMemcpy(iv, caamBufferOut + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
               }
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         size_t i;
         size_t n;
         DesContext *desContext;
         caam_handle_t caamHandle;
         uint8_t block[DES_BLOCK_SIZE];

         //Point to the DES context
         desContext = (DesContext *) context;

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1160CryptoMutex);

         //Perform 3DES-CBC decryption
         for(i = 0; i < length && status == kStatus_Success; i += n)
         {
            //Limit the number of data to process at a time
            n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
            //Copy the ciphertext to the buffer
            osMemcpy(caamBufferIn, c + i, n);
            //Save the last input block
            osMemcpy(block, caamBufferIn + n - DES_BLOCK_SIZE, DES_BLOCK_SIZE);

            //Decrypt data
            status = CAAM_DES_DecryptCbc(CAAM, &caamHandle, caamBufferIn,
               caamBufferOut, n, iv, (const uint8_t *) desContext->ks);

            //Check status code
            if(status == kStatus_Success)
            {
               //Copy the resulting plaintext
               osMemcpy(p + i, caamBufferOut, n);
               //Update the value of the initialization vector
               osMemcpy(iv, block, DES_BLOCK_SIZE);
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
      }
   }
   else
#endif
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
         size_t i;
         size_t n;
         Des3Context *des3Context;
         caam_handle_t caamHandle;
         uint8_t block[DES3_BLOCK_SIZE];

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1160CryptoMutex);

         //Perform 3DES-CBC decryption
         for(i = 0; i < length && status == kStatus_Success; i += n)
         {
            //Limit the number of data to process at a time
            n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
            //Copy the ciphertext to the buffer
            osMemcpy(caamBufferIn, c + i, n);
            //Save the last input block
            osMemcpy(block, caamBufferIn + n - DES3_BLOCK_SIZE, DES3_BLOCK_SIZE);

            //Decrypt data
            status = CAAM_DES3_DecryptCbc(CAAM, &caamHandle, caamBufferIn,
               caamBufferOut, n, iv, (const uint8_t *) des3Context->k1.ks,
               (const uint8_t *) des3Context->k2.ks,
               (const uint8_t *) des3Context->k3.ks);

            //Check status code
            if(status == kStatus_Success)
            {
               //Copy the resulting plaintext
               osMemcpy(p + i, caamBufferOut, n);
               //Update the value of the initialization vector
               osMemcpy(iv, block, DES3_BLOCK_SIZE);
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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
         size_t i;
         size_t n;
         size_t keySize;
         AesContext *aesContext;
         caam_handle_t caamHandle;
         uint8_t block[AES_BLOCK_SIZE];

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Retrieve the length of the key
         if(aesContext->nr == 10)
         {
            //10 rounds are required for 128-bit key
            keySize = 16;
         }
         else if(aesContext->nr == 12)
         {
            //12 rounds are required for 192-bit key
            keySize = 24;
         }
         else if(aesContext->nr == 14)
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
            //Set CAAM job ring
            caamHandle.jobRing = kCAAM_JobRing0;

            //Acquire exclusive access to the CAAM module
            osAcquireMutex(&mimxrt1160CryptoMutex);

            //Perform AES-CBC decryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
               //Copy the ciphertext to the buffer
               osMemcpy(caamBufferIn, c + i, n);
               //Save the last input block
               osMemcpy(block, caamBufferIn + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

               //Decrypt data
               status = CAAM_AES_DecryptCbc(CAAM, &caamHandle, caamBufferIn,
                  caamBufferOut, n, iv, (const uint8_t *) aesContext->ek, keySize);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting plaintext
                  osMemcpy(p + i, caamBufferOut, n);
                  //Update the value of the initialization vector
                  osMemcpy(iv, block, AES_BLOCK_SIZE);
               }
            }
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1160CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
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
            size_t i;
            size_t n;
            size_t keySize;
            AesContext *aesContext;
            caam_handle_t caamHandle;

            //Point to the AES context
            aesContext = (AesContext *) context;

            //Retrieve the length of the key
            if(aesContext->nr == 10)
            {
               //10 rounds are required for 128-bit key
               keySize = 16;
            }
            else if(aesContext->nr == 12)
            {
               //12 rounds are required for 192-bit key
               keySize = 24;
            }
            else if(aesContext->nr == 14)
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
               //Set CAAM job ring
               caamHandle.jobRing = kCAAM_JobRing0;

               //Acquire exclusive access to the CAAM module
               osAcquireMutex(&mimxrt1160CryptoMutex);

               //Perform AES-CTR encryption
               for(i = 0; i < length && status == kStatus_Success; i += n)
               {
                  //Limit the number of data to process at a time
                  n = MIN(length - i, MIMXRT1160_CAAM_BUFFER_SIZE);
                  //Copy the plaintext to the buffer
                  osMemcpy(caamBufferIn, p + i, n);
                  //Copy the counter block
                  osMemcpy(caamInitVector, t, AES_BLOCK_SIZE);

                  //Encrypt data
                  status = CAAM_AES_CryptCtr(CAAM, &caamHandle,
                     caamBufferIn, caamBufferOut, n, caamInitVector,
                     (const uint8_t *) aesContext->ek, keySize, NULL, NULL);

                  //Check status code
                  if(status == kStatus_Success)
                  {
                     //Copy the resulting ciphertext
                     osMemcpy(c + i, caamBufferOut, n);
                     //Update the value of the counter block
                     osMemcpy(t, caamInitVector, AES_BLOCK_SIZE);
                  }
               }
            }

            //Release exclusive access to the CAAM module
            osReleaseMutex(&mimxrt1160CryptoMutex);
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
         status = kStatus_InvalidArgument;
      }
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   //The CRYP module only supports AES cipher algorithm
   if(cipherAlgo != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Save cipher algorithm context
   context->cipherAlgo = cipherAlgo;
   context->cipherContext = cipherContext;

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
   status_t status;
   size_t keySize;
   caam_handle_t caamHandle;
   AesContext *aesContext;

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Initialize status code
   status = kStatus_Success;

   //Point to the AES context
   aesContext = (AesContext *) context->cipherContext;

   //Retrieve the length of the key
   if(aesContext->nr == 10)
   {
      //10 rounds are required for 128-bit key
      keySize = 16;
   }
   else if(aesContext->nr == 12)
   {
      //12 rounds are required for 192-bit key
      keySize = 24;
   }
   else if(aesContext->nr == 14)
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
      //Set CAAM job ring
      caamHandle.jobRing = kCAAM_JobRing0;

      //Acquire exclusive access to the CAAM module
      osAcquireMutex(&mimxrt1160CryptoMutex);

      //Perform AES-GCM encryption
      status = CAAM_AES_EncryptTagGcm(CAAM, &caamHandle, p, c, length, iv,
         ivLen, a, aLen, (const uint8_t *) aesContext->ek, keySize, t, tLen);

      //Release exclusive access to the CAAM module
      osReleaseMutex(&mimxrt1160CryptoMutex);
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;
   size_t keySize;
   caam_handle_t caamHandle;
   AesContext *aesContext;

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Initialize status code
   status = kStatus_Success;

   //Point to the AES context
   aesContext = (AesContext *) context->cipherContext;

   //Retrieve the length of the key
   if(aesContext->nr == 10)
   {
      //10 rounds are required for 128-bit key
      keySize = 16;
   }
   else if(aesContext->nr == 12)
   {
      //12 rounds are required for 192-bit key
      keySize = 24;
   }
   else if(aesContext->nr == 14)
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
      //Set CAAM job ring
      caamHandle.jobRing = kCAAM_JobRing0;

      //Acquire exclusive access to the CAAM module
      osAcquireMutex(&mimxrt1160CryptoMutex);

      //Perform AES-GCM decryption
      status = CAAM_AES_DecryptTagGcm(CAAM, &caamHandle, c, p, length, iv,
         ivLen, a, aLen, (const uint8_t *) aesContext->ek, keySize, t, tLen);

      //Release exclusive access to the CAAM module
      osReleaseMutex(&mimxrt1160CryptoMutex);
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif

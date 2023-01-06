/**
 * @file mimxrt1050_crypto_cipher.c
 * @brief i.MX RT1050 cipher hardware accelerator
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
#include "fsl_dcp.h"
#include "core/crypto.h"
#include "hardware/mimxrt1050/mimxrt1050_crypto.h"
#include "hardware/mimxrt1050/mimxrt1050_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1050_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)

//IAR EWARM compiler?
#if defined(__ICCARM__)

//DCP input buffer
#pragma data_alignment = 16
#pragma location = MIMXRT1050_DCP_RAM_SECTION
static uint8_t dcpBufferIn[MIMXRT1050_DCP_BUFFER_SIZE];

//DCP output buffer
#pragma data_alignment = 16
#pragma location = MIMXRT1050_DCP_RAM_SECTION
static uint8_t dcpBufferOut[MIMXRT1050_DCP_BUFFER_SIZE];

//ARM or GCC compiler?
#else

//DCP input buffer
static uint8_t dcpBufferIn[MIMXRT1050_DCP_BUFFER_SIZE]
   __attribute__((aligned(16), __section__(MIMXRT1050_DCP_RAM_SECTION)));

//DCP output buffer
static uint8_t dcpBufferOut[MIMXRT1050_DCP_BUFFER_SIZE]
   __attribute__((aligned(16), __section__(MIMXRT1050_DCP_RAM_SECTION)));

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
         AesContext *aesContext;
         dcp_handle_t dcpHandle;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Set DCP parameters
            dcpHandle.channel = kDCP_Channel0;
            dcpHandle.keySlot = kDCP_KeySlot0;
            dcpHandle.swapConfig = kDCP_NoSwap;

            //Acquire exclusive access to the DCP module
            osAcquireMutex(&mimxrt1050CryptoMutex);

            //Set the 128-bit key
            status = DCP_AES_SetKey(DCP, &dcpHandle,
               (const uint8_t *) aesContext->ek, 16);

            //Perform AES-ECB encryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1050_DCP_BUFFER_SIZE);
               //Copy the plaintext to the buffer
               osMemcpy(dcpBufferIn, p + i, n);

               //Encrypt data
               status = DCP_AES_EncryptEcb(DCP, &dcpHandle, dcpBufferIn,
                  dcpBufferOut, n);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting ciphertext
                  osMemcpy(c + i, dcpBufferOut, n);
               }
            }

            //Release exclusive access to the DCP module
            osReleaseMutex(&mimxrt1050CryptoMutex);
         }
         else
         {
            //192 and 256-bit keys are not supported
            status = kStatus_Fail;
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
         size_t i;
         size_t n;
         AesContext *aesContext;
         dcp_handle_t dcpHandle;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Set DCP parameters
            dcpHandle.channel = kDCP_Channel0;
            dcpHandle.keySlot = kDCP_KeySlot0;
            dcpHandle.swapConfig = kDCP_NoSwap;

            //Acquire exclusive access to the DCP module
            osAcquireMutex(&mimxrt1050CryptoMutex);

            //Set the 128-bit key
            status = DCP_AES_SetKey(DCP, &dcpHandle,
               (const uint8_t *) aesContext->ek, 16);

            //Perform AES-ECB decryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1050_DCP_BUFFER_SIZE);
               //Copy the ciphertext to the buffer
               osMemcpy(dcpBufferIn, c + i, n);

               //Decrypt data
               status = DCP_AES_DecryptEcb(DCP, &dcpHandle, dcpBufferIn,
                  dcpBufferOut, n);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting plaintext
                  osMemcpy(p + i, dcpBufferOut, n);
               }
            }
         }
         else
         {
            //192 and 256-bit keys are not supported
            status = kStatus_Fail;
         }

         //Release exclusive access to the DCP module
         osReleaseMutex(&mimxrt1050CryptoMutex);
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
         size_t i;
         size_t n;
         AesContext *aesContext;
         dcp_handle_t dcpHandle;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Set DCP parameters
            dcpHandle.channel = kDCP_Channel0;
            dcpHandle.keySlot = kDCP_KeySlot0;
            dcpHandle.swapConfig = kDCP_NoSwap;

            //Acquire exclusive access to the DCP module
            osAcquireMutex(&mimxrt1050CryptoMutex);

            //Set the 128-bit key
            status = DCP_AES_SetKey(DCP, &dcpHandle,
               (const uint8_t *) aesContext->ek, 16);

            //Perform AES-CBC encryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1050_DCP_BUFFER_SIZE);
               //Copy the plaintext to the buffer
               osMemcpy(dcpBufferIn, p + i, n);

               //Encrypt data
               status = DCP_AES_EncryptCbc(DCP, &dcpHandle, dcpBufferIn,
                  dcpBufferOut, n, iv);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting ciphertext
                  osMemcpy(c + i, dcpBufferOut, n);
                  //Update the value of the initialization vector
                  osMemcpy(iv, dcpBufferOut + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
               }
            }
         }
         else
         {
            //192 and 256-bit keys are not supported
            status = kStatus_Fail;
         }

         //Release exclusive access to the DCP module
         osReleaseMutex(&mimxrt1050CryptoMutex);
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
         size_t i;
         size_t n;
         AesContext *aesContext;
         dcp_handle_t dcpHandle;
         uint8_t block[AES_BLOCK_SIZE];

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Set DCP parameters
            dcpHandle.channel = kDCP_Channel0;
            dcpHandle.keySlot = kDCP_KeySlot0;
            dcpHandle.swapConfig = kDCP_NoSwap;

            //Acquire exclusive access to the DCP module
            osAcquireMutex(&mimxrt1050CryptoMutex);

            //Set the 128-bit key
            status = DCP_AES_SetKey(DCP, &dcpHandle,
               (const uint8_t *) aesContext->ek, 16);

            //Perform AES-CBC decryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1050_DCP_BUFFER_SIZE);
               //Copy the ciphertext to the buffer
               osMemcpy(dcpBufferIn, c + i, n);
               //Save the last input block
               osMemcpy(block, dcpBufferIn + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

               //Decrypt data
               status = DCP_AES_DecryptCbc(DCP, &dcpHandle, dcpBufferIn,
                  dcpBufferOut, n, iv);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting plaintext
                  osMemcpy(p + i, dcpBufferOut, n);
                  //Update the value of the initialization vector
                  osMemcpy(iv, block, AES_BLOCK_SIZE);
               }
            }
         }
         else
         {
            //192 and 256-bit keys are not supported
            status = kStatus_Fail;
         }

         //Release exclusive access to the DCP module
         osReleaseMutex(&mimxrt1050CryptoMutex);
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
#endif

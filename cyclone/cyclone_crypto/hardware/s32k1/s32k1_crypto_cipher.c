/**
 * @file s32k1_crypto_cipher.c
 * @brief S32K1 cipher hardware accelerator
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
#include "core/crypto.h"
#include "hardware/s32k1/s32k1_crypto.h"
#include "hardware/s32k1/s32k1_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (S32K1_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief Load AES key
 * @param[in] key 128-bit encryption key
 * @return CSEq error code
 **/

uint32_t aesLoadKey(const uint32_t *key)
{
   //Check for the previous CSEq command to complete
   while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
   {
   }

   //Clear error flags
   FTFC->FSTAT = FTFC_FSTAT_FPVIOL_MASK | FTFC_FSTAT_ACCERR_MASK;

   //Copy the 128-bit key to CSEq RAM
   CSE_PRAM->RAMn[4].DATA_32 = htobe32(key[0]);
   CSE_PRAM->RAMn[5].DATA_32 = htobe32(key[1]);
   CSE_PRAM->RAMn[6].DATA_32 = htobe32(key[2]);
   CSE_PRAM->RAMn[7].DATA_32 = htobe32(key[3]);

   //Start CSEq command
   CSE_PRAM->RAMn[0].DATA_32 = CSEQ_CMD_LOAD_PLAIN_KEY | CSEQ_FORMAT_COPY |
      CSEQ_CALL_SEQ_FIRST;

   //Wait for the CSEq command to complete
   while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
   {
   }

   //Return status code
   return CSE_PRAM->RAMn[1].DATA_32 >> 16;
}


/**
 * @brief Perform AES encryption or decryption
 * @param[in] command CSEq command
 * @param[in] offset CSEq RAM offset
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @return CSEq error code
 **/

uint32_t aesProcessData(uint32_t command, size_t offset, const uint8_t *input,
   uint8_t *output, size_t length)
{
   size_t i;
   size_t j;
   uint32_t temp;
   uint32_t status;

   //Write input data to CSEq RAM
   for(i = offset, j = 0; j < length; i += 4, j += AES_BLOCK_SIZE)
   {
      CSE_PRAM->RAMn[i].DATA_32 = LOAD32BE(input);
      CSE_PRAM->RAMn[i + 1].DATA_32 = LOAD32BE(input + 4);
      CSE_PRAM->RAMn[i + 2].DATA_32 = LOAD32BE(input + 8);
      CSE_PRAM->RAMn[i + 3].DATA_32 = LOAD32BE(input + 12);

      //Next block
      input += AES_BLOCK_SIZE;
   }

   //Start CSEq command
   CSE_PRAM->RAMn[0].DATA_32 = command | CSEQ_FORMAT_COPY | CSEQ_RAM_KEY;

   //Wait for the CSEq command to complete
   while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
   {
   }

   //Retrieve status code
   status = CSE_PRAM->RAMn[1].DATA_32 >> 16;

   //Check status code
   if(status == CSEQ_ERC_NO_ERROR)
   {
      //Read output data from CSEq RAM
      for(i = offset, j = 0; j < length; i += 4, j += AES_BLOCK_SIZE)
      {
         temp = CSE_PRAM->RAMn[i].DATA_32;
         STORE32BE(temp, output);
         temp = CSE_PRAM->RAMn[i + 1].DATA_32;
         STORE32BE(temp, output + 4);
         temp = CSE_PRAM->RAMn[i + 2].DATA_32;
         STORE32BE(temp, output + 8);
         temp = CSE_PRAM->RAMn[i + 3].DATA_32;
         STORE32BE(temp, output + 12);

         //Next block
         output += AES_BLOCK_SIZE;
      }
   }

   //Return status code
   return status;
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
   uint32_t status;

   //Initialize status code
   status = CSEQ_ERC_NO_ERROR;

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
         size_t n;
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Acquire exclusive access to the CSEq module
            osAcquireMutex(&s32k1CryptoMutex);

            //Set encryption key
            status = aesLoadKey(aesContext->ek);

            //Process data blocks
            while(length > 0 && status == CSEQ_ERC_NO_ERROR)
            {
               //Limit the number of data to process at a time
               n = MIN(length, AES_BLOCK_SIZE * 7);

               //Specify the number of data blocks
               CSE_PRAM->RAMn[3].DATA_32 = n / AES_BLOCK_SIZE;

               //Perform AES-ECB encryption
               status = aesProcessData(CSEQ_CMD_ENC_ECB, 4, p, c, n);

               //Next block
               p += n;
               c += n;
               length -= n;
            }

            //Release exclusive access to the CSEq module
            osReleaseMutex(&s32k1CryptoMutex);
         }
         else
         {
            //192 and 256-bit keys are not supported
            status = CSEQ_ERC_KEY_INVALID;
         }
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = CSEQ_ERC_GENERAL_ERROR;
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
         status = CSEQ_ERC_GENERAL_ERROR;
      }
   }

   //Return status code
   return (status == CSEQ_ERC_NO_ERROR) ? NO_ERROR : ERROR_FAILURE;
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
   uint32_t status;

   //Initialize status code
   status = CSEQ_ERC_NO_ERROR;

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
         size_t n;
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Acquire exclusive access to the CSEq module
            osAcquireMutex(&s32k1CryptoMutex);

            //Set encryption key
            status = aesLoadKey(aesContext->ek);

            //Process data blocks
            while(length > 0 && status == CSEQ_ERC_NO_ERROR)
            {
               //Limit the number of data to process at a time
               n = MIN(length, AES_BLOCK_SIZE * 7);

               //Specify the number of data blocks
               CSE_PRAM->RAMn[3].DATA_32 = n / AES_BLOCK_SIZE;

               //Perform AES-ECB decryption
               status = aesProcessData(CSEQ_CMD_DEC_ECB, 4, c, p, n);

               //Next block
               c += n;
               p += n;
               length -= n;
            }

            //Release exclusive access to the CSEq module
            osReleaseMutex(&s32k1CryptoMutex);
         }
         else
         {
            //192 and 256-bit keys are not supported
            status = CSEQ_ERC_KEY_INVALID;
         }
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = CSEQ_ERC_GENERAL_ERROR;
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
         status = CSEQ_ERC_GENERAL_ERROR;
      }
   }

   //Return status code
   return (status == CSEQ_ERC_NO_ERROR) ? NO_ERROR : ERROR_FAILURE;
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
   uint32_t status;

   //Initialize status code
   status = CSEQ_ERC_NO_ERROR;

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
         size_t n;
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Acquire exclusive access to the CSEq module
            osAcquireMutex(&s32k1CryptoMutex);

            //Set encryption key
            status = aesLoadKey(aesContext->ek);

            //Process first data blocks
            if(status == CSEQ_ERC_NO_ERROR)
            {
               //Set initialization vector
               CSE_PRAM->RAMn[4].DATA_32 = LOAD32BE(iv);
               CSE_PRAM->RAMn[5].DATA_32 = LOAD32BE(iv + 4);
               CSE_PRAM->RAMn[6].DATA_32 = LOAD32BE(iv + 8);
               CSE_PRAM->RAMn[7].DATA_32 = LOAD32BE(iv + 12);

               //Specify the number of data blocks
               CSE_PRAM->RAMn[3].DATA_32 = length / AES_BLOCK_SIZE;

               //Limit the number of data to process at a time
               n = MIN(length, AES_BLOCK_SIZE * 6);

               //Perform AES-CBC encryption
               status = aesProcessData(CSEQ_CMD_ENC_CBC | CSEQ_CALL_SEQ_FIRST,
                  8, p, c, n);

               //Check status code
               if(status == CSEQ_ERC_NO_ERROR)
               {
                  //Update the value of the initialization vector
                  osMemcpy(iv, c + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
               }

               //Next block
               p += n;
               c += n;
               length -= n;
            }

            //Process subsequent data blocks
            while(length > 0 && status == CSEQ_ERC_NO_ERROR)
            {
               //Limit the number of data to process at a time
               n = MIN(length, AES_BLOCK_SIZE * 7);

               //Perform AES-CBC encryption
               status = aesProcessData(CSEQ_CMD_ENC_CBC | CSEQ_CALL_SEQ_SUBSEQUENT,
                  4, p, c, n);

               //Check status code
               if(status == CSEQ_ERC_NO_ERROR)
               {
                  //Update the value of the initialization vector
                  osMemcpy(iv, c + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
               }

               //Next block
               p += n;
               c += n;
               length -= n;
            }

            //Release exclusive access to the CSEq module
            osReleaseMutex(&s32k1CryptoMutex);
         }
         else
         {
            //192 and 256-bit keys are not supported
            status = CSEQ_ERC_KEY_INVALID;
         }
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = CSEQ_ERC_GENERAL_ERROR;
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
         status = CSEQ_ERC_GENERAL_ERROR;
      }
   }

   //Return status code
   return (status == CSEQ_ERC_NO_ERROR) ? NO_ERROR : ERROR_FAILURE;
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
   uint32_t status;

   //Initialize status code
   status = CSEQ_ERC_NO_ERROR;

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
         size_t n;
         AesContext *aesContext;
         uint8_t block[AES_BLOCK_SIZE];

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Acquire exclusive access to the CSEq module
            osAcquireMutex(&s32k1CryptoMutex);

            //Set encryption key
            status = aesLoadKey(aesContext->ek);

            //Process first data blocks
            if(status == CSEQ_ERC_NO_ERROR)
            {
               //Set initialization vector
               CSE_PRAM->RAMn[4].DATA_32 = LOAD32BE(iv);
               CSE_PRAM->RAMn[5].DATA_32 = LOAD32BE(iv + 4);
               CSE_PRAM->RAMn[6].DATA_32 = LOAD32BE(iv + 8);
               CSE_PRAM->RAMn[7].DATA_32 = LOAD32BE(iv + 12);

               //Specify the number of data blocks
               CSE_PRAM->RAMn[3].DATA_32 = length / AES_BLOCK_SIZE;

               //Limit the number of data to process at a time
               n = MIN(length, AES_BLOCK_SIZE * 6);
               //Save the last input block
               osMemcpy(block, c + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

               //Perform AES-CBC decryption
               status = aesProcessData(CSEQ_CMD_DEC_CBC | CSEQ_CALL_SEQ_FIRST,
                  8, c, p, n);

               //Check status code
               if(status == CSEQ_ERC_NO_ERROR)
               {
                  //Update the value of the initialization vector
                  osMemcpy(iv, block, AES_BLOCK_SIZE);
               }

               //Next block
               c += n;
               p += n;
               length -= n;
            }

            //Process subsequent data blocks
            while(length > 0 && status == CSEQ_ERC_NO_ERROR)
            {
               //Limit the number of data to process at a time
               n = MIN(length, AES_BLOCK_SIZE * 7);
               //Save the last input block
               osMemcpy(block, c + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

               //Perform AES-CBC decryption
               status = aesProcessData(CSEQ_CMD_DEC_CBC | CSEQ_CALL_SEQ_SUBSEQUENT,
                  4, c, p, n);

               //Check status code
               if(status == CSEQ_ERC_NO_ERROR)
               {
                  //Update the value of the initialization vector
                  osMemcpy(iv, block, AES_BLOCK_SIZE);
               }

               //Next block
               c += n;
               p += n;
               length -= n;
            }

            //Release exclusive access to the CSEq module
            osReleaseMutex(&s32k1CryptoMutex);
         }
         else
         {
            //192 and 256-bit keys are not supported
            status = CSEQ_ERC_KEY_INVALID;
         }
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = CSEQ_ERC_GENERAL_ERROR;
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
         status = CSEQ_ERC_GENERAL_ERROR;
      }
   }

   //Return status code
   return (status == CSEQ_ERC_NO_ERROR) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif

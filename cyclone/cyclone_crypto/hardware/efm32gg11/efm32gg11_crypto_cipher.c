/**
 * @file efm32gg11_crypto_cipher.c
 * @brief EFM32 Giant Gecko 11 cipher hardware accelerator
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
#include "em_device.h"
#include "em_crypto.h"
#include "core/crypto.h"
#include "hardware/efm32gg11/efm32gg11_crypto.h"
#include "hardware/efm32gg11/efm32gg11_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (EFM32GG11_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


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

   //Check the length of the key
   if(keyLen == 16)
   {
      //Copy the 128-bit key
      context->ek[0] = LOAD32LE(key);
      context->ek[1] = LOAD32LE(key + 4);
      context->ek[2] = LOAD32LE(key + 8);
      context->ek[3] = LOAD32LE(key + 12);

      //Generate the decryption key
      AES_DecryptKey128((uint8_t *) context->dk, key);

      //10 rounds are required for 128-bit key
      context->nr = 10;
   }
   else if(keyLen == 32)
   {
      //Copy the 256-bit key
      context->ek[0] = LOAD32LE(key);
      context->ek[1] = LOAD32LE(key + 4);
      context->ek[2] = LOAD32LE(key + 8);
      context->ek[3] = LOAD32LE(key + 12);
      context->ek[4] = LOAD32LE(key + 16);
      context->ek[5] = LOAD32LE(key + 20);
      context->ek[6] = LOAD32LE(key + 24);
      context->ek[7] = LOAD32LE(key + 28);

      //Generate the decryption key
      AES_DecryptKey256((uint8_t *) context->dk, key);

      //14 rounds are required for 256-bit key
      context->nr = 14;
   }
   else
   {
      //192-bit keys are not supported
      return ERROR_INVALID_KEY_LENGTH;
   }

   //Sucessful initialization
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
   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&efm32gg11CryptoMutex);

   //Check the length of the key
   if(context->nr == 10)
   {
      //Perform AES-ECB encryption (128-bit key)
      CRYPTO_AES_ECB128(CRYPTO0, output, input, AES_BLOCK_SIZE,
         (const uint8_t *) context->ek, true);
   }
   else
   {
      //Perform AES-ECB encryption (256-bit key)
      CRYPTO_AES_ECB256(CRYPTO0, output, input, AES_BLOCK_SIZE,
         (const uint8_t *) context->ek, true);
   }

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&efm32gg11CryptoMutex);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&efm32gg11CryptoMutex);

   //Check the length of the key
   if(context->nr == 10)
   {
      //Perform AES-ECB decryption (128-bit key)
      CRYPTO_AES_ECB128(CRYPTO0, output, input, AES_BLOCK_SIZE,
         (const uint8_t *) context->dk, false);
   }
   else
   {
      //Perform AES-ECB decryption (256-bit key)
      CRYPTO_AES_ECB256(CRYPTO0, output, input, AES_BLOCK_SIZE,
         (const uint8_t *) context->dk, false);
   }

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&efm32gg11CryptoMutex);
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
   error_t error;

   //Initialize status code
   error = NO_ERROR;

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

         //Acquire exclusive access to the CRYPTO module
         osAcquireMutex(&efm32gg11CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-ECB encryption (128-bit key)
            CRYPTO_AES_ECB128(CRYPTO0, c, p, length,
               (const uint8_t *) aesContext->ek, true);
         }
         else if(aesContext->nr == 14)
         {
            //Perform AES-ECB encryption (256-bit key)
            CRYPTO_AES_ECB256(CRYPTO0, c, p, length,
               (const uint8_t *) aesContext->ek, true);
         }
         else
         {
            //192-bit keys are not supported
            error = ERROR_INVALID_KEY_LENGTH;
         }

         //Release exclusive access to the CRYPTO module
         osReleaseMutex(&efm32gg11CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
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
   error_t error;

   //Initialize status code
   error = NO_ERROR;

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

         //Acquire exclusive access to the CRYPTO module
         osAcquireMutex(&efm32gg11CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-ECB decryption (128-bit key)
            CRYPTO_AES_ECB128(CRYPTO0, p, c, length,
               (const uint8_t *) aesContext->dk, false);
         }
         else if(aesContext->nr == 14)
         {
            //Perform AES-ECB decryption (256-bit key)
            CRYPTO_AES_ECB256(CRYPTO0, p, c, length,
               (const uint8_t *) aesContext->dk, false);
         }
         else
         {
            //192-bit keys are not supported
            error = ERROR_INVALID_KEY_LENGTH;
         }

         //Release exclusive access to the CRYPTO module
         osReleaseMutex(&efm32gg11CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
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
   error_t error;

   //Initialize status code
   error = NO_ERROR;

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

         //Acquire exclusive access to the CRYPTO module
         osAcquireMutex(&efm32gg11CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-CBC encryption (128-bit key)
            CRYPTO_AES_CBC128(CRYPTO0, c, p, length,
               (const uint8_t *) aesContext->ek, iv, true);
         }
         else if(aesContext->nr == 14)
         {
            //Perform AES-CBC encryption (256-bit key)
            CRYPTO_AES_CBC256(CRYPTO0, c, p, length,
               (const uint8_t *) aesContext->ek, iv, true);
         }
         else
         {
            //192-bit keys are not supported
            error = ERROR_INVALID_KEY_LENGTH;
         }

         //Release exclusive access to the CRYPTO module
         osReleaseMutex(&efm32gg11CryptoMutex);

         //Check status code
         if(!error)
         {
            //Update the value of the initialization vector
            osMemcpy(iv, c + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
         }
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
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
   error_t error;

   //Initialize status code
   error = NO_ERROR;

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
         uint8_t block[AES_BLOCK_SIZE];

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Save the last input block
         osMemcpy(block, c + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

         //Acquire exclusive access to the CRYPTO module
         osAcquireMutex(&efm32gg11CryptoMutex);

         //Check the length of the key
         if(aesContext->nr == 10)
         {
            //Perform AES-CBC decryption (128-bit key)
            CRYPTO_AES_CBC128(CRYPTO0, p, c, length,
               (const uint8_t *) aesContext->dk, iv, false);
         }
         else if(aesContext->nr == 14)
         {
            //Perform AES-CBC decryption (256-bit key)
            CRYPTO_AES_CBC256(CRYPTO0, p, c, length,
               (const uint8_t *) aesContext->dk, iv, false);
         }
         else
         {
            //192-bit keys are not supported
            error = ERROR_INVALID_KEY_LENGTH;
         }

         //Release exclusive access to the CRYPTO module
         osReleaseMutex(&efm32gg11CryptoMutex);

         //Check status code
         if(!error)
         {
            //Update the value of the initialization vector
            osMemcpy(iv, block, AES_BLOCK_SIZE);
         }
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
}

#endif
#if (CFB_SUPPORT == ENABLED)

/**
 * @brief CFB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t cfbEncrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            size_t n;
            AesContext *aesContext;
            uint32_t block[AES_BLOCK_SIZE / 4];

            //Point to the AES context
            aesContext = (AesContext *) context;

            //Get the number of bytes in the last block
            n = length % AES_BLOCK_SIZE;

            //Acquire exclusive access to the CRYPTO module
            osAcquireMutex(&efm32gg11CryptoMutex);

            //Check the length of the key
            if(aesContext->nr == 10)
            {
               //Perform AES-CFB encryption (128-bit key)
               CRYPTO_AES_CFB128(CRYPTO0, c, p, length - n,
                  (const uint8_t *) aesContext->ek, iv, true);
            }
            else if(aesContext->nr == 14)
            {
               //Perform AES-CFB encryption (256-bit key)
               CRYPTO_AES_CFB256(CRYPTO0, c, p, length - n,
                  (const uint8_t *) aesContext->ek, iv, true);
            }
            else
            {
               //192-bit keys are not supported
               error = ERROR_INVALID_KEY_LENGTH;
            }

            //Check status code
            if(!error)
            {
               //The final block requires special processing
               if(n > 0)
               {
                  //Copy the plaintext
                  osMemset(block, 0, AES_BLOCK_SIZE);
                  osMemcpy(block, p + length - n, n);

                  //Encrypt the final block
                  CRYPTO_DataWrite(&CRYPTO0->DATA1, block);
                  CRYPTO_InstructionSequenceExecute(CRYPTO0);
                  CRYPTO_InstructionSequenceWait(CRYPTO0);
                  CRYPTO_DataRead(&CRYPTO0->DATA0, block);

                  //Copy the resulting ciphertext
                  osMemcpy(c + length - n, block, n);
               }
            }

            //Release exclusive access to the CRYPTO module
            osReleaseMutex(&efm32gg11CryptoMutex);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
   {
      //Check the value of the parameter
      if((s % 8) == 0 && s >= 1 && s <= (cipher->blockSize * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Process each plaintext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            cipher->encryptBlock(context, iv, o);

            //Compute C(j) = P(j) XOR MSB(O(j))
            for(i = 0; i < n; i++)
            {
               c[i] = p[i] ^ o[i];
            }

            //Compute I(j+1) = LSB(I(j)) | C(j)
            osMemmove(iv, iv + s, cipher->blockSize - s);
            osMemcpy(iv + cipher->blockSize - s, c, s);

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief CFB decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

error_t cfbDecrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *c, uint8_t *p, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            size_t n;
            AesContext *aesContext;
            uint32_t block[AES_BLOCK_SIZE / 4];

            //Point to the AES context
            aesContext = (AesContext *) context;

            //Get the number of bytes in the last block
            n = length % AES_BLOCK_SIZE;

            //Acquire exclusive access to the CRYPTO module
            osAcquireMutex(&efm32gg11CryptoMutex);

            //Check the length of the key
            if(aesContext->nr == 10)
            {
               //Perform AES-CFB decryption (128-bit key)
               CRYPTO_AES_CFB128(CRYPTO0, p, c, length - n,
                  (const uint8_t *) aesContext->ek, iv, false);
            }
            else if(aesContext->nr == 14)
            {
               //Perform AES-CFB decryption (256-bit key)
               CRYPTO_AES_CFB256(CRYPTO0, p, c, length - n,
                  (const uint8_t *) aesContext->ek, iv, false);
            }
            else
            {
               //192-bit keys are not supported
               error = ERROR_INVALID_KEY_LENGTH;
            }

            //Check status code
            if(!error)
            {
               //The final block requires special processing
               if(n > 0)
               {
                  //Copy the ciphertext
                  osMemset(block, 0, AES_BLOCK_SIZE);
                  osMemcpy(block, c + length - n, n);

                  //Decrypt the final block
                  CRYPTO_DataWrite(&CRYPTO0->DATA1, block);
                  CRYPTO_InstructionSequenceExecute(CRYPTO0);
                  CRYPTO_InstructionSequenceWait(CRYPTO0);
                  CRYPTO_DataRead(&CRYPTO0->DATA0, block);

                  //Copy the resulting plaintext
                  osMemcpy(p + length - n, block, n);
               }
            }

            //Release exclusive access to the CRYPTO module
            osReleaseMutex(&efm32gg11CryptoMutex);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
   {
      //Check the value of the parameter
      if((s % 8) == 0 && s >= 1 && s <= (cipher->blockSize * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Process each ciphertext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            cipher->encryptBlock(context, iv, o);

            //Compute I(j+1) = LSB(I(j)) | C(j)
            osMemmove(iv, iv + s, cipher->blockSize - s);
            osMemcpy(iv + cipher->blockSize - s, c, s);

            //Compute P(j) = C(j) XOR MSB(O(j))
            for(i = 0; i < n; i++)
            {
               p[i] = c[i] ^ o[i];
            }

            //Next block
            c += n;
            p += n;
            length -= n;
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }

   //Return status code
   return error;
}

#endif
#if (OFB_SUPPORT == ENABLED)

/**
 * @brief OFB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t ofbEncrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            size_t n;
            AesContext *aesContext;
            uint32_t block[AES_BLOCK_SIZE / 4];

            //Point to the AES context
            aesContext = (AesContext *) context;

            //Get the number of bytes in the last block
            n = length % AES_BLOCK_SIZE;

            //Acquire exclusive access to the CRYPTO module
            osAcquireMutex(&efm32gg11CryptoMutex);

            //Check the length of the key
            if(aesContext->nr == 10)
            {
               //Perform AES-OFB encryption (128-bit key)
               CRYPTO_AES_OFB128(CRYPTO0, c, p, length - n,
                  (const uint8_t *) aesContext->ek, iv);
            }
            else if(aesContext->nr == 14)
            {
               //Perform AES-OFB encryption (256-bit key)
               CRYPTO_AES_OFB256(CRYPTO0, c, p, length - n,
                  (const uint8_t *) aesContext->ek, iv);
            }
            else
            {
               //192-bit keys are not supported
               error = ERROR_INVALID_KEY_LENGTH;
            }

            //Check status code
            if(!error)
            {
               //The final block requires special processing
               if(n > 0)
               {
                  //Copy the plaintext
                  osMemset(block, 0, AES_BLOCK_SIZE);
                  osMemcpy(block, p + length - n, n);

                  //Encrypt the final block
                  CRYPTO_DataWrite(&CRYPTO0->DATA0, block);
                  CRYPTO_InstructionSequenceExecute(CRYPTO0);
                  CRYPTO_InstructionSequenceWait(CRYPTO0);
                  CRYPTO_DataRead(&CRYPTO0->DATA1, block);

                  //Copy the resulting ciphertext
                  osMemcpy(c + length - n, block, n);
               }
            }

            //Release exclusive access to the CRYPTO module
            osReleaseMutex(&efm32gg11CryptoMutex);
         }
         else
         {
            //No data to process
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
   {
      //Check the value of the parameter
      if((s % 8) == 0 && s >= 1 && s <= (cipher->blockSize * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Process each plaintext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            cipher->encryptBlock(context, iv, o);

            //Compute C(j) = P(j) XOR MSB(O(j))
            for(i = 0; i < n; i++)
            {
               c[i] = p[i] ^ o[i];
            }

            //Compute I(j+1) = LSB(I(j)) | O(j)
            osMemmove(iv, iv + s, cipher->blockSize - s);
            osMemcpy(iv + cipher->blockSize - s, o, s);

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }

   //Return status code
   return error;
}

#endif
#if (CTR_SUPPORT == ENABLED)

/**
 * @brief Increment counter block (CTR mode)
 * @param[in,out] t Pointer to the counter block to be incremented
 **/

void ctrIncCounter(uint8_t *t)
{
   uint_t i;

   //Increment the counter block
   for(i = 0; i < AES_BLOCK_SIZE; i++)
   {
      //Increment the current byte and propagate the carry if necessary
      if(++(t[AES_BLOCK_SIZE - 1 - i]) != 0)
      {
         break;
      }
   }
}


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
   error_t error;

   //Initialize status code
   error = NO_ERROR;

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

            //Acquire exclusive access to the CRYPTO module
            osAcquireMutex(&efm32gg11CryptoMutex);

            //Check the length of the key
            if(aesContext->nr == 10)
            {
               //Perform AES-CTR encryption (128-bit key)
               CRYPTO_AES_CTR128(CRYPTO0, c, p, length,
                  (const uint8_t *) aesContext->ek, t, ctrIncCounter);
            }
            else if(aesContext->nr == 14)
            {
               //Perform AES-CTR encryption (256-bit key)
               CRYPTO_AES_CTR256(CRYPTO0, c, p, length,
                  (const uint8_t *) aesContext->ek, t, ctrIncCounter);
            }
            else
            {
               //192-bit keys are not supported
               error = ERROR_INVALID_KEY_LENGTH;
            }

            //Release exclusive access to the CRYPTO module
            osReleaseMutex(&efm32gg11CryptoMutex);
         }
         else
         {
            //The length of the payload must be a multiple of the block size
            error = ERROR_INVALID_LENGTH;
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
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
         error = ERROR_INVALID_PARAMETER;
      }
   }

   //Return status code
   return error;
}

#endif
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
   const uint32_t pad[4] = {0, 0, 0, 0};

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&efm32gg11CryptoMutex);

   //Set wide arithmetic configuration
   CRYPTO0->WAC = 0;
   CRYPTO0->CTRL = 0;

   //Set CRYPTO module parameters
   CRYPTO_ModulusSet(CRYPTO0, cryptoModulusGcmBin128);
   CRYPTO_MulOperandWidthSet(CRYPTO0, cryptoMulOperand128Bits);
   CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult128Bits);

   //Copy the hash subkey H
   CRYPTO_DataWrite(&CRYPTO0->DDATA1, context->m[0]);
   CRYPTO_DataWrite(&CRYPTO0->DDATA1, pad);

   //Copy the input value
   CRYPTO_DataWrite(&CRYPTO0->DDATA2, (const uint32_t *) x);
   CRYPTO_DataWrite(&CRYPTO0->DDATA2, pad);

   //Perform GF(2^128) multiplication
   CRYPTO_EXECUTE_11(CRYPTO0,
      CRYPTO_CMD_INSTR_SELDDATA1DDATA0,
      CRYPTO_CMD_INSTR_BBSWAP128,
      CRYPTO_CMD_INSTR_DDATA0TODDATA1,
      CRYPTO_CMD_INSTR_SELDDATA2DDATA0,
      CRYPTO_CMD_INSTR_BBSWAP128,
      CRYPTO_CMD_INSTR_DDATA0TODDATA2,
      CRYPTO_CMD_INSTR_SELDDATA0DDATA2,
      CRYPTO_CMD_INSTR_MMUL,
      CRYPTO_CMD_INSTR_DDATA0TODDATA1,
      CRYPTO_CMD_INSTR_SELDDATA1DDATA0,
      CRYPTO_CMD_INSTR_BBSWAP128);

   //Wait for the instruction sequence to complete
   CRYPTO_InstructionSequenceWait(CRYPTO0);

   //Copy the resulting value
   CRYPTO_DataRead(&CRYPTO0->DDATA0, (uint32_t *) x);

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&efm32gg11CryptoMutex);
}

#endif
#endif

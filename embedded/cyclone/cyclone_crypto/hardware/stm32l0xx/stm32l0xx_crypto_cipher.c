/**
 * @file stm32l0xx_crypto_cipher.c
 * @brief STM32L0 cipher hardware accelerator
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
#include "stm32l0xx.h"
#include "stm32l0xx_hal.h"
#include "core/crypto.h"
#include "hardware/stm32l0xx/stm32l0xx_crypto.h"
#include "hardware/stm32l0xx/stm32l0xx_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (STM32L0XX_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief CRYP module initialization
 * @return Error code
 **/

error_t crypInit(void)
{
   //Enable AES peripheral clock
   __HAL_RCC_AES_CLK_ENABLE();

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Perform AES encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode
 **/

void aesProcessData(AesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t mode)
{
   uint32_t temp;

   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32l0xxCryptoMutex);

   //Disable the AES peripheral and clear the CCF flag
   AES->CR = AES_CR_CCFC;

   //Set encryption key
   AES->KEYR3 = context->ek[0];
   AES->KEYR2 = context->ek[1];
   AES->KEYR1 = context->ek[2];
   AES->KEYR0 = context->ek[3];

   //Decryption operation?
   if((mode & AES_CR_MODE) == AES_CR_MODE_DECRYPTION)
   {
      //Select mode 2 by setting to '01' the MODE bitfield of the AES_CR
      temp = AES->CR & ~AES_CR_CHMOD;
      AES->CR = temp | AES_CR_MODE_KEY_DERIVATION;

      //Enable the AES peripheral, by setting the EN bit of the AES_CR register
      AES->CR |= AES_CR_EN;

      //Wait until the CCF flag is set in the AES_SR register
      while((AES->SR & AES_SR_CCF) == 0)
      {
      }

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES->CR |= AES_CR_CCFC;
   }

   //Select the chaining mode
   temp = AES->CR & ~(AES_CR_CHMOD | AES_CR_MODE);
   AES->CR = temp | mode;

   //Configure the data type
   temp = AES->CR & ~AES_CR_DATATYPE;
   AES->CR = temp | AES_CR_DATATYPE_8B;

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      AES->IVR3 = LOAD32BE(iv);
      AES->IVR2 = LOAD32BE(iv + 4);
      AES->IVR1 = LOAD32BE(iv + 8);
      AES->IVR0 = LOAD32BE(iv + 12);
   }

   //Enable the AES by setting the EN bit in the AES_CR register
   AES->CR |= AES_CR_EN;

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //Write four input data words into the AES_DINR register
      AES->DINR = __UNALIGNED_UINT32_READ(input);
      AES->DINR = __UNALIGNED_UINT32_READ(input + 4);
      AES->DINR = __UNALIGNED_UINT32_READ(input + 8);
      AES->DINR = __UNALIGNED_UINT32_READ(input + 12);

      //Wait until the CCF flag is set in the AES_SR register
      while((AES->SR & AES_SR_CCF) == 0)
      {
      }

      //Read four data words from the AES_DOUTR register
      temp = AES->DOUTR;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = AES->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);
      temp = AES->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 8, temp);
      temp = AES->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 12, temp);

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES->CR |= AES_CR_CCFC;

      //Next block
      input += AES_BLOCK_SIZE;
      output += AES_BLOCK_SIZE;
      length -= AES_BLOCK_SIZE;
   }

   //Process final block of data
   if(length > 0)
   {
      uint32_t buffer[4];

      //Copy partial block
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, input, length);

      //Write four input data words into the AES_DINR register
      AES->DINR = buffer[0];
      AES->DINR = buffer[1];
      AES->DINR = buffer[2];
      AES->DINR = buffer[3];

      //Wait until the CCF flag is set in the AES_SR register
      while((AES->SR & AES_SR_CCF) == 0)
      {
      }

      //Read four data words from the AES_DOUTR register
      buffer[0] = AES->DOUTR;
      buffer[1] = AES->DOUTR;
      buffer[2] = AES->DOUTR;
      buffer[3] = AES->DOUTR;

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES->CR |= AES_CR_CCFC;

      //Discard the data that is not part of the payload
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = AES->IVR3;
      STORE32BE(temp, iv);
      temp = AES->IVR2;
      STORE32BE(temp, iv + 4);
      temp = AES->IVR1;
      STORE32BE(temp, iv + 8);
      temp = AES->IVR0;
      STORE32BE(temp, iv + 12);
   }

   //Disable the AES peripheral by clearing the EN bit of the AES_CR register
   AES->CR = 0;

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32l0xxCryptoMutex);
}


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
   if(keyLen != 16)
      return ERROR_INVALID_KEY_LENGTH;

   //10 rounds are required for 128-bit key
   context->nr = 10;

   //Copy the original key
   context->ek[0] = LOAD32BE(key);
   context->ek[1] = LOAD32BE(key + 4);
   context->ek[2] = LOAD32BE(key + 8);
   context->ek[3] = LOAD32BE(key + 12);

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
   //Perform AES encryption
   aesProcessData(context, NULL, input, output, AES_BLOCK_SIZE,
      AES_CR_CHMOD_ECB | AES_CR_MODE_ENCRYPTION);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   //Perform AES decryption
   aesProcessData(context, NULL, input, output, AES_BLOCK_SIZE,
      AES_CR_CHMOD_ECB | AES_CR_MODE_DECRYPTION);
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
         //Encrypt payload data
         aesProcessData(context, NULL, p, c, length, AES_CR_CHMOD_ECB |
            AES_CR_MODE_ENCRYPTION);
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
         //Decrypt payload data
         aesProcessData(context, NULL, c, p, length, AES_CR_CHMOD_ECB |
            AES_CR_MODE_DECRYPTION);
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
         //Encrypt payload data
         aesProcessData(context, iv, p, c, length, AES_CR_CHMOD_CBC |
            AES_CR_MODE_ENCRYPTION);
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
         //Decrypt payload data
         aesProcessData(context, iv, c, p, length, AES_CR_CHMOD_CBC |
            AES_CR_MODE_DECRYPTION);
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
         if(length > 0)
         {
            //Encrypt payload data
            aesProcessData(context, t, p, c, length, AES_CR_CHMOD_CTR |
               AES_CR_MODE_ENCRYPTION);
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
#endif

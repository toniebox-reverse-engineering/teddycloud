/**
 * @file stm32wbxx_crypto_cipher.c
 * @brief STM32WB cipher hardware accelerator
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
#include "stm32wbxx.h"
#include "stm32wbxx_hal.h"
#include "core/crypto.h"
#include "hardware/stm32wbxx/stm32wbxx_crypto.h"
#include "hardware/stm32wbxx/stm32wbxx_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (STM32WBXX_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief CRYP module initialization
 * @return Error code
 **/

error_t crypInit(void)
{
   //Enable AES peripheral clock
   __HAL_RCC_AES1_CLK_ENABLE();

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Load AES key
 * @param[in] context AES algorithm context
 **/

void aesLoadKey(AesContext *context)
{
   uint32_t temp;

   //Read control register
   temp = AES1->CR & ~AES_CR_KEYSIZE;

   //Check the length of the key
   if(context->nr == 10)
   {
      //10 rounds are required for 128-bit key
      AES1->CR = temp | AES_CR_KEYSIZE_128B;

      //Set the 128-bit encryption key
      AES1->KEYR3 = context->ek[0];
      AES1->KEYR2 = context->ek[1];
      AES1->KEYR1 = context->ek[2];
      AES1->KEYR0 = context->ek[3];
   }
   else
   {
      //14 rounds are required for 256-bit key
      AES1->CR = temp | AES_CR_KEYSIZE_256B;

      //Set the 256-bit encryption key
      AES1->KEYR7 = context->ek[0];
      AES1->KEYR6 = context->ek[1];
      AES1->KEYR5 = context->ek[2];
      AES1->KEYR4 = context->ek[3];
      AES1->KEYR3 = context->ek[4];
      AES1->KEYR2 = context->ek[5];
      AES1->KEYR1 = context->ek[6];
      AES1->KEYR0 = context->ek[7];
   }
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
   osAcquireMutex(&stm32wbxxCryptoMutex);

   //Disable the AES peripheral and clear the CCF flag
   AES1->CR = AES_CR_CCFC;

   //Set encryption key
   aesLoadKey(context);

   //Decryption operation?
   if((mode & AES_CR_MODE) == AES_CR_MODE_DECRYPTION)
   {
      //Select mode 2 by setting to '01' the MODE bitfield of the AES_CR
      temp = AES1->CR & ~AES_CR_CHMOD;
      AES1->CR = temp | AES_CR_MODE_KEY_DERIVATION;

      //Enable the AES peripheral, by setting the EN bit of the AES_CR register
      AES1->CR |= AES_CR_EN;

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;
   }

   //Select the chaining mode
   temp = AES1->CR & ~(AES_CR_CHMOD | AES_CR_MODE);
   AES1->CR = temp | mode;

   //Configure the data type
   temp = AES1->CR & ~AES_CR_DATATYPE;
   AES1->CR = temp | AES_CR_DATATYPE_8B;

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      AES1->IVR3 = LOAD32BE(iv);
      AES1->IVR2 = LOAD32BE(iv + 4);
      AES1->IVR1 = LOAD32BE(iv + 8);
      AES1->IVR0 = LOAD32BE(iv + 12);
   }

   //Enable the AES by setting the EN bit in the AES_CR register
   AES1->CR |= AES_CR_EN;

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //Write four input data words into the AES_DINR register
      AES1->DINR = __UNALIGNED_UINT32_READ(input);
      AES1->DINR = __UNALIGNED_UINT32_READ(input + 4);
      AES1->DINR = __UNALIGNED_UINT32_READ(input + 8);
      AES1->DINR = __UNALIGNED_UINT32_READ(input + 12);

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Read four data words from the AES_DOUTR register
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 8, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 12, temp);

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;

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
      AES1->DINR = buffer[0];
      AES1->DINR = buffer[1];
      AES1->DINR = buffer[2];
      AES1->DINR = buffer[3];

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Read four data words from the AES_DOUTR register
      buffer[0] = AES1->DOUTR;
      buffer[1] = AES1->DOUTR;
      buffer[2] = AES1->DOUTR;
      buffer[3] = AES1->DOUTR;

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;

      //Discard the data that is not part of the payload
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = AES1->IVR3;
      STORE32BE(temp, iv);
      temp = AES1->IVR2;
      STORE32BE(temp, iv + 4);
      temp = AES1->IVR1;
      STORE32BE(temp, iv + 8);
      temp = AES1->IVR0;
      STORE32BE(temp, iv + 12);
   }

   //Disable the AES peripheral by clearing the EN bit of the AES_CR register
   AES1->CR = 0;

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32wbxxCryptoMutex);
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
   size_t i;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the key
   if(keyLen == 16)
   {
      //10 rounds are required for 128-bit key
      context->nr = 10;
   }
   else if(keyLen == 32)
   {
      //14 rounds are required for 256-bit key
      context->nr = 14;
   }
   else
   {
      //192-bit keys are not supported
      return ERROR_INVALID_KEY_LENGTH;
   }

   //Determine the number of 32-bit words in the key
   keyLen /= 4;

   //Copy the original key
   for(i = 0; i < keyLen; i++)
   {
      context->ek[i] = LOAD32BE(key + (i * 4));
   }

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
#if (GCM_SUPPORT == ENABLED)

/**
 * @brief Perform AES-GCM encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in] iv Initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[out] t Authentication tag
 * @param[in] mode Operation mode
 **/

void gcmProcessData(AesContext *context, const uint8_t *iv,
   const uint8_t *a, size_t aLen, const uint8_t *input, uint8_t *output,
   size_t length, uint8_t *t, uint32_t mode)
{
   size_t n;
   uint64_t m;
   uint32_t temp;
   uint32_t buffer[4];

   //Acquire exclusive access to the AES module
   osAcquireMutex(&stm32wbxxCryptoMutex);

   //Disable the AES peripheral and clear the CCF flag
   AES1->CR = AES_CR_CCFC;

   //Select GCM chaining mode, by setting to '011' the CHMOD bitfield of the
   //AES_CR register
   temp = AES1->CR & ~AES_CR_CHMOD;
   AES1->CR = temp | AES_CR_CHMOD_GCM_GMAC;

   //Set to '00' (no data swapping) the DATATYPE bitfield
   temp = AES1->CR & ~AES_CR_DATATYPE;
   AES1->CR = temp | AES_CR_DATATYPE_32B;

   //Indicate the Init phase, by setting to '00' the GCMPH bitfield of the
   //AES_CR register
   temp = AES1->CR & ~AES_CR_GCMPH;
   AES1->CR = temp | AES_CR_GCMPH_INIT;

   //Set the MODE bitfield of the AES_CR register to '00' or '10'
   temp = AES1->CR & ~AES_CR_MODE;
   AES1->CR = temp | mode;

   //Set encryption key
   aesLoadKey(context);

   //Set initialization vector
   AES1->IVR3 = LOAD32BE(iv);
   AES1->IVR2 = LOAD32BE(iv + 4);
   AES1->IVR1 = LOAD32BE(iv + 8);
   AES1->IVR0 = 2;

   //Start the calculation of the hash key, by setting to 1 the EN bit of the
   //AES_CR register
   AES1->CR |= AES_CR_EN;

   //Wait until the end of computation, indicated by the CCF flag of the AES_SR
   //transiting to 1
   while((AES1->SR & AES_SR_CCF) == 0)
   {
   }

   //Clear the CCF flag of the AES_SR register, by setting to 1 the CCFC bit
   //of the AES_CR register
   AES1->CR |= AES_CR_CCFC;

   //Configure the data type
   temp = AES1->CR & ~AES_CR_DATATYPE;
   AES1->CR = temp | AES_CR_DATATYPE_8B;

   //Indicate the Header phase, by setting to '01' the GCMPH bitfield of the
   //AES_CR register
   temp = AES1->CR & ~AES_CR_GCMPH;
   AES1->CR = temp | AES_CR_GCMPH_HEADER;

   //Enable the AES peripheral by setting the EN bit of the AES_CR register
   AES1->CR |= AES_CR_EN;

   //Process additional authenticated data
   for(n = aLen; n >= AES_BLOCK_SIZE; n -= AES_BLOCK_SIZE)
   {
      //Write four input data words into the AES_DINR register
      AES1->DINR = __UNALIGNED_UINT32_READ(a);
      AES1->DINR = __UNALIGNED_UINT32_READ(a + 4);
      AES1->DINR = __UNALIGNED_UINT32_READ(a + 8);
      AES1->DINR = __UNALIGNED_UINT32_READ(a + 12);

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;

      //Next block
      a += AES_BLOCK_SIZE;
   }

   //Process final block of additional authenticated data
   if(n > 0)
   {
      //If the AAD size in the last block is inferior to 128 bits, pad the
      //remainder of the block with zeros
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, a, n);

      //Write four input data words into the AES_DINR register
      AES1->DINR = buffer[0];
      AES1->DINR = buffer[1];
      AES1->DINR = buffer[2];
      AES1->DINR = buffer[3];

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;
   }

   //Indicate the Payload phase, by setting to '10' the GCMPH bitfield of the
   //AES_CR register
   temp = AES1->CR & ~AES_CR_GCMPH;
   AES1->CR = temp | AES_CR_GCMPH_PAYLOAD;

   //Process data
   for(n = length; n >= AES_BLOCK_SIZE; n -= AES_BLOCK_SIZE)
   {
      //Write four input data words into the AES_DINR register
      AES1->DINR = __UNALIGNED_UINT32_READ(input);
      AES1->DINR = __UNALIGNED_UINT32_READ(input + 4);
      AES1->DINR = __UNALIGNED_UINT32_READ(input + 8);
      AES1->DINR = __UNALIGNED_UINT32_READ(input + 12);

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Read four data words from the AES_DOUTR register
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 8, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 12, temp);

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;

      //Next block
      input += AES_BLOCK_SIZE;
      output += AES_BLOCK_SIZE;
   }

   //Process final block of data
   if(n > 0)
   {
      //If it is the last block and the plaintext (encryption) or ciphertext
      //(decryption) size in the block is inferior to 128 bits, pad the
      //remainder of the block with zeros
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, input, n);

      //Specify the number of padding bytes in the last block
      temp = AES1->CR & ~AES_CR_NPBLB;
      AES1->CR = temp | ((AES_BLOCK_SIZE - n) << AES_CR_NPBLB_Pos);

      //Write four input data words into the AES_DINR register
      AES1->DINR = buffer[0];
      AES1->DINR = buffer[1];
      AES1->DINR = buffer[2];
      AES1->DINR = buffer[3];

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Read four data words from the AES_DOUTR register
      buffer[0] = AES1->DOUTR;
      buffer[1] = AES1->DOUTR;
      buffer[2] = AES1->DOUTR;
      buffer[3] = AES1->DOUTR;

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;

      //Discard the bits that are not part of the payload when the last block
      //size is less than 16 bytes
      osMemcpy(output, buffer, n);
   }

   //Indicate the Final phase, by setting to '11' the GCMPH bitfield of the
   //AES_CR register
   temp = AES1->CR & ~AES_CR_GCMPH;
   AES1->CR = temp | AES_CR_GCMPH_FINAL;

   //Select encrypt mode by setting to '00' the MODE bitfield of the AES_CR
   //register
   temp = AES1->CR & ~AES_CR_MODE;
   AES1->CR = temp | AES_CR_MODE_ENCRYPTION;

   //Compose the data of the block, by concatenating the AAD bit length and
   //the payload bit length. Write the block into the AES_DINR register
   m = aLen * 8;
   AES1->DINR = htole32(m >> 32);
   AES1->DINR = htole32(m);
   m = length * 8;
   AES1->DINR = htole32(m >> 32);
   AES1->DINR = htole32(m);

   //Wait until the end of computation, indicated by the CCF flag of the AES_SR
   //transiting to 1
   while((AES1->SR & AES_SR_CCF) == 0)
   {
   }

   //Get the GCM authentication tag, by reading the AES_DOUTR register four
   //times
   temp = AES1->DOUTR;
   __UNALIGNED_UINT32_WRITE(t, temp);
   temp = AES1->DOUTR;
   __UNALIGNED_UINT32_WRITE(t + 4, temp);
   temp = AES1->DOUTR;
   __UNALIGNED_UINT32_WRITE(t + 8, temp);
   temp = AES1->DOUTR;
   __UNALIGNED_UINT32_WRITE(t + 12, temp);

   //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
   AES1->CR |= AES_CR_CCFC;

   //Disable the AES peripheral by clearing the EN bit of the AES_CR register
   AES1->CR = 0;

   //Release exclusive access to the AES module
   osReleaseMutex(&stm32wbxxCryptoMutex);
}


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
   uint8_t authTag[16];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen != 12)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Perform AES-GCM encryption
   gcmProcessData(context->cipherContext, iv, a, aLen, p, c, length,
      authTag, AES_CR_MODE_ENCRYPTION);

   //Copy the resulting authentication tag
   osMemcpy(t, authTag, tLen);

   //Successful processing
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
   size_t i;
   uint8_t mask;
   uint8_t authTag[16];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen != 12)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Perform AES-GCM decryption
   gcmProcessData(context->cipherContext, iv, a, aLen, c, p, length,
      authTag, AES_CR_MODE_DECRYPTION);

   //The calculated tag is bitwise compared to the received tag
   for(mask = 0, i = 0; i < tLen; i++)
   {
      mask |= authTag[i] ^ t[i];
   }

   //The message is authenticated if and only if the tags match
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#if (CCM_SUPPORT == ENABLED)

/**
 * @brief Perform AES-CCM encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in] b0 Pointer to the B0 block
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[out] t Authentication tag
 * @param[in] mode Operation mode
 **/

void ccmProcessData(AesContext *context, const uint8_t *b0, const uint8_t *a,
   size_t aLen, const uint8_t *input, uint8_t *output, size_t length,
   uint8_t *t, uint32_t mode)
{
   size_t n;
   uint32_t temp;
   uint8_t buffer[16];

   //Acquire exclusive access to the AES module
   osAcquireMutex(&stm32wbxxCryptoMutex);

   //Disable the AES peripheral and clear the CCF flag
   AES1->CR = AES_CR_CCFC;

   //Select CCM chaining mode, by setting to '100' the CHMOD bitfield of the
   //AES_CR register
   temp = AES1->CR & ~AES_CR_CHMOD;
   AES1->CR = temp | AES_CR_CHMOD_CCM;

   //Configure the data type
   temp = AES1->CR & ~AES_CR_DATATYPE;
   AES1->CR = temp | AES_CR_DATATYPE_8B;

   //Indicate the Init phase, by setting to '00' the GCMPH bitfield of the
   //AES_CR register
   temp = AES1->CR & ~AES_CR_GCMPH;
   AES1->CR = temp | AES_CR_GCMPH_INIT;

   //Set the MODE bitfield of the AES_CR register to '00' or '10'. Although
   //the bitfield is only used in payload phase, it is recommended to set it
   //in the Init phase and keep it unchanged in all subsequent phases
   temp = AES1->CR & ~AES_CR_MODE;
   AES1->CR = temp | mode;

   //Set encryption key
   aesLoadKey(context);

   //Initialize AES_IVRx registers with B0 data
   AES1->IVR3 = LOAD32BE(b0);
   AES1->IVR2 = LOAD32BE(b0 + 4);
   AES1->IVR1 = LOAD32BE(b0 + 8);
   AES1->IVR0 = LOAD32BE(b0 + 12);

   //Start the calculation of the counter, by setting to 1 the EN bit of the
   //AES_CR register
   AES1->CR |= AES_CR_EN;

   //Wait until the end of computation, indicated by the CCF flag of the AES_SR
   //transiting to 1
   while((AES1->SR & AES_SR_CCF) == 0)
   {
   }

   //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
   AES1->CR |= AES_CR_CCFC;

   //Indicate the Header phase, by setting to '01' the GCMPH bitfield of
   //the AES_CR register
   temp = AES1->CR & ~AES_CR_GCMPH;
   AES1->CR = temp | AES_CR_GCMPH_HEADER;

   //Enable the AES peripheral by setting the EN bit of the AES_CR register
   AES1->CR |= AES_CR_EN;

   //The header phase can be skipped if there is no associated data
   if(aLen > 0)
   {
      //The first block of the associated data (B1) must be formatted by
      //software, with the associated data length
      osMemset(buffer, 0, 16);

      //Check the length of the associated data string
      if(aLen < 0xFF00)
      {
         //The length is encoded as 2 octets
         STORE16BE(aLen, buffer);

         //Number of bytes to copy
         n = MIN(aLen, 16 - 2);
         //Concatenate the associated data A
         osMemcpy(buffer + 2, a, n);
      }
      else
      {
         //The length is encoded as 6 octets
         buffer[0] = 0xFF;
         buffer[1] = 0xFE;

         //MSB is stored first
         STORE32BE(aLen, buffer + 2);

         //Number of bytes to copy
         n = MIN(aLen, 16 - 6);
         //Concatenate the associated data A
         osMemcpy(buffer + 6, a, n);
      }

      //Write four input data words into the AES_DINR register
      AES1->DINR = LOAD32LE(buffer);
      AES1->DINR = LOAD32LE(buffer + 4);
      AES1->DINR = LOAD32LE(buffer + 8);
      AES1->DINR = LOAD32LE(buffer + 12);

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;

      //Number of remaining data bytes
      aLen -= n;
      a += n;
   }

   //Process additional authenticated data
   while(aLen >= AES_BLOCK_SIZE)
   {
      //Write four input data words into the AES_DINR register
      AES1->DINR = __UNALIGNED_UINT32_READ(a);
      AES1->DINR = __UNALIGNED_UINT32_READ(a + 4);
      AES1->DINR = __UNALIGNED_UINT32_READ(a + 8);
      AES1->DINR = __UNALIGNED_UINT32_READ(a + 12);

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;

      //Next block
      a += AES_BLOCK_SIZE;
      aLen -= AES_BLOCK_SIZE;
   }

   //Process final block of additional authenticated data
   if(aLen > 0)
   {
      //If the AAD size in the last block is inferior to 128 bits, pad the
      //remainder of the block with zeros
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, a, aLen);

      //Write four input data words into the AES_DINR register
      AES1->DINR = __UNALIGNED_UINT32_READ(buffer);
      AES1->DINR = __UNALIGNED_UINT32_READ(buffer + 4);
      AES1->DINR = __UNALIGNED_UINT32_READ(buffer + 8);
      AES1->DINR = __UNALIGNED_UINT32_READ(buffer + 12);

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;
   }

   //Indicate the Payload phase, by setting to '10' the GCMPH bitfield of the
   //AES_CR register
   temp = AES1->CR & ~AES_CR_GCMPH;
   AES1->CR = temp | AES_CR_GCMPH_PAYLOAD;

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //Write four input data words into the AES_DINR register
      AES1->DINR = __UNALIGNED_UINT32_READ(input);
      AES1->DINR = __UNALIGNED_UINT32_READ(input + 4);
      AES1->DINR = __UNALIGNED_UINT32_READ(input + 8);
      AES1->DINR = __UNALIGNED_UINT32_READ(input + 12);

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Read four data words from the AES_DOUTR register
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 8, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(output + 12, temp);

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;

      //Next block
      input += AES_BLOCK_SIZE;
      output += AES_BLOCK_SIZE;
      length -= AES_BLOCK_SIZE;
   }

   //Process final block of data
   if(length > 0)
   {
      //If it is the last block and the plaintext (encryption) or ciphertext
      //(decryption) size in the block is inferior to 128 bits, pad the
      //remainder of the block with zeros
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, input, length);

      //Decryption operation?
      if((mode & AES_CR_MODE) == AES_CR_MODE_DECRYPTION)
      {
         //Specify the number of padding bytes in the last block
         temp = AES1->CR & ~AES_CR_NPBLB;
         AES1->CR = temp | ((AES_BLOCK_SIZE - length) << AES_CR_NPBLB_Pos);
      }

      //Write four input data words into the AES_DINR register
      AES1->DINR = __UNALIGNED_UINT32_READ(buffer);
      AES1->DINR = __UNALIGNED_UINT32_READ(buffer + 4);
      AES1->DINR = __UNALIGNED_UINT32_READ(buffer + 8);
      AES1->DINR = __UNALIGNED_UINT32_READ(buffer + 12);

      //Wait until the CCF flag is set in the AES_SR register
      while((AES1->SR & AES_SR_CCF) == 0)
      {
      }

      //Read four data words from the AES_DOUTR register
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(buffer, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(buffer + 4, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(buffer + 8, temp);
      temp = AES1->DOUTR;
      __UNALIGNED_UINT32_WRITE(buffer + 12, temp);

      //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
      AES1->CR |= AES_CR_CCFC;

      //Discard the bits that are not part of the payload when the last block
      //size is less than 16 bytes
      osMemcpy(output, buffer, length);
   }

   //Indicate the Final phase, by setting to '11' the GCMPH bitfield of the
   //AES_CR register
   temp = AES1->CR & ~AES_CR_GCMPH;
   AES1->CR = temp | AES_CR_GCMPH_FINAL;

   //Wait until the end of computation, indicated by the CCF flag of the AES_SR
   //transiting to 1
   while((AES1->SR & AES_SR_CCF) == 0)
   {
   }

   //Get the CCM authentication tag, by reading the AES_DOUTR register four
   //times
   temp = AES1->DOUTR;
   __UNALIGNED_UINT32_WRITE(t, temp);
   temp = AES1->DOUTR;
   __UNALIGNED_UINT32_WRITE(t + 4, temp);
   temp = AES1->DOUTR;
   __UNALIGNED_UINT32_WRITE(t + 8, temp);
   temp = AES1->DOUTR;
   __UNALIGNED_UINT32_WRITE(t + 12, temp);

   //Clear the CCF flag, by setting the CCFC bit of the AES_CR register
   AES1->CR |= AES_CR_CCFC;

   //Disable the AES peripheral by clearing the EN bit of the AES_CR register
   AES1->CR = 0;

   //Release exclusive access to the AES module
   osReleaseMutex(&stm32wbxxCryptoMutex);
}


/**
 * @brief Authenticated encryption using CCM
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] n Nonce
 * @param[in] nLen Length of the nonce
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @param[out] t MAC resulting from the encryption process
 * @param[in] tLen Length of the MAC
 * @return Error code
 **/

error_t ccmEncrypt(const CipherAlgo *cipher, void *context, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *p, uint8_t *c,
   size_t length, uint8_t *t, size_t tLen)
{
   size_t i;
   size_t q;
   size_t qLen;
   uint8_t b0[16];
   uint8_t authTag[16];

   //Check parameters
   if(cipher == NULL || context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The CRYP module only supports AES cipher algorithm
   if(cipher != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the nonce
   if(nLen < 7 || nLen > 13)
      return ERROR_INVALID_LENGTH;

   //Check the length of the MAC
   if(tLen < 4 || tLen > 16 || (tLen % 2) != 0)
      return ERROR_INVALID_LENGTH;

   //Q is the bit string representation of the octet length of P
   q = length;
   //Compute the octet length of Q
   qLen = 15 - nLen;

   //Format the leading octet of the first block (B0)
   b0[0] = (aLen > 0) ? 0x40 : 0x00;
   //Encode the octet length of T
   b0[0] |= ((tLen - 2) / 2) << 3;
   //Encode the octet length of Q
   b0[0] |= qLen - 1;

   //Copy the nonce
   osMemcpy(b0 + 1, n, nLen);

   //Encode the length field Q
   for(i = 0; i < qLen; i++, q >>= 8)
   {
      b0[15 - i] = q & 0xFF;
   }

   //Invalid length?
   if(q != 0)
      return ERROR_INVALID_LENGTH;

   //Perform AES-CCM encryption
   ccmProcessData(context, b0, a, aLen, p, c, length, authTag,
      AES_CR_MODE_ENCRYPTION);

   //Copy the resulting authentication tag
   osMemcpy(t, authTag, tLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Authenticated decryption using CCM
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] n Nonce
 * @param[in] nLen Length of the nonce
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @param[in] t MAC to be verified
 * @param[in] tLen Length of the MAC
 * @return Error code
 **/

error_t ccmDecrypt(const CipherAlgo *cipher, void *context, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *c, uint8_t *p,
   size_t length, const uint8_t *t, size_t tLen)
{
   size_t i;
   size_t q;
   size_t qLen;
   uint8_t mask;
   uint8_t b0[16];
   uint8_t authTag[16];

   //Check parameters
   if(cipher == NULL || context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The CRYP module only supports AES cipher algorithm
   if(cipher != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the nonce
   if(nLen < 7 || nLen > 13)
      return ERROR_INVALID_LENGTH;

   //Check the length of the MAC
   if(tLen < 4 || tLen > 16 || (tLen % 2) != 0)
      return ERROR_INVALID_LENGTH;

   //Q is the bit string representation of the octet length of C
   q = length;
   //Compute the octet length of Q
   qLen = 15 - nLen;

   //Format the leading octet of the first block (B0)
   b0[0] = (aLen > 0) ? 0x40 : 0x00;
   //Encode the octet length of T
   b0[0] |= ((tLen - 2) / 2) << 3;
   //Encode the octet length of Q
   b0[0] |= qLen - 1;

   //Copy the nonce
   osMemcpy(b0 + 1, n, nLen);

   //Encode the length field Q
   for(i = 0; i < qLen; i++, q >>= 8)
   {
      b0[15 - i] = q & 0xFF;
   }

   //Invalid length?
   if(q != 0)
      return ERROR_INVALID_LENGTH;

   //Perform AES-CCM decryption
   ccmProcessData(context, b0, a, aLen, c, p, length, authTag,
      AES_CR_MODE_DECRYPTION);

   //The calculated tag is bitwise compared to the received tag
   for(mask = 0, i = 0; i < tLen; i++)
   {
      mask |= authTag[i] ^ t[i];
   }

   //The message is authenticated if and only if the tags match
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif

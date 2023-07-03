/**
 * @file msp432e4_crypto_cipher.c
 * @brief MSP432E4 cipher hardware accelerator
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
#include <stdint.h>
#include "msp432.h"
#include "driverlib/des.h"
#include "driverlib/aes.h"
#include "core/crypto.h"
#include "hardware/msp432e4/msp432e4_crypto.h"
#include "hardware/msp432e4/msp432e4_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MSP432E4_CRYPTO_CIPHER_SUPPORT == ENABLED)


/**
 * @brief Set DES operation mode
 * @param[in] mode Mode of operation
 **/

void desSetMode(uint32_t mode)
{
   //Perform a software reset
   DES->SYSCONFIG |= DES_SYSCONFIG_SOFTRESET;

   //Wait for the reset to complete
   while((DES->SYSSTATUS & DES_SYSSTATUS_RESETDONE) == 0)
   {
   }

   //Backup the save context field before updating the register
   if((DES->CTRL & DES_CTRL_CONTEXT) != 0)
   {
      mode |= DES_CTRL_CONTEXT;
   }

   //Write control register
   DES->CTRL = mode;
}


#if (DES_SUPPORT == ENABLED)

/**
 * @brief Perform DES encryption or decryption
 * @param[in] context DES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode
 **/

void desProcessData(DesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t mode)
{
   uint32_t temp;

   //Acquire exclusive access to the DES module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Set operation mode
   desSetMode(DES_CFG_SINGLE | mode);

   //Set encryption key
   DES->KEY1_L = context->ks[0];
   DES->KEY1_H = context->ks[1];

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      DES->IV_L = LOAD32LE(iv);
      DES->IV_H = LOAD32LE(iv + 4);
   }

   //Set data length
   DES->LENGTH = length;

   //Process data
   while(length >= DES_BLOCK_SIZE)
   {
      //Wait for the DES engine to be ready to accept data
      while((DES->CTRL & DES_CTRL_INPUT_READY) == 0)
      {
      }

      //Write input block
      DES->DATA_L = LOAD32LE(input);
      DES->DATA_H = LOAD32LE(input + 4);

      //Wait for the output to be ready
      while((DES->CTRL & DES_CTRL_OUTPUT_READY) == 0)
      {
      }

      //Read output block
      temp = DES->DATA_L;
      STORE32LE(temp, output);
      temp = DES->DATA_H;
      STORE32LE(temp, output + 4);

      //Next block
      input += DES_BLOCK_SIZE;
      output += DES_BLOCK_SIZE;
      length -= DES_BLOCK_SIZE;
   }

   //Process final block of data
   if(length > 0)
   {
      uint32_t buffer[2];

      //Copy partial block
      osMemset(buffer, 0, DES_BLOCK_SIZE);
      osMemcpy(buffer, input, length);

      //Wait for the DES engine to be ready to accept data
      while((DES->CTRL & DES_CTRL_INPUT_READY) == 0)
      {
      }

      //Write input block
      DES->DATA_L = buffer[0];
      DES->DATA_H = buffer[1];

      //Wait for the output to be ready
      while((DES->CTRL & DES_CTRL_OUTPUT_READY) == 0)
      {
      }

      //Read output block
      buffer[0] = DES->DATA_L;
      buffer[1] = DES->DATA_H;

      //Copy partial block
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = DES->IV_L;
      STORE32LE(temp, iv);
      temp = DES->IV_H;
      STORE32LE(temp, iv + 4);
   }

   //Release exclusive access to the DES module
   osReleaseMutex(&msp432e4CryptoMutex);
}


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

   //No error to report
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
   //Perform DES encryption
   desProcessData(context, NULL, input, output, DES_BLOCK_SIZE,
      DES_CFG_DIR_ENCRYPT | DES_CFG_MODE_ECB);
}


/**
 * @brief Decrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void desDecryptBlock(DesContext *context, const uint8_t *input, uint8_t *output)
{
   //Perform DES decryption
   desProcessData(context, NULL, input, output, DES_BLOCK_SIZE,
      DES_CFG_DIR_DECRYPT | DES_CFG_MODE_ECB);
}

#endif
#if (DES3_SUPPORT == ENABLED)

/**
 * @brief Perform Triple DES encryption or decryption
 * @param[in] context Triple DES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode
 **/

void des3ProcessData(Des3Context *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t mode)
{
   uint32_t temp;

   //Acquire exclusive access to the DES module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Set operation mode
   desSetMode(DES_CFG_TRIPLE | mode);

   //Set encryption key
   DES->KEY1_L = context->k1.ks[0];
   DES->KEY1_H = context->k1.ks[1];
   DES->KEY2_L = context->k2.ks[0];
   DES->KEY2_H = context->k2.ks[1];
   DES->KEY3_L = context->k3.ks[0];
   DES->KEY3_H = context->k3.ks[1];

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      DES->IV_L = LOAD32LE(iv);
      DES->IV_H = LOAD32LE(iv + 4);
   }

   //Set data length
   DES->LENGTH = length;

   //Process data
   while(length >= DES3_BLOCK_SIZE)
   {
      //Wait for the DES engine to be ready to accept data
      while((DES->CTRL & DES_CTRL_INPUT_READY) == 0)
      {
      }

      //Write input block
      DES->DATA_L = LOAD32LE(input);
      DES->DATA_H = LOAD32LE(input + 4);

      //Wait for the output to be ready
      while((DES->CTRL & DES_CTRL_OUTPUT_READY) == 0)
      {
      }

      //Read output block
      temp = DES->DATA_L;
      STORE32LE(temp, output);
      temp = DES->DATA_H;
      STORE32LE(temp, output + 4);

      //Next block
      input += DES3_BLOCK_SIZE;
      output += DES3_BLOCK_SIZE;
      length -= DES3_BLOCK_SIZE;
   }

   //Process final block of data
   if(length > 0)
   {
      uint32_t buffer[2];

      //Copy partial block
      osMemset(buffer, 0, DES3_BLOCK_SIZE);
      osMemcpy(buffer, input, length);

      //Wait for the DES engine to be ready to accept data
      while((DES->CTRL & DES_CTRL_INPUT_READY) == 0)
      {
      }

      //Write input block
      DES->DATA_L = buffer[0];
      DES->DATA_H = buffer[1];

      //Wait for the output to be ready
      while((DES->CTRL & DES_CTRL_OUTPUT_READY) == 0)
      {
      }

      //Read output block
      buffer[0] = DES->DATA_L;
      buffer[1] = DES->DATA_H;

      //Copy partial block
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = DES->IV_L;
      STORE32LE(temp, iv);
      temp = DES->IV_H;
      STORE32LE(temp, iv + 4);
   }

   //Release exclusive access to the DES module
   osReleaseMutex(&msp432e4CryptoMutex);
}


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
      osMemcpy(context->k1.ks, key, 8);
      osMemcpy(context->k2.ks, key, 8);
      osMemcpy(context->k3.ks, key, 8);
   }
   else if(keyLen == 16)
   {
      //If the key length is 128 bits including parity, the first 8 bytes of the
      //encoding represent the key used for the two outer DES operations, and
      //the second 8 bytes represent the key used for the inner DES operation
      osMemcpy(context->k1.ks, key, 8);
      osMemcpy(context->k2.ks, key + 8, 8);
      osMemcpy(context->k3.ks, key, 8);
   }
   else if(keyLen == 24)
   {
      //If the key length is 192 bits including parity, then 3 independent DES
      //keys are represented, in the order in which they are used for encryption
      osMemcpy(context->k1.ks, key, 8);
      osMemcpy(context->k2.ks, key + 8, 8);
      osMemcpy(context->k3.ks, key + 16, 8);
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
   //Perform Triple DES encryption
   des3ProcessData(context, NULL, input, output, DES3_BLOCK_SIZE,
      DES_CFG_DIR_ENCRYPT | DES_CFG_MODE_ECB);
}


/**
 * @brief Decrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void des3DecryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   //Perform Triple DES decryption
   des3ProcessData(context, NULL, input, output, DES3_BLOCK_SIZE,
      DES_CFG_DIR_DECRYPT | DES_CFG_MODE_ECB);
}

#endif
#if (AES_SUPPORT == ENABLED)

/**
 * @brief Set AES operation mode
 * @param[in] mode Mode of operation
 **/

void aesSetMode(uint32_t mode)
{
   //Perform a software reset
   AES->SYSCONFIG |= AES_SYSCONFIG_SOFTRESET;

   //Wait for the reset to complete
   while((AES->SYSSTATUS & AES_SYSSTATUS_RESETDONE) == 0)
   {
   }

   //Backup the save context field before updating the register
   if((AES->CTRL & AES_CTRL_SAVE_CONTEXT) != 0)
   {
      mode |= AES_CTRL_SAVE_CONTEXT;
   }

   //Write control register
   AES->CTRL = mode;
}


/**
 * @brief Load AES key
 * @param[in] context AES algorithm context
 **/

void aesLoadKey(AesContext *context)
{
   uint32_t temp;

   //Read control register
   temp = AES->CTRL & ~AES_CTRL_KEY_SIZE_M;

   //Check the length of the key
   if(context->nr == 10)
   {
      //10 rounds are required for 128-bit key
      AES->CTRL = temp | AES_CTRL_KEY_SIZE_128;

      //Set the 128-bit encryption key
      AES->KEY1_0 = context->ek[0];
      AES->KEY1_1 = context->ek[1];
      AES->KEY1_2 = context->ek[2];
      AES->KEY1_3 = context->ek[3];
   }
   else if(context->nr == 12)
   {
      //12 rounds are required for 192-bit key
      AES->CTRL = temp | AES_CTRL_KEY_SIZE_192;

      //Set the 192-bit encryption key
      AES->KEY1_0 = context->ek[0];
      AES->KEY1_1 = context->ek[1];
      AES->KEY1_2 = context->ek[2];
      AES->KEY1_3 = context->ek[3];
      AES->KEY1_4 = context->ek[4];
      AES->KEY1_5 = context->ek[5];
   }
   else
   {
      //14 rounds are required for 256-bit key
      AES->CTRL = temp | AES_CTRL_KEY_SIZE_256;

      //Set the 256-bit encryption key
      AES->KEY1_0 = context->ek[0];
      AES->KEY1_1 = context->ek[1];
      AES->KEY1_2 = context->ek[2];
      AES->KEY1_3 = context->ek[3];
      AES->KEY1_4 = context->ek[4];
      AES->KEY1_5 = context->ek[5];
      AES->KEY1_6 = context->ek[6];
      AES->KEY1_7 = context->ek[7];
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

   //Acquire exclusive access to the AES module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Set operation mode
   aesSetMode(mode);
   //Set encryption key
   aesLoadKey(context);

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      AES->IV_IN_0 = LOAD32LE(iv);
      AES->IV_IN_1 = LOAD32LE(iv + 4);
      AES->IV_IN_2 = LOAD32LE(iv + 8);
      AES->IV_IN_3 = LOAD32LE(iv + 12);
   }

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //Wait for the AES engine to be ready to accept data
      while((AES->CTRL & AES_CTRL_INPUT_READY) == 0)
      {
      }

      //Write input block
      AES->DATA_IN_3 = LOAD32LE(input);
      AES->DATA_IN_2 = LOAD32LE(input + 4);
      AES->DATA_IN_1 = LOAD32LE(input + 8);
      AES->DATA_IN_0 = LOAD32LE(input + 12);

      //Wait for the output to be ready
      while((AES->CTRL & AES_CTRL_OUTPUT_READY) == 0)
      {
      }

      //Read output block
      temp = AES->DATA_IN_3;
      STORE32LE(temp, output);
      temp = AES->DATA_IN_2;
      STORE32LE(temp, output + 4);
      temp = AES->DATA_IN_1;
      STORE32LE(temp, output + 8);
      temp = AES->DATA_IN_0;
      STORE32LE(temp, output + 12);

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

      //Wait for the AES engine to be ready to accept data
      while((AES->CTRL & AES_CTRL_INPUT_READY) == 0)
      {
      }

      //Write input block
      AES->DATA_IN_3 = buffer[0];
      AES->DATA_IN_2 = buffer[1];
      AES->DATA_IN_1 = buffer[2];
      AES->DATA_IN_0 = buffer[3];

      //Wait for the output to be ready
      while((AES->CTRL & AES_CTRL_OUTPUT_READY) == 0)
      {
      }

      //Read output block
      buffer[0] = AES->DATA_IN_3;
      buffer[1] = AES->DATA_IN_2;
      buffer[2] = AES->DATA_IN_1;
      buffer[3] = AES->DATA_IN_0;

      //Copy partial block
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = AES->IV_IN_0;
      STORE32LE(temp, iv);
      temp = AES->IV_IN_1;
      STORE32LE(temp, iv + 4);
      temp = AES->IV_IN_2;
      STORE32LE(temp, iv + 8);
      temp = AES->IV_IN_3;
      STORE32LE(temp, iv + 12);
   }

   //Release exclusive access to the AES module
   osReleaseMutex(&msp432e4CryptoMutex);
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

   //Copy the original key
   osMemcpy(context->ek, key, keyLen);

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
      AES_CFG_DIR_ENCRYPT | AES_CFG_MODE_ECB);
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
      AES_CFG_DIR_DECRYPT | AES_CFG_MODE_ECB);
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
   error_t error;

   //Initialize status code
   error = NO_ERROR;

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
         //Encrypt payload data
         desProcessData(context, NULL, p, c, length, DES_CFG_DIR_ENCRYPT |
            DES_CFG_MODE_ECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Encrypt payload data
         des3ProcessData(context, NULL, p, c, length, DES_CFG_DIR_ENCRYPT |
            DES_CFG_MODE_ECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Encrypt payload data
         aesProcessData(context, NULL, p, c, length, AES_CFG_DIR_ENCRYPT |
            AES_CFG_MODE_ECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Decrypt payload data
         desProcessData(context, NULL, c, p, length, DES_CFG_DIR_DECRYPT |
            DES_CFG_MODE_ECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Decrypt payload data
         des3ProcessData(context, NULL, c, p, length, DES_CFG_DIR_DECRYPT |
            DES_CFG_MODE_ECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Decrypt payload data
         aesProcessData(context, NULL, c, p, length, AES_CFG_DIR_DECRYPT |
            AES_CFG_MODE_ECB);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Encrypt payload data
         desProcessData(context, iv, p, c, length, DES_CFG_DIR_ENCRYPT |
            DES_CFG_MODE_CBC);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Encrypt payload data
         des3ProcessData(context, iv, p, c, length, DES_CFG_DIR_ENCRYPT |
            DES_CFG_MODE_CBC);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Encrypt payload data
         aesProcessData(context, iv, p, c, length, AES_CFG_DIR_ENCRYPT |
            AES_CFG_MODE_CBC);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Decrypt payload data
         desProcessData(context, iv, c, p, length, DES_CFG_DIR_DECRYPT |
            DES_CFG_MODE_CBC);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Decrypt payload data
         des3ProcessData(context, iv, c, p, length, DES_CFG_DIR_DECRYPT |
            DES_CFG_MODE_CBC);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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
         //Decrypt payload data
         aesProcessData(context, iv, c, p, length, AES_CFG_DIR_DECRYPT |
            AES_CFG_MODE_CBC);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
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

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            desProcessData(context, iv, p, c, length, DES_CFG_DIR_ENCRYPT |
               DES_CFG_MODE_CFB);
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
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES3_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            des3ProcessData(context, iv, p, c, length, DES_CFG_DIR_ENCRYPT |
               DES_CFG_MODE_CFB);
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
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            aesProcessData(context, iv, p, c, length, AES_CFG_DIR_ENCRYPT |
               AES_CFG_MODE_CFB);
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
#endif
   //Unknown cipher algorithm?
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

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Decrypt payload data
            desProcessData(context, iv, c, p, length, DES_CFG_DIR_DECRYPT |
               DES_CFG_MODE_CFB);
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
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES3_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Decrypt payload data
            des3ProcessData(context, iv, c, p, length, DES_CFG_DIR_DECRYPT |
               DES_CFG_MODE_CFB);
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
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Decrypt payload data
            aesProcessData(context, iv, c, p, length, AES_CFG_DIR_DECRYPT |
               AES_CFG_MODE_CFB);
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
#endif
   //Unknown cipher algorithm?
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
#if (CTR_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)

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
            aesProcessData(context, t, p, c, length, AES_CFG_DIR_ENCRYPT |
               AES_CFG_MODE_CTR | AES_CFG_CTR_WIDTH_128);
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
#if (GCM_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)

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
   uint32_t temp;
   uint32_t buffer[4];

   //Acquire exclusive access to the AES module
   osAcquireMutex(&msp432e4CryptoMutex);

   //Check parameters
   if(aLen > 0 || length > 0)
   {
      //Set GCM operation mode
      aesSetMode(AES_CFG_MODE_GCM_HY0CALC | mode);
      //Set encryption key
      aesLoadKey(context);

      //When the length of the IV is 96 bits, the padding string is appended to
      //the IV to form the pre-counter block
      AES->IV_IN_0 = LOAD32LE(iv);
      AES->IV_IN_1 = LOAD32LE(iv + 4);
      AES->IV_IN_2 = LOAD32LE(iv + 8);
      AES->IV_IN_3 = BETOH32(1);

      //Set data length
      AES->C_LENGTH_0 = length;
      AES->C_LENGTH_1 = 0;

      //Set additional authenticated data length
      AES->AUTH_LENGTH = aLen;

      //Process additional authenticated data
      while(aLen >= AES_BLOCK_SIZE)
      {
         //Wait for the AES engine to be ready to accept data
         while((AES->CTRL & AES_CTRL_INPUT_READY) == 0)
         {
         }

         //Write block
         AES->DATA_IN_3 = LOAD32LE(a);
         AES->DATA_IN_2 = LOAD32LE(a + 4);
         AES->DATA_IN_1 = LOAD32LE(a + 8);
         AES->DATA_IN_0 = LOAD32LE(a + 12);

         //Next block
         a += AES_BLOCK_SIZE;
         aLen -= AES_BLOCK_SIZE;
      }

      //Process final block of additional authenticated data
      if(aLen > 0)
      {
         //Copy partial block
         osMemset(buffer, 0, AES_BLOCK_SIZE);
         osMemcpy(buffer, a, aLen);

         //Wait for the AES engine to be ready to accept data
         while((AES->CTRL & AES_CTRL_INPUT_READY) == 0)
         {
         }

         //Write block
         AES->DATA_IN_3 = buffer[0];
         AES->DATA_IN_2 = buffer[1];
         AES->DATA_IN_1 = buffer[2];
         AES->DATA_IN_0 = buffer[3];
      }

      //Process data
      while(length >= AES_BLOCK_SIZE)
      {
         //Wait for the AES engine to be ready to accept data
         while((AES->CTRL & AES_CTRL_INPUT_READY) == 0)
         {
         }

         //Write input block
         AES->DATA_IN_3 = LOAD32LE(input);
         AES->DATA_IN_2 = LOAD32LE(input + 4);
         AES->DATA_IN_1 = LOAD32LE(input + 8);
         AES->DATA_IN_0 = LOAD32LE(input + 12);

         //Wait for the output to be ready
         while((AES->CTRL & AES_CTRL_OUTPUT_READY) == 0)
         {
         }

         //Read output block
         temp = AES->DATA_IN_3;
         STORE32LE(temp, output);
         temp = AES->DATA_IN_2;
         STORE32LE(temp, output + 4);
         temp = AES->DATA_IN_1;
         STORE32LE(temp, output + 8);
         temp = AES->DATA_IN_0;
         STORE32LE(temp, output + 12);

         //Next block
         input += AES_BLOCK_SIZE;
         output += AES_BLOCK_SIZE;
         length -= AES_BLOCK_SIZE;
      }

      //Process final block of data
      if(length > 0)
      {
         //Copy partial block
         osMemset(buffer, 0, AES_BLOCK_SIZE);
         osMemcpy(buffer, input, length);

         //Wait for the AES engine to be ready to accept data
         while((AES->CTRL & AES_CTRL_INPUT_READY) == 0)
         {
         }

         //Write input block
         AES->DATA_IN_3 = buffer[0];
         AES->DATA_IN_2 = buffer[1];
         AES->DATA_IN_1 = buffer[2];
         AES->DATA_IN_0 = buffer[3];

         //Wait for the output to be ready
         while((AES->CTRL & AES_CTRL_OUTPUT_READY) == 0)
         {
         }

         //Read output block
         buffer[0] = AES->DATA_IN_3;
         buffer[1] = AES->DATA_IN_2;
         buffer[2] = AES->DATA_IN_1;
         buffer[3] = AES->DATA_IN_0;

         //Copy partial block
         osMemcpy(output, buffer, length);
      }

      //Wait for the output context to be ready
      while((AES->CTRL & AES_CTRL_SVCTXTRDY) == 0)
      {
      }

      //Read the authentication tag
      temp = AES->TAG_OUT_0;
      STORE32LE(temp, t);
      temp = AES->TAG_OUT_1;
      STORE32LE(temp, t + 4);
      temp = AES->TAG_OUT_2;
      STORE32LE(temp, t + 8);
      temp = AES->TAG_OUT_3;
      STORE32LE(temp, t + 12);
   }
   else
   {
      //Set CTR operation mode
      aesSetMode(AES_CFG_DIR_ENCRYPT | AES_CFG_MODE_CTR |
         AES_CFG_CTR_WIDTH_32);

      //Set encryption key
      aesLoadKey(context);

      //When the length of the IV is 96 bits, the padding string is appended to
      //the IV to form the pre-counter block
      AES->IV_IN_0 = LOAD32LE(iv);
      AES->IV_IN_1 = LOAD32LE(iv + 4);
      AES->IV_IN_2 = LOAD32LE(iv + 8);
      AES->IV_IN_3 = BETOH32(1);

      //Wait for the AES engine to be ready to accept data
      while((AES->CTRL & AES_CTRL_INPUT_READY) == 0)
      {
      }

      //Write input block
      AES->DATA_IN_3 = 0;
      AES->DATA_IN_2 = 0;
      AES->DATA_IN_1 = 0;
      AES->DATA_IN_0 = 0;

      //Wait for the output to be ready
      while((AES->CTRL & AES_CTRL_OUTPUT_READY) == 0)
      {
      }

      //Read output block
      temp = AES->DATA_IN_3;
      STORE32LE(temp, t);
      temp = AES->DATA_IN_2;
      STORE32LE(temp, t + 4);
      temp = AES->DATA_IN_1;
      STORE32LE(temp, t + 8);
      temp = AES->DATA_IN_0;
      STORE32LE(temp, t + 12);
   }

   //Release exclusive access to the AES module
   osReleaseMutex(&msp432e4CryptoMutex);
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
   gcmProcessData(context->cipherContext, iv, a, aLen, p, c, length, authTag,
      AES_CFG_DIR_ENCRYPT);

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
   gcmProcessData(context->cipherContext, iv, a, aLen, c, p, length, authTag,
      AES_CFG_DIR_DECRYPT);

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

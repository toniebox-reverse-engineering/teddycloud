/**
 * @file sam4l_crypto_cipher.c
 * @brief SAM4L cipher hardware accelerator
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
#include "sam4l.h"
#include "core/crypto.h"
#include "hardware/sam4l/sam4l_crypto.h"
#include "hardware/sam4l/sam4l_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "debug.h"

//Check crypto library configuration
#if (SAM4L_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief Encrypt/decrypt a 16-byte block using AES algorithm
 * @param[in] input Input block to be encrypted/decrypted
 * @param[out] output Resulting block
 **/

void aesProcessDataBlock(const uint8_t *input, uint8_t *output)
{
   uint32_t *p;

   //The IBUFRDY bit is set when the input buffer is ready to receive data
   while((AESA->AESA_SR & AESA_SR_IBUFRDY) == 0)
   {
   }

   //Write input block
   p = (uint32_t *) input;
   AESA->AESA_IDATA = p[0];
   AESA->AESA_IDATA = p[1];
   AESA->AESA_IDATA = p[2];
   AESA->AESA_IDATA = p[3];

   //The ODATARDY bit is set when the encryption or decryption operation has
   //completed and the processed data can be read from the output buffer
   while((AESA->AESA_SR & AESA_SR_ODATARDY) == 0)
   {
   }

   //Read output block
   p = (uint32_t *) output;
   p[0] = AESA->AESA_ODATA;
   p[1] = AESA->AESA_ODATA;
   p[2] = AESA->AESA_ODATA;
   p[3] = AESA->AESA_ODATA;
}


/**
 * @brief Perform AES encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode
 **/

void aesProcessData(AesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t mode)
{
   uint32_t *p;

   //Acquire exclusive access to the AES module
   osAcquireMutex(&sam4lCryptoMutex);

   //Enable AES module
   AESA->AESA_CTRL = AESA_CTRL_ENABLE;

   //Set operation mode
   AESA->AESA_MODE = AESA_MODE_CTYPE(15) | mode;

   //Set encryption key
   AESA->AESA_KEY[0].AESA_KEY = context->ek[0];
   AESA->AESA_KEY[1].AESA_KEY = context->ek[1];
   AESA->AESA_KEY[2].AESA_KEY = context->ek[2];
   AESA->AESA_KEY[3].AESA_KEY = context->ek[3];

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      p = (uint32_t *) iv;
      AESA->AESA_INITVECT[0].AESA_INITVECT = p[0];
      AESA->AESA_INITVECT[1].AESA_INITVECT = p[1];
      AESA->AESA_INITVECT[2].AESA_INITVECT = p[2];
      AESA->AESA_INITVECT[3].AESA_INITVECT = p[3];

      //Notify the module that the next input data block is the beginning
      //of a new message
      AESA->AESA_CTRL |= AESA_CTRL_NEWMSG;
   }

   //Reset input and output buffer pointers
   AESA->AESA_DATABUFPTR = 0;

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //The data is encrypted block by block
      aesProcessDataBlock(input, output);

      //Next block
      input += AES_BLOCK_SIZE;
      output += AES_BLOCK_SIZE;
      length -= AES_BLOCK_SIZE;
   }

   //Process final block of data
   if(length > 0)
   {
      uint8_t buffer[AES_BLOCK_SIZE];

      //Copy input data
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, input, length);

      //Encrypt the final block of data
      aesProcessDataBlock(buffer, buffer);

      //Copy output data
      osMemcpy(output, buffer, length);
   }

   //Disabled AES module
   AESA->AESA_CTRL = 0;

   //Release exclusive access to the AES module
   osReleaseMutex(&sam4lCryptoMutex);
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

   //192 and 256-bit keys are not supported
   if(keyLen != 16)
      return ERROR_INVALID_KEY_LENGTH;

   //10 rounds are required for 128-bit key
   context->nr = 10;

   //Copy the original key
   context->ek[0] = LOAD32LE(key);
   context->ek[1] = LOAD32LE(key + 4);
   context->ek[2] = LOAD32LE(key + 8);
   context->ek[3] = LOAD32LE(key + 12);

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
      AESA_MODE_ENCRYPT | AESA_MODE_OPMODE_ECB);
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
      AESA_MODE_OPMODE_ECB);
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
         aesProcessData(context, NULL, p, c, length, AESA_MODE_ENCRYPT |
            AESA_MODE_OPMODE_ECB);
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
         aesProcessData(context, NULL, c, p, length, AESA_MODE_OPMODE_ECB);
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
         aesProcessData(context, iv, p, c, length, AESA_MODE_ENCRYPT |
            AESA_MODE_OPMODE_CBC);

         //Update the value of the initialization vector
         osMemcpy(iv, c + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
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
         uint8_t block[AES_BLOCK_SIZE];

         //Save the last input block
         osMemcpy(block, c + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

         //Decrypt payload data
         aesProcessData(context, iv, c, p, length, AESA_MODE_OPMODE_CBC);

         //Update the value of the initialization vector
         osMemcpy(iv, block, AES_BLOCK_SIZE);
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
            //Encrypt payload data
            aesProcessData(context, iv, p, c, length, AESA_MODE_ENCRYPT |
               AESA_MODE_OPMODE_CFB | AESA_MODE_CFBS_128BIT);
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
            //Decrypt payload data
            aesProcessData(context, iv, c, p, length, AESA_MODE_OPMODE_CFB |
               AESA_MODE_CFBS_128BIT);
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
            //Encrypt payload data
            aesProcessData(context, iv, p, c, length, AESA_MODE_ENCRYPT |
               AESA_MODE_OPMODE_OFB);
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
#endif

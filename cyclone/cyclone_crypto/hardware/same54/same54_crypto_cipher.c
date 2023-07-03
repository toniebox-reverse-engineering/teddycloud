/**
 * @file same54_crypto_cipher.c
 * @brief SAME54 cipher hardware accelerator
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
#include "sam.h"
#include "core/crypto.h"
#include "hardware/same54/same54_crypto.h"
#include "hardware/same54/same54_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (SAME54_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief Load AES key
 * @param[in] context AES algorithm context
 **/

void aesLoadKey(AesContext *context)
{
   uint32_t temp;

   //Read CTRLA register
   temp = AES_REGS->AES_CTRLA & ~AES_CTRLA_KEYSIZE_Msk;

   //Check the length of the key
   if(context->nr == 10)
   {
      //10 rounds are required for 128-bit key
      AES_REGS->AES_CTRLA = temp | AES_CTRLA_KEYSIZE_128BIT;

      //Set the 128-bit encryption key
      AES_REGS->AES_KEYWORD[0] = context->ek[0];
      AES_REGS->AES_KEYWORD[1] = context->ek[1];
      AES_REGS->AES_KEYWORD[2] = context->ek[2];
      AES_REGS->AES_KEYWORD[3] = context->ek[3];
   }
   else if(context->nr == 12)
   {
      //12 rounds are required for 192-bit key
      AES_REGS->AES_CTRLA = temp | AES_CTRLA_KEYSIZE_192BIT;

      //Set the 192-bit encryption key
      AES_REGS->AES_KEYWORD[0] = context->ek[0];
      AES_REGS->AES_KEYWORD[1] = context->ek[1];
      AES_REGS->AES_KEYWORD[2] = context->ek[2];
      AES_REGS->AES_KEYWORD[3] = context->ek[3];
      AES_REGS->AES_KEYWORD[4] = context->ek[4];
      AES_REGS->AES_KEYWORD[5] = context->ek[5];
   }
   else
   {
      //14 rounds are required for 256-bit key
      AES_REGS->AES_CTRLA = temp | AES_CTRLA_KEYSIZE_256BIT;

      //Set the 256-bit encryption key
      AES_REGS->AES_KEYWORD[0] = context->ek[0];
      AES_REGS->AES_KEYWORD[1] = context->ek[1];
      AES_REGS->AES_KEYWORD[2] = context->ek[2];
      AES_REGS->AES_KEYWORD[3] = context->ek[3];
      AES_REGS->AES_KEYWORD[4] = context->ek[4];
      AES_REGS->AES_KEYWORD[5] = context->ek[5];
      AES_REGS->AES_KEYWORD[6] = context->ek[6];
      AES_REGS->AES_KEYWORD[7] = context->ek[7];
   }
}


/**
 * @brief Encrypt/decrypt a 16-byte block using AES algorithm
 * @param[in] input Input block to be encrypted/decrypted
 * @param[out] output Resulting block
 **/

void aesProcessDataBlock(const uint8_t *input, uint8_t *output)
{
   uint32_t *p;

   //Write input block
   p = (uint32_t *) input;
   AES_REGS->AES_INDATA = p[0];
   AES_REGS->AES_INDATA = p[1];
   AES_REGS->AES_INDATA = p[2];
   AES_REGS->AES_INDATA = p[3];

   //Start encryption/decryption
   AES_REGS->AES_CTRLB |= AES_CTRLB_START_Msk;

   //The ENCCMP status flag is set when encryption/decryption is complete
   while((AES_REGS->AES_INTFLAG & AES_INTFLAG_ENCCMP_Msk) == 0)
   {
   }

   //Read output block
   p = (uint32_t *) output;
   p[0] = AES_REGS->AES_INDATA;
   p[1] = AES_REGS->AES_INDATA;
   p[2] = AES_REGS->AES_INDATA;
   p[3] = AES_REGS->AES_INDATA;
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
   osAcquireMutex(&same54CryptoMutex);

   //Perform software reset
   AES_REGS->AES_CTRLA = AES_CTRLA_SWRST_Msk;
   AES_REGS->AES_CTRLA = 0;
   AES_REGS->AES_CTRLB = 0;

   //Set operation mode
   AES_REGS->AES_CTRLA = AES_CTRLA_STARTMODE_MANUAL | mode;
   //Set encryption key
   aesLoadKey(context);
   //Enable AES module
   AES_REGS->AES_CTRLA |= AES_CTRLA_ENABLE_Msk;

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      p = (uint32_t *) iv;
      AES_REGS->AES_INTVECTV[0] = p[0];
      AES_REGS->AES_INTVECTV[1] = p[1];
      AES_REGS->AES_INTVECTV[2] = p[2];
      AES_REGS->AES_INTVECTV[3] = p[3];

      //Indicate the hardware to use initialization vector for encrypting
      //the first block of message
      AES_REGS->AES_CTRLB |= AES_CTRLB_NEWMSG_Msk;
   }

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

   //Release exclusive access to the AES module
   osReleaseMutex(&same54CryptoMutex);
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
      AES_CTRLA_CIPHER_ENC | AES_CTRLA_AESMODE_ECB);
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
      AES_CTRLA_CIPHER_DEC | AES_CTRLA_AESMODE_ECB);
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
         aesProcessData(context, NULL, p, c, length, AES_CTRLA_CIPHER_ENC |
            AES_CTRLA_AESMODE_ECB);
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
         aesProcessData(context, NULL, c, p, length, AES_CTRLA_CIPHER_DEC |
            AES_CTRLA_AESMODE_ECB);
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
         aesProcessData(context, iv, p, c, length, AES_CTRLA_CIPHER_ENC |
            AES_CTRLA_AESMODE_CBC);

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
         aesProcessData(context, iv, c, p, length, AES_CTRLA_CIPHER_DEC |
            AES_CTRLA_AESMODE_CBC);

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
            aesProcessData(context, iv, p, c, length, AES_CTRLA_CIPHER_ENC |
               AES_CTRLA_AESMODE_CFB | AES_CTRLA_CFBS_128BIT);
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
            aesProcessData(context, iv, c, p, length, AES_CTRLA_CIPHER_DEC |
               AES_CTRLA_AESMODE_CFB | AES_CTRLA_CFBS_128BIT);
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
            aesProcessData(context, iv, p, c, length, AES_CTRLA_CIPHER_ENC |
               AES_CTRLA_AESMODE_OFB);
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
#if (GCM_SUPPORT == ENABLED)

/**
 * @brief Generate hash subkey
 * @param[in] context AES algorithm context
 **/

void gcmGenerateHashSubKey(AesContext *context)
{
   //Perform software reset
   AES_REGS->AES_CTRLA = AES_CTRLA_SWRST_Msk;
   AES_REGS->AES_CTRLA = 0;
   AES_REGS->AES_CTRLB = 0;

   //Set operation mode
   AES_REGS->AES_CTRLA = AES_CTRLA_STARTMODE_MANUAL | AES_CTRLA_CIPHER_ENC |
      AES_CTRLA_AESMODE_ECB | AES_CTRLA_CTYPE(15);

   //Set encryption key
   aesLoadKey(context);
   //Write zero to CIPLEN register
   AES_REGS->AES_CIPLEN = 0;
   //Enable AES module
   AES_REGS->AES_CTRLA |= AES_CTRLA_ENABLE_Msk;

   //Write the zeros to DATA register
   AES_REGS->AES_INDATA = 0;
   AES_REGS->AES_INDATA = 0;
   AES_REGS->AES_INDATA = 0;
   AES_REGS->AES_INDATA = 0;

   //Generate the hash subkey
   AES_REGS->AES_CTRLB |= AES_CTRLB_START_Msk;

   //The ENCCMP status flag is set when the hash subkey generation is complete
   while((AES_REGS->AES_INTFLAG & AES_INTFLAG_ENCCMP_Msk) == 0)
   {
   }

   //Disable AES module
   AES_REGS->AES_CTRLA &= ~AES_CTRLA_ENABLE_Msk;
}


/**
 * @brief Set GCM operation mode
 * @param[in] context AES algorithm context
 * @param[in] mode Operation mode (encryption or decryption)
 **/

void gcmSetMode(AesContext *context, uint32_t mode)
{
   //Set operation mode
   AES_REGS->AES_CTRLA = AES_CTRLA_STARTMODE_MANUAL | mode |
      AES_CTRLA_AESMODE_GCM | AES_CTRLA_CTYPE(15);

   //Set encryption key
   aesLoadKey(context);

   //Enable AES module
   AES_REGS->AES_CTRLA |= AES_CTRLA_ENABLE_Msk;
}


/**
 * @brief Update GHASH value
 * @param[in] data Input block of data
 **/

void gcmUpdateGhash(const uint8_t *data)
{
   uint32_t *p;

   //Write data block
   p = (uint32_t *) data;
   AES_REGS->AES_INDATA = p[0];
   AES_REGS->AES_INDATA = p[1];
   AES_REGS->AES_INDATA = p[2];
   AES_REGS->AES_INDATA = p[3];

   //Start GF multiplication
   AES_REGS->AES_CTRLB |= AES_CTRLB_START_Msk;

   //The ENCCMP status flag is set when the GF multiplication is complete
   while((AES_REGS->AES_INTFLAG & AES_INTFLAG_GFMCMP_Msk) == 0)
   {
   }
}


/**
 * @brief Generate pre-counter block
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[out] j Resulting value of the pre-counter block (J0)
 **/

void gcmGeneratePreCounterBlock(const uint8_t *iv, size_t ivLen, uint32_t *j)
{
   size_t k;
   size_t n;
   uint8_t buffer[16];

   //Check whether the length of the IV is 96 bits
   if(ivLen == 12)
   {
      //When the length of the IV is 96 bits, the padding string is appended
      //to the IV to form the pre-counter block
      j[0] = LOAD32LE(iv);
      j[1] = LOAD32LE(iv + 4);
      j[2] = LOAD32LE(iv + 8);
      j[3] = BETOH32(1);
   }
   else
   {
      //Set GFMUL bit
      AES_REGS->AES_CTRLB |= AES_CTRLB_GFMUL_Msk;

      //Initialize GHASH calculation
      osMemset(buffer, 0, 16);

      //Length of the IV
      n = ivLen;

      //Process the initialization vector
      while(n > 0)
      {
         //The IV processed in a block-by-block fashion
         k = MIN(n, 16);

         //Copy current block
         osMemset(buffer, 0, 16);
         osMemcpy(buffer, iv, k);

         //Apply GHASH function
         gcmUpdateGhash(buffer);

         //Next block
         iv += k;
         n -= k;
      }

      //The string is appended with 64 additional 0 bits, followed by the
      //64-bit representation of the length of the IV
      osMemset(buffer, 0, 8);
      STORE64BE(ivLen * 8, buffer + 8);

      //The GHASH function is applied to the resulting string to form the
      //pre-counter block
      gcmUpdateGhash(buffer);

      //Retrieve the resulting value
      j[0] = AES_REGS->AES_GHASH[0];
      j[1] = AES_REGS->AES_GHASH[1];
      j[2] = AES_REGS->AES_GHASH[2];
      j[3] = AES_REGS->AES_GHASH[3];

      //Reset GHASH calculation
      AES_REGS->AES_GHASH[0] = 0;
      AES_REGS->AES_GHASH[1] = 0;
      AES_REGS->AES_GHASH[2] = 0;
      AES_REGS->AES_GHASH[3] = 0;
   }
}


/**
 * @brief Process additional authenticated data
 * @param[in] aad Additional authenticated data
 * @param[in] aadLen Length of the additional data
 **/

void gcmProcessAuthData(const uint8_t *aad, size_t aadLen)
{
   //Set GFMUL bit
   AES_REGS->AES_CTRLB |= AES_CTRLB_GFMUL_Msk;

   //Process additional authenticated data
   while(aadLen > 16)
   {
      //Additional authenticated data is written block by block
      gcmUpdateGhash(aad);

      //Next block
      aad += 16;
      aadLen -= 16;
   }

   //Process final block of additional authenticated data
   if(aadLen > 0)
   {
      uint8_t buffer[16];

      //Copy partial block
      osMemset(buffer, 0, 16);
      osMemcpy(buffer, aad, aadLen);

      //Write the resulting block
      gcmUpdateGhash(buffer);
   }
}


/**
 * @brief Encrypt/decrypt payload data
 * @param[in] j Value of the pre-counter block (J0)
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 **/

void gcmProcessData(const uint32_t *j, const uint8_t *input, uint8_t *output,
   size_t length)
{
   uint32_t buffer[4];

   //Clear GFMUL bit
   AES_REGS->AES_CTRLB &= ~AES_CTRLB_GFMUL_Msk;

   //Copy the left-most 96-bits of the counter block
   buffer[0] = j[0];
   buffer[1] = j[1];
   buffer[2] = j[2];

   //Increment the right-most 32 bits of the counter block
   buffer[3] = betoh32(j[3]) + 1;
   buffer[3] = htobe32(buffer[3]);

   //Load the resulting value in INTVECT registers
   AES_REGS->AES_INTVECTV[0] = buffer[0];
   AES_REGS->AES_INTVECTV[1] = buffer[1];
   AES_REGS->AES_INTVECTV[2] = buffer[2];
   AES_REGS->AES_INTVECTV[3] = buffer[3];

   //Set NEWMSG bit for the new set of plain text processing
   AES_REGS->AES_CTRLB |= AES_CTRLB_NEWMSG_Msk;
   //Load CIPLEN register
   AES_REGS->AES_CIPLEN = length;
   //Clear ENCCMP status flag
   AES_REGS->AES_INTFLAG = AES_INTFLAG_ENCCMP_Msk;

   //Process data
   while(length > AES_BLOCK_SIZE)
   {
      //The data is encrypted block by block
      aesProcessDataBlock(input, output);

      //Next block
      input += AES_BLOCK_SIZE;
      output += AES_BLOCK_SIZE;
      length -= AES_BLOCK_SIZE;
   }

   //Process final block of data
   if(length == AES_BLOCK_SIZE)
   {
      //Set EOM bit for the last block of data
      AES_REGS->AES_CTRLB |= AES_CTRLB_EOM_Msk;

      //Encrypt the final block of data
      aesProcessDataBlock(input, output);
   }
   else if(length > 0)
   {
      uint8_t inputBlock[AES_BLOCK_SIZE];
      uint8_t outputBlock[AES_BLOCK_SIZE];

      //Save current GHASH value
      buffer[0] = AES_REGS->AES_GHASH[0];
      buffer[1] = AES_REGS->AES_GHASH[1];
      buffer[2] = AES_REGS->AES_GHASH[2];
      buffer[3] = AES_REGS->AES_GHASH[3];

      //Set EOM bit for the last block of data
      AES_REGS->AES_CTRLB |= AES_CTRLB_EOM_Msk;

      //Copy input data
      osMemset(inputBlock, 0, AES_BLOCK_SIZE);
      osMemcpy(inputBlock, input, length);

      //Encrypt the final block of data
      aesProcessDataBlock(inputBlock, outputBlock);

      //Copy output data
      osMemcpy(output, outputBlock, length);

      //Restore previous GHASH value (workaround)
      AES_REGS->AES_GHASH[0] = buffer[0];
      AES_REGS->AES_GHASH[1] = buffer[1];
      AES_REGS->AES_GHASH[2] = buffer[2];
      AES_REGS->AES_GHASH[3] = buffer[3];

      //Set GFMUL bit
      AES_REGS->AES_CTRLB |= AES_CTRLB_GFMUL_Msk;

      //Check operation mode
      if((AES_REGS->AES_CTRLA & AES_CTRLA_CIPHER_ENC) != 0)
      {
         osMemset(inputBlock, 0, AES_BLOCK_SIZE);
         osMemcpy(inputBlock, output, length);
      }

      //Recompute GHASH value (workaround)
      gcmUpdateGhash(inputBlock);

      //Clear GFMUL bit
      AES_REGS->AES_CTRLB &= ~AES_CTRLB_GFMUL_Msk;
   }
   else
   {
      //Just for sanity
   }
}


/**
 * @brief Calculate authentication tag
 * @param[in] context AES algorithm context
 * @param[in] j Value of the pre-counter block (J0)
 * @param[in] aadLen Length of the additional data, in bytes
 * @param[in] dataLen Length of the payload data, in bytes
 * @param[out] tag Authentication tag
 **/

void gcmGenerateTag(AesContext *context, const uint32_t *j, size_t aadLen,
   size_t dataLen, uint8_t *tag)
{
   uint32_t buffer[4];
   uint64_t n;

   //Append the 64-bit representation of the length of the AAD and the
   //ciphertext
   n = aadLen * 8;
   buffer[0] = htobe32(n >> 32);
   buffer[1] = htobe32(n);
   n = dataLen * 8;
   buffer[2] = htobe32(n >> 32);
   buffer[3] = htobe32(n);

   //Set GFMUL bit
   AES_REGS->AES_CTRLB |= AES_CTRLB_GFMUL_Msk;

   //Apply GHASH function
   gcmUpdateGhash((uint8_t *) buffer);

   //The hardware generates the final GHASH value in GHASH registers
   buffer[0] = AES_REGS->AES_GHASH[0];
   buffer[1] = AES_REGS->AES_GHASH[1];
   buffer[2] = AES_REGS->AES_GHASH[2];
   buffer[3] = AES_REGS->AES_GHASH[3];

   //Disable AES module
   AES_REGS->AES_CTRLA = 0;
   AES_REGS->AES_CTRLB = 0;

   //Set operation mode
   AES_REGS->AES_CTRLA = AES_CTRLA_STARTMODE_MANUAL | AES_CTRLA_CIPHER_ENC |
      AES_CTRLA_AESMODE_COUNTER | AES_CTRLA_CTYPE(15);

   //Set encryption key
   aesLoadKey(context);
   //Enable AES module
   AES_REGS->AES_CTRLA |= AES_CTRLA_ENABLE_Msk;

   //Load J0 value to INITVECTV registers
   AES_REGS->AES_INTVECTV[0] = j[0];
   AES_REGS->AES_INTVECTV[1] = j[1];
   AES_REGS->AES_INTVECTV[2] = j[2];
   AES_REGS->AES_INTVECTV[3] = j[3];

   //Set NEWMSG bit
   AES_REGS->AES_CTRLB |= AES_CTRLB_NEWMSG_Msk;

   //Generate the authentication tag
   aesProcessDataBlock((uint8_t *) buffer, (uint8_t *) buffer);

   //Copy the resulting value
   memcpy(tag, buffer, 16);

   //Perform software reset
   AES_REGS->AES_CTRLA = AES_CTRLA_SWRST_Msk;

   //Disable AES module
   AES_REGS->AES_CTRLA = 0;
   AES_REGS->AES_CTRLB = 0;
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
   uint32_t j[4];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The length of the IV shall meet SP 800-38D requirements
   if(ivLen < 1)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Acquire exclusive access to the AES module
   osAcquireMutex(&same54CryptoMutex);

   //Perform AES-GCM encryption
   gcmGenerateHashSubKey(context->cipherContext);
   gcmSetMode(context->cipherContext, AES_CTRLA_CIPHER_ENC);
   gcmGeneratePreCounterBlock(iv, ivLen, j);
   gcmProcessAuthData(a, aLen);
   gcmProcessData(j, p, c, length);
   gcmGenerateTag(context->cipherContext, j, aLen, length, authTag);

   //Release exclusive access to the AES module
   osReleaseMutex(&same54CryptoMutex);

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
   uint32_t j[4];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The length of the IV shall meet SP 800-38D requirements
   if(ivLen < 1)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Acquire exclusive access to the AES module
   osAcquireMutex(&same54CryptoMutex);

   //Perform AES-GCM decryption
   gcmGenerateHashSubKey(context->cipherContext);
   gcmSetMode(context->cipherContext, AES_CTRLA_CIPHER_DEC);
   gcmGeneratePreCounterBlock(iv, ivLen, j);
   gcmProcessAuthData(a, aLen);
   gcmProcessData(j, c, p, length);
   gcmGenerateTag(context->cipherContext, j, aLen, length, authTag);

   //Release exclusive access to the AES module
   osReleaseMutex(&same54CryptoMutex);

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

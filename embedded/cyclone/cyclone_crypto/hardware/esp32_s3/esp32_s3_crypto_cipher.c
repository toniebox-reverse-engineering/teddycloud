/**
 * @file esp32_s3_crypto_cipher.c
 * @brief ESP32-S3 cipher hardware accelerator
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
#include "esp_crypto_lock.h"
#include "soc/hwcrypto_reg.h"
#include "driver/periph_ctrl.h"
#include "core/crypto.h"
#include "hardware/esp32_s3/esp32_s3_crypto.h"
#include "hardware/esp32_s3/esp32_s3_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "debug.h"

//Check crypto library configuration
#if (ESP32_S3_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief AES module initialization
 **/

void esp32s3AesInit(void)
{
}


/**
 * @brief Load AES key
 * @param[in] context AES algorithm context
 * @param[in] mode Operation mode
 **/

void aesLoadKey(AesContext *context, uint32_t mode)
{
   //Disable DMA mode
   REG_WRITE(AES_DMA_ENABLE_REG, 0);
   //Configure endianness
   REG_WRITE(AES_ENDIAN_REG, AES_ENDIAN_DEFAULT);

   //Check the length of the key
   if(context->nr == 10)
   {
      //Configure operation mode
      REG_WRITE(AES_MODE_REG, AES_MODE_128_BITS | mode);

      //Load the 128-bit key
      REG_WRITE(AES_KEY_BASE, context->ek[0]);
      REG_WRITE(AES_KEY_BASE + 4, context->ek[1]);
      REG_WRITE(AES_KEY_BASE + 8, context->ek[2]);
      REG_WRITE(AES_KEY_BASE + 12, context->ek[3]);
   }
   else
   {
      //Configure operation mode
      REG_WRITE(AES_MODE_REG, AES_MODE_256_BITS | mode);

      //Load the 256-bit key
      REG_WRITE(AES_KEY_BASE, context->ek[0]);
      REG_WRITE(AES_KEY_BASE + 4, context->ek[1]);
      REG_WRITE(AES_KEY_BASE + 8, context->ek[2]);
      REG_WRITE(AES_KEY_BASE + 12, context->ek[3]);
      REG_WRITE(AES_KEY_BASE + 16, context->ek[4]);
      REG_WRITE(AES_KEY_BASE + 20, context->ek[5]);
      REG_WRITE(AES_KEY_BASE + 24, context->ek[6]);
      REG_WRITE(AES_KEY_BASE + 28, context->ek[7]);
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

   //Write plaintext
   p = (uint32_t *) input;
   REG_WRITE(AES_TEXT_IN_BASE, p[0]);
   REG_WRITE(AES_TEXT_IN_BASE + 4, p[1]);
   REG_WRITE(AES_TEXT_IN_BASE + 8, p[2]);
   REG_WRITE(AES_TEXT_IN_BASE + 12, p[3]);

   //Start AES encryption
   REG_WRITE(AES_TRIGGER_REG, 1);

   //Wait for the operation to complete
   while(REG_READ(AES_STATE_REG) != 0)
   {
   }

   //Read ciphertext
   p = (uint32_t *) output;
   p[0] = REG_READ(AES_TEXT_OUT_BASE);
   p[1] = REG_READ(AES_TEXT_OUT_BASE + 4);
   p[2] = REG_READ(AES_TEXT_OUT_BASE + 8);
   p[3] = REG_READ(AES_TEXT_OUT_BASE + 12);
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
   //Acquire exclusive access to the AES module
   esp_crypto_sha_aes_lock_acquire();
   //Enable AES module
   periph_module_enable(PERIPH_AES_MODULE);

   //Load AES key
   aesLoadKey(context, AES_MODE_ENC);
   //Perform AES encryption
   aesProcessDataBlock(input, output);

   //Disable AES module
   periph_module_disable(PERIPH_AES_MODULE);
   //Release exclusive access to the AES module
   esp_crypto_sha_aes_lock_release();
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   //Acquire exclusive access to the AES module
   esp_crypto_sha_aes_lock_acquire();
   //Enable AES module
   periph_module_enable(PERIPH_AES_MODULE);

   //Load AES key
   aesLoadKey(context, AES_MODE_DEC);
   //Perform AES decryption
   aesProcessDataBlock(input, output);

   //Disable AES module
   periph_module_disable(PERIPH_AES_MODULE);
   //Release exclusive access to the AES module
   esp_crypto_sha_aes_lock_release();
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
      //Acquire exclusive access to the AES module
      esp_crypto_sha_aes_lock_acquire();
      //Enable AES module
      periph_module_enable(PERIPH_AES_MODULE);

      //Load AES key
      aesLoadKey(context, AES_MODE_ENC);

      //ECB mode operates in a block-by-block fashion
      while(length >= AES_BLOCK_SIZE)
      {
         //Encrypt current block
         aesProcessDataBlock(p, c);

         //Next block
         p += AES_BLOCK_SIZE;
         c += AES_BLOCK_SIZE;
         length -= AES_BLOCK_SIZE;
      }

      //Disable AES module
      periph_module_disable(PERIPH_AES_MODULE);
      //Release exclusive access to the AES module
      esp_crypto_sha_aes_lock_release();

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
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
      //Acquire exclusive access to the AES module
      esp_crypto_sha_aes_lock_acquire();
      //Enable AES module
      periph_module_enable(PERIPH_AES_MODULE);

      //Load AES key
      aesLoadKey(context, AES_MODE_DEC);

      //ECB mode operates in a block-by-block fashion
      while(length >= AES_BLOCK_SIZE)
      {
         //Decrypt current block
         aesProcessDataBlock(c, p);

         //Next block
         c += AES_BLOCK_SIZE;
         p += AES_BLOCK_SIZE;
         length -= AES_BLOCK_SIZE;
      }

      //Disable AES module
      periph_module_disable(PERIPH_AES_MODULE);
      //Release exclusive access to the AES module
      esp_crypto_sha_aes_lock_release();

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
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
   size_t i;

   //Initialize status code
   error = NO_ERROR;

   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Acquire exclusive access to the AES module
      esp_crypto_sha_aes_lock_acquire();
      //Enable AES module
      periph_module_enable(PERIPH_AES_MODULE);

      //Load AES key
      aesLoadKey(context, AES_MODE_ENC);

      //CBC mode operates in a block-by-block fashion
      while(length >= AES_BLOCK_SIZE)
      {
         //XOR input block with IV contents
         for(i = 0; i < AES_BLOCK_SIZE; i++)
         {
            c[i] = p[i] ^ iv[i];
         }

         //Encrypt the current block based upon the output of the previous
         //encryption
         aesProcessDataBlock(c, c);

         //Update IV with output block contents
         osMemcpy(iv, c, AES_BLOCK_SIZE);

         //Next block
         p += AES_BLOCK_SIZE;
         c += AES_BLOCK_SIZE;
         length -= AES_BLOCK_SIZE;
      }

      //Disable AES module
      periph_module_disable(PERIPH_AES_MODULE);
      //Release exclusive access to the AES module
      esp_crypto_sha_aes_lock_release();

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
   {
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
   size_t i;
   uint8_t t[16];

   //Initialize status code
   error = NO_ERROR;

   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Acquire exclusive access to the AES module
      esp_crypto_sha_aes_lock_acquire();
      //Enable AES module
      periph_module_enable(PERIPH_AES_MODULE);

      //Load AES key
      aesLoadKey(context, AES_MODE_DEC);

      //CBC mode operates in a block-by-block fashion
      while(length >= AES_BLOCK_SIZE)
      {
         //Save input block
         osMemcpy(t, c, AES_BLOCK_SIZE);

         //Decrypt the current block
         aesProcessDataBlock(c, p);

         //XOR output block with IV contents
         for(i = 0; i < AES_BLOCK_SIZE; i++)
         {
            p[i] ^= iv[i];
         }

         //Update IV with input block contents
         osMemcpy(iv, t, AES_BLOCK_SIZE);

         //Next block
         c += AES_BLOCK_SIZE;
         p += AES_BLOCK_SIZE;
         length -= AES_BLOCK_SIZE;
      }

      //Disable AES module
      periph_module_disable(PERIPH_AES_MODULE);
      //Release exclusive access to the AES module
      esp_crypto_sha_aes_lock_release();

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
   {
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
      if((s % 8) == 0 && s >= 1 && s <= (AES_BLOCK_SIZE * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Acquire exclusive access to the AES module
         esp_crypto_sha_aes_lock_acquire();
         //Enable AES module
         periph_module_enable(PERIPH_AES_MODULE);

         //Load AES key
         aesLoadKey(context, AES_MODE_ENC);

         //Process each plaintext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            aesProcessDataBlock(iv, o);

            //Compute C(j) = P(j) XOR MSB(O(j))
            for(i = 0; i < n; i++)
            {
               c[i] = p[i] ^ o[i];
            }

            //Compute I(j+1) = LSB(I(j)) | C(j)
            osMemmove(iv, iv + s, AES_BLOCK_SIZE - s);
            osMemcpy(iv + AES_BLOCK_SIZE - s, c, s);

            //Next block
            p += n;
            c += n;
            length -= n;
         }

         //Disable AES module
         periph_module_disable(PERIPH_AES_MODULE);
         //Release exclusive access to the AES module
         esp_crypto_sha_aes_lock_release();
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
      if((s % 8) == 0 && s >= 1 && s <= (AES_BLOCK_SIZE * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Acquire exclusive access to the AES module
         esp_crypto_sha_aes_lock_acquire();
         //Enable AES module
         periph_module_enable(PERIPH_AES_MODULE);

         //Load AES key
         aesLoadKey(context, AES_MODE_ENC);

         //Process each ciphertext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            aesProcessDataBlock(iv, o);

            //Compute I(j+1) = LSB(I(j)) | C(j)
            osMemmove(iv, iv + s, AES_BLOCK_SIZE - s);
            osMemcpy(iv + AES_BLOCK_SIZE - s, c, s);

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

         //Disable AES module
         periph_module_disable(PERIPH_AES_MODULE);
         //Release exclusive access to the AES module
         esp_crypto_sha_aes_lock_release();
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
      if((s % 8) == 0 && s >= 1 && s <= (AES_BLOCK_SIZE * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Acquire exclusive access to the AES module
         esp_crypto_sha_aes_lock_acquire();
         //Enable AES module
         periph_module_enable(PERIPH_AES_MODULE);

         //Load AES key
         aesLoadKey(context, AES_MODE_ENC);

         //Process each plaintext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            aesProcessDataBlock(iv, o);

            //Compute C(j) = P(j) XOR MSB(O(j))
            for(i = 0; i < n; i++)
            {
               c[i] = p[i] ^ o[i];
            }

            //Compute I(j+1) = LSB(I(j)) | O(j)
            osMemmove(iv, iv + s, AES_BLOCK_SIZE - s);
            osMemcpy(iv + AES_BLOCK_SIZE - s, o, s);

            //Next block
            p += n;
            c += n;
            length -= n;
         }

         //Disable AES module
         periph_module_disable(PERIPH_AES_MODULE);
         //Release exclusive access to the AES module
         esp_crypto_sha_aes_lock_release();
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
      if((m % 8) == 0 && m <= (AES_BLOCK_SIZE * 8))
      {
         size_t i;
         size_t n;
         uint16_t temp;
         uint8_t o[16];

         //Determine the size, in bytes, of the specific part of the block
         //to be incremented
         m = m / 8;

         //Acquire exclusive access to the AES module
         esp_crypto_sha_aes_lock_acquire();
         //Enable AES module
         periph_module_enable(PERIPH_AES_MODULE);

         //Load AES key
         aesLoadKey(context, AES_MODE_ENC);

         //Process plaintext
         while(length > 0)
         {
            //CTR mode operates in a block-by-block fashion
            n = MIN(length, AES_BLOCK_SIZE);

            //Compute O(j) = CIPH(T(j))
            aesProcessDataBlock(t, o);

            //Compute C(j) = P(j) XOR T(j)
            for(i = 0; i < n; i++)
            {
               c[i] = p[i] ^ o[i];
            }

            //Standard incrementing function
            for(temp = 1, i = 1; i <= m; i++)
            {
               //Increment the current byte and propagate the carry
               temp += t[AES_BLOCK_SIZE - i];
               t[AES_BLOCK_SIZE - i] = temp & 0xFF;
               temp >>= 8;
            }

            //Next block
            p += n;
            c += n;
            length -= n;
         }

         //Disable AES module
         periph_module_disable(PERIPH_AES_MODULE);
         //Release exclusive access to the AES module
         esp_crypto_sha_aes_lock_release();
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
